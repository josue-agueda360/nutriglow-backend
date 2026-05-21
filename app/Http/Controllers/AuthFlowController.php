<?php

namespace App\Http\Controllers;

use App\Mail\AgendaAppointmentMail;
use App\Mail\AgendaAppointmentReminderMail;
use App\Mail\AdminPasswordCodeMail;
use App\Mail\AdminPasswordGeneratedMail;
use App\Mail\AdminLoginCodeMail;
use App\Mail\BillingInvoiceMail;
use App\Models\AgendaAppointment;
use App\Models\BillingCashCut;
use App\Models\BillingInvoice;
use App\Models\User;
use App\Models\Usariosapp;
use Barryvdh\DomPDF\Facade\Pdf;
use Carbon\Carbon;
use Carbon\Exceptions\InvalidFormatException;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\ValidationException;
use Illuminate\Validation\Rules\Password;
use Throwable;

class AuthFlowController extends Controller
{
    public function create()
    {
        return view('auth.signin');
    }

    public function store(Request $request)
    {
        $credentials = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required'],
        ]);

        $email = $this->normalizeLoginEmail($credentials['email']);
        $user = User::query()
            ->whereRaw('LOWER(email) = ?', [$email])
            ->first();

        $userLockUntil = $this->getActiveUserLoginLock($user);

        if ($userLockUntil) {
            return back()->withErrors([
                'email' => $this->getLoginLockMessage($userLockUntil),
            ])->onlyInput('email');
        }

        $lock = $this->getActiveLoginLock($email);

        if ($lock) {
            return back()->withErrors([
                'email' => $this->getLoginLockMessage($lock->locked_until),
            ])->onlyInput('email');
        }

        $credentials['email'] = $email;

        if ($user && Hash::check($credentials['password'], $user->password) && $user->role === 'administrador') {
            $this->clearUserLoginAttempts($user);
            $this->clearLoginAttempts($email);
            $this->startAdminTwoFactorFlow($request, $user);

            return redirect()->route('login.admin.verify');
        }

        if (Auth::attempt($credentials)) {
            $this->clearUserLoginAttempts($user);
            $this->clearLoginAttempts($email);
            $request->session()->regenerate();
            $request->session()->put('auth_session_version', (int) ($user?->session_version ?? 1));
            $this->logAdminAudit('system_login_success', $request, $user, 'user', $user?->id);

            return redirect()->route('panel');
        }

        $lockUntil = $user
            ? $this->registerFailedUserLoginAttempt($user)
            : $this->registerFailedLoginAttempt($email);

        if ($user && $user->role === 'administrador') {
            $this->logAdminAudit(
                'admin_login_failed',
                $request,
                $user,
                'user',
                $user->id,
                ['locked_until' => $lockUntil?->toDateTimeString()]
            );
        }

        return back()->withErrors([
            'email' => $lockUntil
                ? $this->getLoginLockMessage($lockUntil)
                : 'Correo o contrasena incorrectos.',
        ])->onlyInput('email');
    }

    public function showAdminTwoFactorChallenge(Request $request)
    {
        $user = $this->getPendingAdminLoginUser($request);

        if (! $user) {
            return redirect()
                ->route('login')
                ->withErrors([
                    'email' => 'Tu verificacion expiro. Ingresa nuevamente.',
                ]);
        }

        return view('auth.admin-verify', [
            'email' => $user->email,
        ]);
    }

    public function verifyAdminTwoFactorChallenge(Request $request)
    {
        $user = $this->getPendingAdminLoginUser($request);

        if (! $user) {
            return redirect()
                ->route('login')
                ->withErrors([
                    'email' => 'Tu verificacion expiro. Ingresa nuevamente.',
                ]);
        }

        $data = $request->validate([
            'verification_code' => ['required', 'digits:6'],
        ], [
            'verification_code.required' => 'El codigo es obligatorio.',
            'verification_code.digits' => 'El codigo debe tener 6 numeros.',
        ]);

        $verification = DB::table('admin_login_verification_codes')
            ->where('user_id', $user->id)
            ->whereNull('used_at')
            ->where('expires_at', '>=', now())
            ->latest('id')
            ->first();

        if (! $verification || ! Hash::check($data['verification_code'], $verification->code_hash)) {
            $this->logAdminAudit('admin_2fa_failed', $request, $user, 'user', $user->id);

            return back()->withErrors([
                'verification_code' => 'El codigo no es valido o ya vencio.',
            ])->withInput();
        }

        DB::table('admin_login_verification_codes')
            ->where('id', $verification->id)
            ->update([
                'used_at' => now(),
                'updated_at' => now(),
            ]);

        Auth::login($user);
        $request->session()->regenerate();
        $request->session()->put('auth_session_version', (int) ($user->session_version ?? 1));
        $this->clearPendingAdminLogin($request);
        $this->clearUserLoginAttempts($user);
        $this->clearLoginAttempts($this->normalizeLoginEmail($user->email));
        $this->logAdminAudit('admin_login_success', $request, $user, 'user', $user->id, ['two_factor' => true]);

        return redirect()->route('panel');
    }

    public function dashboard(Request $request)
    {
        $activeSection = $request->query('section', 'principal');
        $search = trim((string) $request->query('search', ''));
        $historyUserId = $request->query('history_user');
        $historyRange = (int) $request->query('history_range', 30);
        $historyDate = trim((string) $request->query('history_date', ''));
        $recipeRange = $request->query('recipe_range', 'todos');
        $recipeUserId = $request->query('recipe_user');
        $securityView = (string) $request->query('security_view', 'dia');
        $securityLimit = max(10, (int) $request->query('security_limit', 10));
        $auditView = (string) $request->query('audit_view', 'dia');
        $auditDate = trim((string) $request->query('audit_date', ''));
        $rescheduleAppointmentId = $request->query('reschedule_appointment');
        $rescheduleWeek = trim((string) $request->query('reschedule_week', ''));

        $availableSections = ['principal', 'usuarios', 'cargas', 'historial', 'recetas', 'agenda', 'agenda_citas', 'reagendar', 'notificaciones', 'facturacion', 'auditoria', 'seguridad'];

        if (! in_array($activeSection, $availableSections, true)) {
            $activeSection = 'principal';
        }

        $panelKey = (string) $request->query('panel_key', '');
        $lastAllowedSection = (string) $request->session()->get('panel_last_allowed_section', 'principal');

        if (
            $activeSection !== 'principal'
            && $activeSection !== $lastAllowedSection
            && ! $this->hasValidPanelSectionKey($request, $activeSection, $panelKey)
        ) {
            $activeSection = 'principal';
        }

        $request->session()->put('panel_last_allowed_section', $activeSection);

        if (! in_array($historyRange, [5, 15, 30], true)) {
            $historyRange = 30;
        }

        if (! in_array($recipeRange, ['todos', 'alto', 'medio', 'bajo'], true)) {
            $recipeRange = 'todos';
        }

        $uploadUsers = Usariosapp::query()
            ->when($search !== '', function ($query) use ($search) {
                $query->where('nombre', 'like', '%' . $search . '%')
                    ->orWhere('dpi', 'like', '%' . $search . '%');
            })
            ->orderBy('id', 'desc')
            ->get();

        $systemUsers = User::query()
            ->when($search !== '', function ($query) use ($search) {
                $query->where('name', 'like', '%' . $search . '%')
                    ->orWhere('email', 'like', '%' . $search . '%');
            })
            ->orderBy('id', 'desc')
            ->get();

        $historyUsers = Usariosapp::query()
            ->when($search !== '', function ($query) use ($search) {
                $query->where('nombre', 'like', '%' . $search . '%')
                    ->orWhere('dpi', 'like', '%' . $search . '%');
            })
            ->orderBy('nombre')
            ->get();

        $selectedHistoryUser = $historyUserId
            ? $historyUsers->firstWhere('id', (int) $historyUserId)
            : $historyUsers->first();

        $historyEntries = collect();

        if ($selectedHistoryUser) {
            $historyEntries = $this->buildHistoryEntries($historyRange, $historyDate);
        }

        $recipeUsers = Usariosapp::query()
            ->when($search !== '', function ($query) use ($search) {
                $query->where('nombre', 'like', '%' . $search . '%')
                    ->orWhere('dpi', 'like', '%' . $search . '%');
            })
            ->when($recipeRange !== 'todos', function ($query) use ($recipeRange) {
                $query->where('rango_receta', $recipeRange);
            })
            ->orderByRaw("CASE COALESCE(rango_receta, 'bajo') WHEN 'alto' THEN 1 WHEN 'medio' THEN 2 WHEN 'bajo' THEN 3 ELSE 4 END")
            ->orderBy('nombre')
            ->get();

        $recipeUsers->each(function (Usariosapp $recipeUser) {
            $recipeUser->setAttribute('receta_imagen_url', $this->recipeImageUrl($recipeUser->receta_imagen));
        });

        $selectedRecipeUser = $recipeUserId
            ? $recipeUsers->firstWhere('id', (int) $recipeUserId)
            : null;

        $agendaClients = Usariosapp::query()
            ->when($search !== '', function ($query) use ($search) {
                $query->where('nombre', 'like', '%' . $search . '%')
                    ->orWhere('correo', 'like', '%' . $search . '%')
                    ->orWhere('dpi', 'like', '%' . $search . '%');
            })
            ->orderBy('nombre')
            ->get();

        $agendaToday = now(config('app.timezone', 'America/Guatemala'));
        $agendaRangeStart = $agendaToday->copy()->startOfDay();
        $agendaRangeEnd = $agendaToday->copy()->endOfDay();

        $agendaAppointmentsQuery = AgendaAppointment::query()
            ->with('usariosapp', 'creator')
            ->whereBetween('appointment_at', [$agendaRangeStart, $agendaRangeEnd])
            ->when($search !== '', function ($query) use ($search) {
                $query->where(function ($innerQuery) use ($search) {
                    $innerQuery->where('cliente_nombre', 'like', '%' . $search . '%')
                        ->orWhere('cliente_correo', 'like', '%' . $search . '%');
                });
            });

        $agendaPendingAppointments = (clone $agendaAppointmentsQuery)
            ->where('is_completed', false)
            ->orderBy('appointment_at')
            ->orderByDesc('id')
            ->get();

        $agendaCompletedAppointments = (clone $agendaAppointmentsQuery)
            ->where('is_completed', true)
            ->orderBy('appointment_at')
            ->orderByDesc('id')
            ->get();

        $notificationAppointments = (clone $agendaAppointmentsQuery)
            ->where('is_completed', false)
            ->where('appointment_at', '>', $agendaToday->copy()->subMinutes(30))
            ->orderBy('appointment_at')
            ->orderByDesc('id')
            ->get();

        $rescheduleBaseDate = $agendaToday->copy();

        if ($rescheduleWeek !== '') {
            try {
                $rescheduleBaseDate = Carbon::createFromFormat('Y-m-d', $rescheduleWeek, config('app.timezone', 'America/Guatemala'));
            } catch (InvalidFormatException) {
                $rescheduleBaseDate = $agendaToday->copy();
            }
        }

        $rescheduleWeekStart = $rescheduleBaseDate->copy()->startOfWeek(Carbon::MONDAY)->startOfDay();
        $rescheduleWeekEnd = $rescheduleWeekStart->copy()->addDays(6)->endOfDay();
        $rescheduleWeekDays = collect(range(0, 6))->map(fn (int $offset) => $rescheduleWeekStart->copy()->addDays($offset));
        $rescheduleHours = collect(range(8, 17));

        $rescheduleAppointments = AgendaAppointment::query()
            ->with('usariosapp', 'creator')
            ->whereBetween('appointment_at', [$rescheduleWeekStart, $rescheduleWeekEnd])
            ->when($search !== '', function ($query) use ($search) {
                $query->where(function ($innerQuery) use ($search) {
                    $innerQuery->where('cliente_nombre', 'like', '%' . $search . '%')
                        ->orWhere('cliente_correo', 'like', '%' . $search . '%');
                });
            })
            ->orderBy('appointment_at')
            ->orderBy('id')
            ->get();

        $rescheduleCalendar = [];
        foreach ($rescheduleAppointments as $rescheduleAppointment) {
            $dayKey = $rescheduleAppointment->appointment_at->format('Y-m-d');
            $hourKey = $rescheduleAppointment->appointment_at->format('H');
            $rescheduleCalendar[$dayKey][$hourKey][] = $rescheduleAppointment;
        }

        $selectedRescheduleAppointment = $rescheduleAppointmentId
            ? AgendaAppointment::query()->with('creator', 'usariosapp')->find((int) $rescheduleAppointmentId)
            : null;

        $auditSelectedDate = $agendaToday->copy();

        if ($auditDate !== '') {
            try {
                $auditSelectedDate = Carbon::createFromFormat('Y-m-d', $auditDate, config('app.timezone', 'America/Guatemala'));
            } catch (InvalidFormatException) {
                $auditSelectedDate = $agendaToday->copy();
                $auditDate = '';
            }
        }

        if ($auditView !== 'historial') {
            $auditView = 'dia';
            $auditDate = '';
        }

        $billingInvoices = BillingInvoice::query()
            ->with('creator')
            ->when($auditView === 'dia', function ($query) use ($agendaRangeStart, $agendaRangeEnd) {
                $query->whereBetween('billed_at', [$agendaRangeStart, $agendaRangeEnd]);
            })
            ->when($auditView === 'historial' && $auditDate !== '', function ($query) use ($auditSelectedDate) {
                $query->whereBetween('billed_at', [
                    $auditSelectedDate->copy()->startOfDay(),
                    $auditSelectedDate->copy()->endOfDay(),
                ]);
            })
            ->when($search !== '', function ($query) use ($search) {
                $query->where(function ($innerQuery) use ($search) {
                    $innerQuery->where('cliente_nombre', 'like', '%' . $search . '%')
                        ->orWhere('cliente_correo', 'like', '%' . $search . '%')
                        ->orWhere('invoice_number', 'like', '%' . $search . '%');
                });
            })
            ->orderByDesc('billed_at')
            ->orderByDesc('id')
            ->get();

        $lastCashCut = BillingCashCut::query()
            ->latest('cut_at')
            ->first();

        $billingCutInvoices = BillingInvoice::query()
            ->when($lastCashCut, function ($query) use ($lastCashCut) {
                $query->where('billed_at', '>', $lastCashCut->cut_at);
            })
            ->orderBy('billed_at')
            ->orderBy('id')
            ->get();

        $billingCutTotal = (float) $billingCutInvoices->sum('total');
        $billingCutClientCount = $billingCutInvoices->count();

        $securityLoginsQuery = DB::table('admin_audit_logs')
            ->leftJoin('users', 'users.id', '=', 'admin_audit_logs.actor_user_id')
            ->whereIn('admin_audit_logs.action', ['admin_login_success', 'system_login_success'])
            ->select([
                'admin_audit_logs.id',
                'admin_audit_logs.action',
                'admin_audit_logs.created_at',
                'users.name as user_name',
                'users.email as user_email',
            ]);

        if ($securityView !== 'historial') {
            $securityLoginsQuery->whereBetween('admin_audit_logs.created_at', [$agendaRangeStart, $agendaRangeEnd]);
            $securityView = 'dia';
        }

        $securityHasMore = false;

        if ($securityView === 'historial') {
            $securityLogins = $securityLoginsQuery
                ->orderByDesc('admin_audit_logs.created_at')
                ->limit($securityLimit + 1)
                ->get();

            $securityHasMore = $securityLogins->count() > $securityLimit;
            $securityLogins = $securityLogins->take($securityLimit);
        } else {
            $securityLogins = $securityLoginsQuery
                ->orderByDesc('admin_audit_logs.created_at')
                ->get();
        }

        return view('auth.dashboard', compact(
            'activeSection',
            'systemUsers',
            'uploadUsers',
            'search',
            'historyUsers',
            'selectedHistoryUser',
            'historyEntries',
            'historyRange',
            'historyDate',
            'recipeUsers',
            'selectedRecipeUser',
            'recipeRange',
            'agendaClients',
            'agendaPendingAppointments',
            'agendaCompletedAppointments',
            'rescheduleAppointments',
            'rescheduleWeekDays',
            'rescheduleWeekStart',
            'rescheduleWeekEnd',
            'rescheduleHours',
            'rescheduleCalendar',
            'selectedRescheduleAppointment',
            'notificationAppointments',
            'billingInvoices',
            'billingCutTotal',
            'billingCutClientCount',
            'lastCashCut',
            'auditView',
            'auditDate',
            'auditSelectedDate',
            'agendaToday',
            'securityLogins',
            'securityView',
            'securityLimit',
            'securityHasMore'
        ));
    }

    public function storeCargaUsuario(Request $request)
    {
        $data = $request->validate([
            'nombre' => ['required', 'string', 'max:255'],
            'correo' => ['required', 'email', 'max:255', 'unique:Usariosapp,correo'],
            'dpi' => ['required', 'digits:13', 'unique:Usariosapp,dpi'],
            'password' => ['required', 'string', Password::min(8)->mixedCase()->numbers()->symbols()],
        ], [
            'nombre.required' => 'El nombre es obligatorio.',
            'correo.required' => 'El correo es obligatorio.',
            'correo.email' => 'Ingresa un correo valido.',
            'correo.unique' => 'Este correo ya esta registrado.',
            'dpi.required' => 'El DPI es obligatorio.',
            'dpi.digits' => 'El DPI debe tener exactamente 13 numeros.',
            'dpi.unique' => 'Este DPI ya esta registrado.',
            'password.required' => 'La contrasena es obligatoria.',
            'password.min' => 'La contrasena debe tener al menos 8 caracteres.',
            'password.mixed' => 'La contrasena debe incluir mayusculas y minusculas.',
            'password.numbers' => 'La contrasena debe incluir al menos un numero.',
            'password.symbols' => 'La contrasena debe incluir al menos un simbolo.',
        ]);

        $uploadUser = Usariosapp::create([
            'nombre' => $data['nombre'],
            'correo' => $data['correo'],
            'dpi' => $data['dpi'],
            'password' => Hash::make($data['password']),
        ]);

        if (Auth::check()) {
            $this->logAdminAudit('app_user_created', $request, Auth::user(), 'usariosapp', $uploadUser->id, [
                'nombre' => $uploadUser->nombre,
                'correo' => $uploadUser->correo,
            ]);
        }

        if ($request->expectsJson()) {
            return response()->json([
                'message' => 'Usuario agregado correctamente en Cargas.',
                'user' => $this->formatCargaUsuarioForPanel($uploadUser),
            ]);
        }

        return redirect()
            ->route('panel', $this->panelRouteParams($request, 'cargas'))
            ->with('success_cargas', 'Usuario agregado correctamente en Cargas.');
    }

    public function updateCargaUsuario(Request $request, Usariosapp $usariosapp)
    {
        $data = $request->validate([
            'nombre' => ['required', 'string', 'max:255'],
            'correo' => ['required', 'email', 'max:255', 'unique:Usariosapp,correo,' . $usariosapp->id],
            'dpi' => ['required', 'digits:13', 'unique:Usariosapp,dpi,' . $usariosapp->id],
            'password' => ['nullable', 'string', Password::min(8)->mixedCase()->numbers()->symbols()],
        ], [
            'nombre.required' => 'El nombre es obligatorio.',
            'correo.required' => 'El correo es obligatorio.',
            'correo.email' => 'Ingresa un correo valido.',
            'correo.unique' => 'Este correo ya esta registrado.',
            'dpi.required' => 'El DPI es obligatorio.',
            'dpi.digits' => 'El DPI debe tener exactamente 13 numeros.',
            'dpi.unique' => 'Este DPI ya esta registrado.',
            'password.min' => 'La contrasena debe tener al menos 8 caracteres.',
            'password.mixed' => 'La contrasena debe incluir mayusculas y minusculas.',
            'password.numbers' => 'La contrasena debe incluir al menos un numero.',
            'password.symbols' => 'La contrasena debe incluir al menos un simbolo.',
        ]);

        $usariosapp->nombre = $data['nombre'];
        $usariosapp->correo = $data['correo'];
        $usariosapp->dpi = $data['dpi'];

        if (! empty($data['password'])) {
            $usariosapp->password = Hash::make($data['password']);
        }

        $usariosapp->save();

        if (Auth::check()) {
            $this->logAdminAudit('app_user_updated', $request, Auth::user(), 'usariosapp', $usariosapp->id, [
                'nombre' => $usariosapp->nombre,
                'correo' => $usariosapp->correo,
                'dpi' => $usariosapp->dpi,
                'password_changed' => ! empty($data['password']),
            ]);
        }

        if ($request->expectsJson()) {
            return response()->json([
                'message' => 'Usuario actualizado correctamente en Cargas.',
                'user' => $this->formatCargaUsuarioForPanel($usariosapp),
            ]);
        }

        return redirect()
            ->route('panel', $this->panelRouteParams($request, 'cargas'))
            ->with('success_cargas', 'Usuario actualizado correctamente en Cargas.');
    }

    public function storeAgendaAppointment(Request $request)
    {
        $data = $request->validate([
            'agenda_client_type' => ['required', 'in:existente,nuevo'],
            'usariosapp_id' => ['nullable', 'integer', 'exists:Usariosapp,id'],
            'cliente_nombre' => ['nullable', 'string', 'max:255'],
            'cliente_correo' => ['nullable', 'email', 'max:255'],
            'appointment_at' => ['required', 'date', 'after:now'],
        ], [
            'agenda_client_type.required' => 'Selecciona el tipo de cliente.',
            'agenda_client_type.in' => 'Selecciona un tipo de cliente valido.',
            'usariosapp_id.exists' => 'Selecciona un cliente existente valido.',
            'cliente_nombre.required' => 'El nombre del cliente es obligatorio.',
            'cliente_correo.required' => 'El correo del cliente es obligatorio.',
            'cliente_correo.email' => 'Ingresa un correo valido para la cita.',
            'appointment_at.required' => 'La fecha y hora de la cita son obligatorias.',
            'appointment_at.after' => 'La cita debe programarse en una fecha y hora futuras.',
        ]);

        $linkedClient = null;

        if ($data['agenda_client_type'] === 'existente') {
            if (empty($data['usariosapp_id'])) {
                return redirect()
                    ->route('panel', $this->panelRouteParams($request, 'agenda'))
                    ->withErrors(['usariosapp_id' => 'Selecciona un cliente existente.'])
                    ->withInput();
            }

            $linkedClient = Usariosapp::findOrFail((int) $data['usariosapp_id']);
            $clienteNombre = $linkedClient->nombre;
            $clienteCorreo = $linkedClient->correo;
        } else {
            $extraValidation = validator($data, [
                'cliente_nombre' => ['required', 'string', 'max:255'],
                'cliente_correo' => ['required', 'email', 'max:255'],
            ], [
                'cliente_nombre.required' => 'Ingresa el nombre del cliente nuevo.',
                'cliente_correo.required' => 'Ingresa el correo del cliente nuevo.',
            ]);

            if ($extraValidation->fails()) {
                return redirect()
                    ->route('panel', $this->panelRouteParams($request, 'agenda'))
                    ->withErrors($extraValidation)
                    ->withInput();
            }

            $clienteNombre = $data['cliente_nombre'];
            $clienteCorreo = $data['cliente_correo'];
        }

        $appointmentAt = Carbon::parse($data['appointment_at'], config('app.timezone', 'America/Guatemala'));

        if (! $this->isAgendaAppointmentInsideBusinessHours($appointmentAt)) {
            return redirect()
                ->route('panel', $this->panelRouteParams($request, 'agenda'))
                ->withErrors(['appointment_at' => 'El horario de citas permitido es de 08:00 a 17:00 horas.'])
                ->withInput();
        }

        $appointment = AgendaAppointment::create([
            'usariosapp_id' => $linkedClient?->id,
            'cliente_nombre' => $clienteNombre,
            'cliente_correo' => $clienteCorreo,
            'appointment_at' => $appointmentAt,
            'created_by_user_id' => Auth::id(),
        ]);

        Mail::to($clienteCorreo)->send(new AgendaAppointmentMail($appointment));

        if (Auth::check()) {
            $this->logAdminAudit('agenda_appointment_created', $request, Auth::user(), 'agenda_appointments', $appointment->id, [
                'cliente_nombre' => $clienteNombre,
                'cliente_correo' => $clienteCorreo,
                'appointment_at' => $appointmentAt->toDateTimeString(),
                'linked_usariosapp_id' => $linkedClient?->id,
            ]);
        }

        return redirect()
            ->route('panel', $this->panelRouteParams($request, 'agenda'))
            ->with('success_agenda', $this->mailDeliveredMessage('Cita creada correctamente y correo enviado al cliente.'));
    }

    public function toggleAgendaAppointmentStatus(Request $request, AgendaAppointment $agendaAppointment)
    {
        $isTryingToReturnExpiredAppointment = $agendaAppointment->is_completed
            && $agendaAppointment->appointment_at
            && $agendaAppointment->appointment_at->copy()->addMinutes(30)->lte(now(config('app.timezone', 'America/Guatemala')));

        if ($isTryingToReturnExpiredAppointment) {
            if ($request->expectsJson()) {
                return response()->json([
                    'message' => 'Cita caducada.',
                    'appointment' => [
                        'id' => $agendaAppointment->id,
                        'is_completed' => true,
                    ],
                ], 422);
            }

            return redirect()
                ->route('panel', $this->panelRouteParams($request, 'agenda_citas'))
                ->withErrors(['agenda' => 'Cita caducada.']);
        }

        $agendaAppointment->is_completed = ! $agendaAppointment->is_completed;
        $agendaAppointment->completed_at = $agendaAppointment->is_completed ? now() : null;
        $agendaAppointment->save();

        if (Auth::check()) {
            $this->logAdminAudit('agenda_appointment_status_updated', $request, Auth::user(), 'agenda_appointments', $agendaAppointment->id, [
                'cliente_nombre' => $agendaAppointment->cliente_nombre,
                'appointment_at' => $agendaAppointment->appointment_at?->toDateTimeString(),
                'is_completed' => $agendaAppointment->is_completed,
            ]);
        }

        if ($request->expectsJson()) {
            return response()->json([
                'message' => $agendaAppointment->is_completed
                    ? 'Cita marcada como completada.'
                    : 'Cita devuelta a pendientes.',
                'appointment' => [
                    'id' => $agendaAppointment->id,
                    'is_completed' => $agendaAppointment->is_completed,
                ],
            ]);
        }

        return redirect()
            ->route('panel', $this->panelRouteParams($request, 'agenda_citas'))
            ->with('success_agenda', $agendaAppointment->is_completed
                ? 'Cita marcada como completada.'
                : 'Cita devuelta a pendientes.');
    }

    public function rescheduleAgendaAppointment(Request $request, AgendaAppointment $agendaAppointment)
    {
        $data = $request->validate([
            'reschedule_appointment_at' => ['required', 'date', 'after:now'],
        ], [
            'reschedule_appointment_at.required' => 'La nueva fecha y hora son obligatorias.',
            'reschedule_appointment_at.date' => 'Ingresa una fecha y hora validas.',
            'reschedule_appointment_at.after' => 'La nueva fecha debe ser posterior al momento actual.',
        ]);

        $previousAppointmentAt = $agendaAppointment->appointment_at?->copy();
        $newAppointmentAt = Carbon::parse($data['reschedule_appointment_at'], config('app.timezone', 'America/Guatemala'));

        if (! $this->isAgendaAppointmentInsideBusinessHours($newAppointmentAt)) {
            return redirect()->route('panel', [
                ...$this->panelRouteParams($request, 'reagendar'),
                'reschedule_week' => $agendaAppointment->appointment_at?->copy()->startOfWeek(Carbon::MONDAY)->format('Y-m-d'),
                'reschedule_appointment' => $agendaAppointment->id,
            ])->withErrors(['reschedule_appointment_at' => 'El horario de citas permitido es de 08:00 a 17:00 horas.'])
                ->withInput();
        }

        $agendaAppointment->appointment_at = $newAppointmentAt;
        $agendaAppointment->is_completed = false;
        $agendaAppointment->completed_at = null;
        $agendaAppointment->save();

        if (Auth::check()) {
            $this->logAdminAudit('agenda_appointment_rescheduled', $request, Auth::user(), 'agenda_appointments', $agendaAppointment->id, [
                'cliente_nombre' => $agendaAppointment->cliente_nombre,
                'previous_appointment_at' => $previousAppointmentAt?->toDateTimeString(),
                'new_appointment_at' => $newAppointmentAt->toDateTimeString(),
            ]);
        }

        return redirect()->route('panel', [
            ...$this->panelRouteParams($request, 'reagendar'),
            'reschedule_week' => $newAppointmentAt->copy()->startOfWeek(Carbon::MONDAY)->format('Y-m-d'),
            'reschedule_appointment' => $agendaAppointment->id,
        ])->with('success_reagendar', 'Cita reagendada correctamente.');
    }

    public function destroyAgendaAppointment(Request $request, AgendaAppointment $agendaAppointment)
    {
        $weekStart = $agendaAppointment->appointment_at?->copy()->startOfWeek(Carbon::MONDAY)->format('Y-m-d')
            ?? now(config('app.timezone', 'America/Guatemala'))->startOfWeek(Carbon::MONDAY)->format('Y-m-d');

        if (Auth::check()) {
            $this->logAdminAudit('agenda_appointment_deleted', $request, Auth::user(), 'agenda_appointments', $agendaAppointment->id, [
                'cliente_nombre' => $agendaAppointment->cliente_nombre,
                'cliente_correo' => $agendaAppointment->cliente_correo,
                'appointment_at' => $agendaAppointment->appointment_at?->toDateTimeString(),
            ]);
        }

        $agendaAppointment->delete();

        return redirect()->route('panel', [
            ...$this->panelRouteParams($request, 'reagendar'),
            'reschedule_week' => $weekStart,
        ])->with('success_reagendar', 'Cita eliminada correctamente.');
    }

    public function sendTodayAgendaNotifications(Request $request)
    {
        $today = now(config('app.timezone', 'America/Guatemala'));
        $rangeStart = $today->copy()->startOfDay();
        $rangeEnd = $today->copy()->endOfDay();
        $search = trim((string) $request->input('search', ''));

        $appointments = AgendaAppointment::query()
            ->whereBetween('appointment_at', [$rangeStart, $rangeEnd])
            ->where('is_completed', false)
            ->where('appointment_at', '>', $today->copy()->subMinutes(30))
            ->when($search !== '', function ($query) use ($search) {
                $query->where(function ($innerQuery) use ($search) {
                    $innerQuery->where('cliente_nombre', 'like', '%' . $search . '%')
                        ->orWhere('cliente_correo', 'like', '%' . $search . '%');
                });
            })
            ->orderBy('appointment_at')
            ->get();

        if ($appointments->isEmpty()) {
            return redirect()
                ->route('panel', $this->panelRouteParams($request, 'notificaciones'))
                ->with('success_notificaciones', 'No hay citas pendientes del dia para notificar.');
        }

        foreach ($appointments as $appointment) {
            Mail::to($appointment->cliente_correo)->send(new AgendaAppointmentReminderMail($appointment));
        }

        if (Auth::check()) {
            $this->logAdminAudit('agenda_notifications_sent', $request, Auth::user(), 'agenda_appointments', null, [
                'appointments_count' => $appointments->count(),
                'date' => $today->format('Y-m-d'),
            ]);
        }

        return redirect()
            ->route('panel', $this->panelRouteParams($request, 'notificaciones'))
            ->with('success_notificaciones', $this->mailDeliveredMessage('Notificaciones enviadas correctamente a ' . $appointments->count() . ' cita(s) del dia.'));
    }

    public function downloadFacturaPdf(Request $request)
    {
        $validator = validator($request->all(), [
            'billing_client_type' => ['required', 'in:existente,nuevo'],
            'billing_usariosapp_id' => ['nullable', 'integer', 'exists:Usariosapp,id'],
            'billing_cliente_nombre' => ['nullable', 'string', 'max:255'],
            'billing_cliente_correo' => ['nullable', 'email', 'max:255'],
            'cita_costo' => ['required', 'numeric', 'min:0'],
            'extras' => ['nullable', 'array'],
            'extras.*.descripcion' => ['nullable', 'string', 'max:255'],
            'extras.*.monto' => ['nullable', 'numeric', 'min:0'],
        ], [
            'billing_client_type.required' => 'Selecciona el tipo de cliente.',
            'billing_client_type.in' => 'Selecciona un tipo de cliente valido.',
            'billing_usariosapp_id.exists' => 'Selecciona un cliente existente valido.',
            'billing_cliente_correo.email' => 'Ingresa un correo valido.',
            'cita_costo.required' => 'El costo de la cita es obligatorio.',
            'cita_costo.numeric' => 'El costo de la cita debe ser numerico.',
            'cita_costo.min' => 'El costo de la cita no puede ser negativo.',
            'extras.*.monto.numeric' => 'Cada monto extra debe ser numerico.',
            'extras.*.monto.min' => 'Ningun monto extra puede ser negativo.',
        ]);

        if ($validator->fails()) {
            if ($request->expectsJson()) {
                return response()->json([
                    'message' => 'Revisa los datos de la factura.',
                    'errors' => $validator->errors(),
                ], 422);
            }

            return redirect()
                ->route('panel', $this->panelRouteParams($request, 'facturacion'))
                ->withErrors($validator)
                ->withInput();
        }

        $data = $validator->validated();
        $billingType = $data['billing_client_type'];
        $linkedClient = null;

        if ($billingType === 'existente') {
            if (empty($data['billing_usariosapp_id'])) {
                if ($request->expectsJson()) {
                    return response()->json([
                        'message' => 'Selecciona un cliente existente.',
                        'errors' => ['billing_usariosapp_id' => ['Selecciona un cliente existente.']],
                    ], 422);
                }

                return redirect()
                    ->route('panel', $this->panelRouteParams($request, 'facturacion'))
                    ->withErrors(['billing_usariosapp_id' => 'Selecciona un cliente existente.'])
                    ->withInput();
            }

            $linkedClient = Usariosapp::findOrFail((int) $data['billing_usariosapp_id']);
            $clienteNombre = $linkedClient->nombre;
            $clienteCorreo = $linkedClient->correo;
            $clienteDpi = $linkedClient->dpi;
        } else {
            $extraValidator = validator($data, [
                'billing_cliente_nombre' => ['required', 'string', 'max:255'],
                'billing_cliente_correo' => ['required', 'email', 'max:255'],
            ], [
                'billing_cliente_nombre.required' => 'Ingresa el nombre del cliente.',
                'billing_cliente_correo.required' => 'Ingresa el correo del cliente.',
                'billing_cliente_correo.email' => 'Ingresa un correo valido.',
            ]);

            if ($extraValidator->fails()) {
                if ($request->expectsJson()) {
                    return response()->json([
                        'message' => 'Revisa los datos del cliente.',
                        'errors' => $extraValidator->errors(),
                    ], 422);
                }

                return redirect()
                    ->route('panel', $this->panelRouteParams($request, 'facturacion'))
                    ->withErrors($extraValidator)
                    ->withInput();
            }

            $clienteNombre = $data['billing_cliente_nombre'];
            $clienteCorreo = $data['billing_cliente_correo'];
            $clienteDpi = null;
        }

        $citaCosto = (float) $data['cita_costo'];
        $extras = collect($data['extras'] ?? [])
            ->map(function ($item) {
                return [
                    'descripcion' => trim((string) ($item['descripcion'] ?? '')),
                    'monto' => (float) ($item['monto'] ?? 0),
                ];
            })
            ->filter(function ($item) {
                return $item['descripcion'] !== '' || $item['monto'] > 0;
            })
            ->values();

        $extrasTotal = $extras->sum('monto');
        $total = $citaCosto + $extrasTotal;
        $generatedAt = now(config('app.timezone', 'America/Guatemala'));
        $invoiceNumber = 'FAC-' . $generatedAt->format('Ymd-His');

        $invoice = BillingInvoice::create([
            'invoice_number' => $invoiceNumber,
            'usariosapp_id' => $linkedClient?->id,
            'cliente_nombre' => $clienteNombre,
            'cliente_correo' => $clienteCorreo,
            'cliente_dpi' => $clienteDpi,
            'cita_costo' => $citaCosto,
            'extras' => $extras->all(),
            'extras_total' => $extrasTotal,
            'total' => $total,
            'generated_by_user_id' => Auth::id(),
            'billed_at' => $generatedAt,
        ]);

        if (Auth::check()) {
            $this->logAdminAudit('invoice_generated', $request, Auth::user(), 'billing_invoices', $invoice->id, [
                'invoice_number' => $invoiceNumber,
                'cliente_nombre' => $clienteNombre,
                'cliente_correo' => $clienteCorreo,
                'cita_costo' => $citaCosto,
                'extras_total' => $extrasTotal,
                'total' => $total,
            ]);
        }

        $pdfPath = $this->storeBillingInvoicePdf($invoice);

        $this->queueBillingInvoiceMail($invoice, $request, $pdfPath);
        $invoiceMessage = $this->mailDeliveredMessage('Factura generada correctamente. La factura se enviara al correo del cliente.');

        if ($request->expectsJson()) {
            $lastCashCut = BillingCashCut::query()->latest('cut_at')->first();
            $cutInvoices = BillingInvoice::query()
                ->when($lastCashCut, function ($query) use ($lastCashCut) {
                    $query->where('billed_at', '>', $lastCashCut->cut_at);
                })
                ->orderBy('billed_at')
                ->orderBy('id')
                ->get();

            return response()->json([
                'message' => $invoiceMessage,
                'download_url' => route('panel.facturacion.download', $invoice),
                'invoice' => [
                    'id' => $invoice->id,
                    'invoice_number' => $invoice->invoice_number,
                    'cliente_nombre' => $invoice->cliente_nombre,
                    'cliente_correo' => $invoice->cliente_correo,
                    'billed_at_iso_date' => $invoice->billed_at->format('Y-m-d'),
                    'billed_at_date' => $invoice->billed_at->format('d/m/Y'),
                    'billed_at_time' => $invoice->billed_at->format('H:i'),
                    'cita_costo' => (float) $invoice->cita_costo,
                    'extras' => collect($invoice->extras ?? [])->map(function ($extra) {
                        return [
                            'descripcion' => (string) ($extra['descripcion'] ?? ''),
                            'monto' => (float) ($extra['monto'] ?? 0),
                        ];
                    })->values()->all(),
                    'total' => (float) $invoice->total,
                ],
                'cut_total' => (float) $cutInvoices->sum('total'),
                'cut_client_count' => $cutInvoices->count(),
            ]);
        }

        return $this->downloadBillingInvoicePdf($invoice, $pdfPath);
    }

    public function downloadStoredFacturaPdf(BillingInvoice $billingInvoice)
    {
        $pdfPath = $this->ensureBillingInvoicePdfExists($billingInvoice);

        return $this->downloadBillingInvoicePdf($billingInvoice, $pdfPath);
    }

    public function downloadCashCutPdf(Request $request)
    {
        $generatedAt = now(config('app.timezone', 'America/Guatemala'));
        $lastCashCut = BillingCashCut::query()->latest('cut_at')->first();

        $invoices = BillingInvoice::query()
            ->with('creator')
            ->when($lastCashCut, function ($query) use ($lastCashCut) {
                $query->where('billed_at', '>', $lastCashCut->cut_at);
            })
            ->orderBy('billed_at')
            ->orderBy('id')
            ->get();

        if ($invoices->isEmpty()) {
            return redirect()
                ->route('panel', $this->panelRouteParams($request, 'auditoria'))
                ->with('success_auditoria', 'No hay movimientos nuevos desde el ultimo corte de caja.');
        }

        $total = (float) $invoices->sum('total');
        $invoiceCount = $invoices->count();
        $cutNumber = 'CORTE-' . $generatedAt->format('Ymd-His');

        $cashCut = BillingCashCut::create([
            'cut_number' => $cutNumber,
            'total' => $total,
            'invoice_count' => $invoiceCount,
            'generated_by_user_id' => Auth::id(),
            'cut_at' => $generatedAt,
        ]);

        if (Auth::check()) {
            $this->logAdminAudit('billing_cash_cut_generated', $request, Auth::user(), 'billing_cash_cuts', $cashCut->id, [
                'cut_number' => $cutNumber,
                'total' => $total,
                'invoice_count' => $invoiceCount,
            ]);
        }

        $pdf = Pdf::loadView('pdfs.corte-caja', [
            'cutNumber' => $cutNumber,
            'generatedAt' => $generatedAt,
            'invoices' => $invoices,
            'total' => $total,
            'invoiceCount' => $invoiceCount,
            'generatedBy' => Auth::user()?->name ?? 'Sistema',
            'lastCashCut' => $lastCashCut,
        ])->setPaper('a4');

        return $pdf->download('corte-caja-' . strtolower($cutNumber) . '.pdf');
    }

    public function downloadDateCashCutPdf(Request $request)
    {
        $auditDate = trim((string) $request->input('audit_date', ''));

        if ($auditDate === '') {
            return redirect()
                ->route('panel', $this->panelRouteParams($request, 'auditoria', [
                    'audit_view' => 'historial',
                ]))
                ->with('success_auditoria', 'Selecciona una fecha para hacer el corte.');
        }

        $generatedAt = now(config('app.timezone', 'America/Guatemala'));

        try {
            $selectedDate = Carbon::createFromFormat('Y-m-d', $auditDate, config('app.timezone', 'America/Guatemala'));
        } catch (InvalidFormatException) {
            return redirect()
                ->route('panel', $this->panelRouteParams($request, 'auditoria', [
                    'audit_view' => 'historial',
                ]))
                ->with('success_auditoria', 'Selecciona una fecha valida para hacer el corte.');
        }

        $invoices = BillingInvoice::query()
            ->with('creator')
            ->whereBetween('billed_at', [
                $selectedDate->copy()->startOfDay(),
                $selectedDate->copy()->endOfDay(),
            ])
            ->orderBy('billed_at')
            ->orderBy('id')
            ->get();

        if ($invoices->isEmpty()) {
            return redirect()
                ->route('panel', $this->panelRouteParams($request, 'auditoria', [
                    'audit_view' => 'historial',
                    'audit_date' => $auditDate,
                ]))
                ->with('success_auditoria', 'No hubieron facturas ese dia.');
        }

        $total = (float) $invoices->sum('total');
        $invoiceCount = $invoices->count();
        $cutNumber = 'CORTE-FECHA-' . $selectedDate->format('Ymd') . '-' . $generatedAt->format('His');

        if (Auth::check()) {
            $this->logAdminAudit('billing_date_cash_cut_generated', $request, Auth::user(), 'billing_invoices', null, [
                'cut_number' => $cutNumber,
                'selected_date' => $selectedDate->toDateString(),
                'total' => $total,
                'invoice_count' => $invoiceCount,
            ]);
        }

        $pdf = Pdf::loadView('pdfs.corte-caja', [
            'cutNumber' => $cutNumber,
            'generatedAt' => $generatedAt,
            'invoices' => $invoices,
            'total' => $total,
            'invoiceCount' => $invoiceCount,
            'generatedBy' => Auth::user()?->name ?? 'Sistema',
            'lastCashCut' => BillingCashCut::query()->latest('cut_at')->first(),
        ])->setPaper('a4');

        return $pdf->download('corte-fecha-' . $selectedDate->format('Y-m-d') . '.pdf');
    }

    public function storeSystemUser(Request $request)
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:users,email'],
            'password' => ['required', 'string', Password::min(8)->mixedCase()->numbers()->symbols()],
            'role' => ['required', 'in:administrador,usuario'],
        ], $this->systemUserValidationMessages());

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
            'role' => $data['role'],
        ]);

        $this->storePasswordHistory($user);
        $this->logAdminAudit('system_user_created', $request, Auth::user(), 'user', $user->id, [
            'created_role' => $user->role,
            'created_email' => $user->email,
        ]);

        if ($request->expectsJson()) {
            return response()->json([
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'role' => ucfirst($user->role),
                    'role_value' => $user->role,
                    'initial' => strtoupper(substr($user->name, 0, 1)),
                    'search' => strtolower($user->name . ' ' . $user->email),
                    'update_url' => route('panel.usuarios.update', $user),
                    'delete_url' => route('panel.usuarios.destroy', $user),
                ],
            ]);
        }

        return redirect()
            ->route('panel', $this->panelRouteParams($request, 'usuarios'))
            ->with('success', 'Usuario creado correctamente.');
    }

    public function updateSystemUser(Request $request, User $user)
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:users,email,' . $user->id],
            'current_password' => ['nullable', 'string'],
            'password' => ['nullable', 'string', Password::min(8)->mixedCase()->numbers()->symbols()],
            'role' => ['required', 'in:administrador,usuario'],
        ], $this->systemUserValidationMessages());

        $isAdminUser = $user->role === 'administrador';
        $hasCurrentPassword = ! empty($data['current_password']);
        $hasNewPassword = ! empty($data['password']);
        $wantsAdminPasswordChange = $isAdminUser && ($hasCurrentPassword || $hasNewPassword);

        if ($wantsAdminPasswordChange) {
            if (! $hasCurrentPassword) {
                return response()->json([
                    'message' => 'Ingresa la contrasena actual del administrador.',
                ], 422);
            }

            if (! $hasNewPassword) {
                return response()->json([
                    'message' => 'Ingresa la nueva contrasena del administrador.',
                ], 422);
            }

            if (! Hash::check($data['current_password'], $user->password)) {
                return response()->json([
                    'message' => 'La contrasena actual no coincide con la registrada.',
                ], 422);
            }

            if ($this->passwordWasUsedByAdmin($user, $data['password'])) {
                return response()->json([
                    'message' => 'La nueva contrasena no puede repetirse con una anterior.',
                ], 422);
            }
        }

        $user->name = $data['name'];
        $user->email = $data['email'];
        $user->role = $data['role'];

        if (! empty($data['password'])) {
            $user->password = Hash::make($data['password']);
            $user->session_version = ((int) ($user->session_version ?? 1)) + 1;
        }

        $user->save();

        if (! empty($data['password'])) {
            $this->storePasswordHistory($user);
            if (Auth::check() && Auth::id() === $user->id) {
                $request->session()->put('auth_session_version', (int) $user->session_version);
            }
        }

        $this->logAdminAudit('system_user_updated', $request, Auth::user(), 'user', $user->id, [
            'updated_role' => $user->role,
            'updated_email' => $user->email,
            'password_changed' => ! empty($data['password']),
        ]);

        if ($request->expectsJson()) {
            return response()->json([
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'role' => ucfirst($user->role),
                    'role_value' => $user->role,
                    'initial' => strtoupper(substr($user->name, 0, 1)),
                    'search' => strtolower($user->name . ' ' . $user->email),
                    'update_url' => route('panel.usuarios.update', $user),
                    'delete_url' => route('panel.usuarios.destroy', $user),
                ],
            ]);
        }

        return redirect()
            ->route('panel', $this->panelRouteParams($request, 'usuarios'))
            ->with('success', 'Usuario actualizado correctamente.');
    }

    public function sendAdminPasswordCode(Request $request, User $user)
    {
        if ($user->role !== 'administrador') {
            return response()->json([
                'message' => 'Solo los administradores pueden cambiar su contrasena por correo.',
            ], 422);
        }

        $code = (string) random_int(100000, 999999);

        DB::table('admin_password_reset_codes')
            ->where('user_id', $user->id)
            ->delete();

        DB::table('admin_password_reset_codes')->insert([
            'user_id' => $user->id,
            'code_hash' => Hash::make($code),
            'expires_at' => now()->addMinutes(10),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        Mail::to($user->email)->send(new AdminPasswordCodeMail($user, $code));
        $this->logAdminAudit('admin_password_code_sent', $request, Auth::user(), 'user', $user->id);

        return response()->json([
            'message' => $this->mailDeliveredMessage('Codigo enviado al correo del administrador.'),
        ]);
    }

    public function resetAdminPassword(Request $request, User $user)
    {
        if ($user->role !== 'administrador') {
            return response()->json([
                'message' => 'Solo los administradores pueden usar este cambio de contrasena.',
            ], 422);
        }

        $data = $request->validate([
            'verification_code' => ['required', 'digits:6'],
        ], [
            'verification_code.required' => 'El codigo es obligatorio.',
            'verification_code.digits' => 'El codigo debe tener 6 numeros.',
        ]);

        $reset = DB::table('admin_password_reset_codes')
            ->where('user_id', $user->id)
            ->whereNull('used_at')
            ->where('expires_at', '>=', now())
            ->latest('id')
            ->first();

        if (! $reset || ! Hash::check($data['verification_code'], $reset->code_hash)) {
            return response()->json([
                'message' => 'El codigo no es valido o ya vencio.',
            ], 422);
        }

        $newPassword = $this->generateUniqueAdminPassword($user);

        DB::transaction(function () use ($user, $reset, $newPassword) {
            $user->password = Hash::make($newPassword);
            $user->session_version = ((int) ($user->session_version ?? 1)) + 1;
            $user->save();

            $this->storePasswordHistory($user);

            DB::table('admin_password_reset_codes')
                ->where('id', $reset->id)
                ->update([
                    'used_at' => now(),
                    'updated_at' => now(),
                ]);
        });

        if (Auth::check() && Auth::id() === $user->id) {
            $request->session()->put('auth_session_version', (int) $user->session_version);
        }

        Mail::to($user->email)->send(new AdminPasswordGeneratedMail($user, $newPassword));
        $this->logAdminAudit('admin_password_reset_by_code', $request, Auth::user(), 'user', $user->id);

        return response()->json([
            'message' => $this->mailDeliveredMessage('Nueva contrasena enviada al correo del administrador.'),
        ]);
    }

    public function destroySystemUser(Request $request, User $user)
    {
        if ($user->role !== 'usuario') {
            if ($request->expectsJson()) {
                return response()->json([
                    'message' => 'Solo se pueden eliminar usuarios con rol usuario.',
                ], 422);
            }

            return redirect()
                ->route('panel', $this->panelRouteParams($request, 'usuarios'))
                ->with('error', 'Solo se pueden eliminar usuarios con rol usuario.');
        }

        $user->delete();
        $this->logAdminAudit('system_user_deleted', $request, Auth::user(), 'user', $user->id, [
            'deleted_email' => $user->email,
        ]);

        if ($request->expectsJson()) {
            return response()->json([
                'deleted' => true,
            ]);
        }

        return redirect()
            ->route('panel', $this->panelRouteParams($request, 'usuarios'))
            ->with('success', 'Usuario eliminado correctamente.');
    }

    public function destroyCargaUsuario(Request $request, Usariosapp $usariosapp)
    {
        $targetId = $usariosapp->id;
        $targetEmail = $usariosapp->correo;
        $usariosapp->delete();

        if (Auth::check()) {
            $this->logAdminAudit('app_user_deleted', $request, Auth::user(), 'usariosapp', $targetId, [
                'correo' => $targetEmail,
            ]);
        }

        if ($request->expectsJson()) {
            return response()->json([
                'deleted' => true,
                'id' => $targetId,
            ]);
        }

        return redirect()
            ->route('panel', $this->panelRouteParams($request, 'cargas'))
            ->with('success_cargas', 'Usuario eliminado correctamente de Cargas.');
    }

    public function updateRecetaUsuario(Request $request, Usariosapp $usariosapp)
    {
        $data = $request->validate([
            'receta_opinion' => ['nullable', 'string', 'max:1200'],
            'receta_imagen' => ['nullable', 'image', 'max:4096'],
        ]);

        if ($request->hasFile('receta_imagen')) {
            $imagePath = $request->file('receta_imagen')->store('recetas', 's3');

            if (! $imagePath) {
                throw \Illuminate\Validation\ValidationException::withMessages([
                    'receta_imagen' => 'No se pudo subir la imagen de referencia. Intenta de nuevo.',
                ]);
            }

            $data['receta_imagen'] = $imagePath;
        }

        $usariosapp->update($data);

        if (Auth::check()) {
            $this->logAdminAudit('recipe_user_updated', $request, Auth::user(), 'usariosapp', $usariosapp->id, [
                'has_image' => ! empty($data['receta_imagen']),
                'has_opinion' => ! empty($data['receta_opinion']),
            ]);
        }

        if ($request->expectsJson()) {
            return response()->json([
                'message' => 'Recomendacion enviada correctamente al usuario.',
                'image_url' => $this->recipeImageUrl($usariosapp->receta_imagen),
            ]);
        }

        return redirect()
            ->route('panel', $this->panelRouteParams($request, 'recetas', [
                'recipe_user' => $usariosapp->id,
                'recipe_range' => $request->query('recipe_range', 'todos'),
            ]))
            ->with('success_recetas', 'Recomendacion enviada correctamente al usuario.');
    }

    public function updateRecetaRango(Request $request, Usariosapp $usariosapp)
    {
        $data = $request->validate([
            'rango_receta' => ['required', 'in:alto,medio,bajo'],
        ]);

        $usariosapp->update($data);

        if (Auth::check()) {
            $this->logAdminAudit('recipe_range_updated', $request, Auth::user(), 'usariosapp', $usariosapp->id, [
                'rango_receta' => $usariosapp->rango_receta,
            ]);
        }

        if ($request->expectsJson()) {
            return response()->json([
                'message' => 'Clasificacion actualizada correctamente.',
                'rango_receta' => $usariosapp->rango_receta,
            ]);
        }

        return redirect()
            ->route('panel', $this->panelRouteParams($request, 'recetas', [
                'recipe_range' => $request->query('recipe_range', 'todos'),
                'search' => $request->query('search'),
            ]))
            ->with('success_recetas', 'Clasificacion actualizada correctamente.');
    }

    public function destroy(Request $request)
    {
        $this->logAdminAudit('logout', $request, Auth::user(), 'user', Auth::id());
        Auth::logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('login');
    }

    private function formatCargaUsuarioForPanel(Usariosapp $user): array
    {
        return [
            'id' => $user->id,
            'nombre' => $user->nombre,
            'correo' => $user->correo,
            'dpi' => $user->dpi,
            'initial' => strtoupper(substr($user->nombre, 0, 1)),
            'search' => strtolower($user->nombre . ' ' . $user->dpi),
            'update_url' => route('panel.cargas.update', $user),
            'delete_url' => route('panel.cargas.destroy', $user),
        ];
    }

    private function buildHistoryEntries(int $historyRange, string $historyDate): Collection
    {
        if ($historyDate !== '') {
            try {
                $selectedDate = Carbon::createFromFormat('Y-m-d', $historyDate);
            } catch (InvalidFormatException) {
                $selectedDate = Carbon::now();
            }

            return collect([
                [
                    'fecha' => $selectedDate->format('d/m/Y'),
                    'hora' => '07:00',
                    'titulo' => '',
                    'calorias' => '',
                    'carbohidratos' => '',
                    'proteina' => '',
                    'grasas' => '',
                ],
            ]);
        }

        return collect(range(0, $historyRange - 1))
            ->map(function (int $offset) {
                $date = Carbon::now()->subDays($offset);

                return [
                    'fecha' => $date->format('d/m/Y'),
                    'hora' => $date->copy()->setTime(7, 0)->format('H:i'),
                    'titulo' => '',
                    'calorias' => '',
                    'carbohidratos' => '',
                    'proteina' => '',
                    'grasas' => '',
                ];
            });
    }

    private function generateUniqueAdminPassword(User $user): string
    {
        for ($attempt = 0; $attempt < 50; $attempt++) {
            $password = $this->generateSecurePassword();

            if (! $this->passwordWasUsedByAdmin($user, $password)) {
                return $password;
            }
        }

        abort(500, 'No se pudo generar una contrasena unica para el administrador.');
    }

    private function generateSecurePassword(int $length = 14): string
    {
        $uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        $lowercase = 'abcdefghijkmnopqrstuvwxyz';
        $numbers = '23456789';
        $symbols = '@#$%&*!?';
        $pool = $uppercase . $lowercase . $numbers . $symbols;

        $password = [
            $uppercase[random_int(0, strlen($uppercase) - 1)],
            $lowercase[random_int(0, strlen($lowercase) - 1)],
            $numbers[random_int(0, strlen($numbers) - 1)],
            $symbols[random_int(0, strlen($symbols) - 1)],
        ];

        for ($index = count($password); $index < $length; $index++) {
            $password[] = $pool[random_int(0, strlen($pool) - 1)];
        }

        shuffle($password);

        return implode('', $password);
    }

    private function passwordWasUsedByAdmin(User $user, string $plainPassword): bool
    {
        if (Hash::check($plainPassword, $user->password)) {
            return true;
        }

        $history = DB::table('user_password_histories')
            ->where('user_id', $user->id)
            ->pluck('password_hash');

        foreach ($history as $passwordHash) {
            if (Hash::check($plainPassword, $passwordHash)) {
                return true;
            }
        }

        return false;
    }

    private function storePasswordHistory(User $user): void
    {
        $alreadyStored = DB::table('user_password_histories')
            ->where('user_id', $user->id)
            ->where('password_hash', $user->password)
            ->exists();

        if ($alreadyStored) {
            return;
        }

        DB::table('user_password_histories')->insert([
            'user_id' => $user->id,
            'password_hash' => $user->password,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function startAdminTwoFactorFlow(Request $request, User $user): void
    {
        $code = (string) random_int(100000, 999999);

        DB::table('admin_login_verification_codes')
            ->where('user_id', $user->id)
            ->delete();

        DB::table('admin_login_verification_codes')->insert([
            'user_id' => $user->id,
            'code_hash' => Hash::make($code),
            'expires_at' => now()->addMinutes(10),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $request->session()->put('pending_admin_login_user_id', $user->id);

        try {
            Mail::to($user->email)->send(new AdminLoginCodeMail($user, $code));
        } catch (Throwable $exception) {
            report($exception);

            DB::table('admin_login_verification_codes')
                ->where('user_id', $user->id)
                ->delete();

            $this->clearPendingAdminLogin($request);
            $this->logAdminAudit('admin_login_code_failed', $request, $user, 'user', $user->id);

            throw ValidationException::withMessages([
                'email' => 'No se pudo enviar el codigo de seguridad. Revisa la configuracion SMTP e intenta de nuevo.',
            ]);
        }

        $this->logAdminAudit('admin_login_code_sent', $request, $user, 'user', $user->id);
    }

    private function getPendingAdminLoginUser(Request $request): ?User
    {
        $pendingUserId = $request->session()->get('pending_admin_login_user_id');

        if (! $pendingUserId) {
            return null;
        }

        $user = User::find($pendingUserId);

        if (! $user || $user->role !== 'administrador') {
            $this->clearPendingAdminLogin($request);

            return null;
        }

        return $user;
    }

    private function clearPendingAdminLogin(Request $request): void
    {
        $request->session()->forget('pending_admin_login_user_id');
    }

    private function logAdminAudit(
        string $action,
        Request $request,
        ?User $actor = null,
        ?string $targetType = null,
        ?int $targetId = null,
        array $context = []
    ): void {
        $actor ??= Auth::user();

        DB::table('admin_audit_logs')->insert([
            'actor_user_id' => $actor?->id,
            'action' => $action,
            'target_type' => $targetType,
            'target_id' => $targetId,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'context' => empty($context) ? null : json_encode($context, JSON_UNESCAPED_UNICODE),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function normalizeLoginEmail(string $email): string
    {
        return mb_strtolower(trim($email));
    }

    private function getActiveUserLoginLock(?User $user): ?Carbon
    {
        if (! $user || ! $user->login_locked_until) {
            return null;
        }

        $lockedUntil = Carbon::parse($user->login_locked_until);

        if ($lockedUntil->isFuture()) {
            return $lockedUntil;
        }

        $this->clearUserLoginAttempts($user);

        return null;
    }

    private function registerFailedUserLoginAttempt(User $user): ?Carbon
    {
        $attempts = ((int) $user->failed_login_attempts) + 1;
        $lockUntil = $attempts >= 3 ? now()->addMinutes(20) : null;

        $user->forceFill([
            'failed_login_attempts' => $attempts,
            'login_locked_until' => $lockUntil,
        ])->save();

        return $lockUntil;
    }

    private function clearUserLoginAttempts(?User $user): void
    {
        if (! $user) {
            return;
        }

        if ((int) $user->failed_login_attempts === 0 && ! $user->login_locked_until) {
            return;
        }

        $user->forceFill([
            'failed_login_attempts' => 0,
            'login_locked_until' => null,
        ])->save();
    }

    private function getActiveLoginLock(string $email): ?object
    {
        $lock = DB::table('login_attempt_locks')
            ->where('email', $email)
            ->first();

        if (! $lock) {
            return null;
        }

        if ($lock->locked_until && Carbon::parse($lock->locked_until)->isFuture()) {
            return $lock;
        }

        if ((int) $lock->failed_attempts > 0 || $lock->locked_until) {
            $this->clearLoginAttempts($email);
        }

        return null;
    }

    private function registerFailedLoginAttempt(string $email): ?Carbon
    {
        $existing = DB::table('login_attempt_locks')
            ->where('email', $email)
            ->first();

        $attempts = ((int) ($existing->failed_attempts ?? 0)) + 1;
        $lockUntil = $attempts >= 3 ? now()->addMinutes(20) : null;

        DB::table('login_attempt_locks')->updateOrInsert(
            ['email' => $email],
            [
                'failed_attempts' => $attempts,
                'locked_until' => $lockUntil,
                'updated_at' => now(),
                'created_at' => $existing->created_at ?? now(),
            ]
        );

        return $lockUntil;
    }

    private function clearLoginAttempts(string $email): void
    {
        DB::table('login_attempt_locks')
            ->where('email', $email)
            ->delete();
    }

    private function getLoginLockMessage($lockedUntil): string
    {
        $lockTime = $lockedUntil instanceof Carbon
            ? $lockedUntil
            : Carbon::parse($lockedUntil);

        $minutes = max(1, (int) ceil(now()->diffInSeconds($lockTime) / 60));

        return 'Tu acceso esta bloqueado por 20 minutos. Intenta de nuevo en ' . $minutes . ' minuto' . ($minutes === 1 ? '' : 's') . '.';
    }

    private function mailDeliveredMessage(string $defaultMessage): string
    {
        if (config('mail.default') === 'log') {
            return $defaultMessage . ' El proyecto esta en modo log, asi que revisa storage/logs/laravel.log para ver el contenido del correo.';
        }

        return $defaultMessage;
    }

    private function recipeImageUrl(?string $path): ?string
    {
        if (! $path) {
            return null;
        }

        try {
            if (Storage::disk('s3')->exists($path)) {
                return Storage::disk('s3')->temporaryUrl($path, now()->addMinutes(30));
            }
        } catch (Throwable) {
            // Si el objeto viejo todavia esta local, conservamos la vista previa.
        }

        if (Storage::disk('public')->exists($path)) {
            return asset('storage/' . $path);
        }

        try {
            return Storage::disk('s3')->url($path);
        } catch (Throwable) {
            return null;
        }
    }

    private function isAgendaAppointmentInsideBusinessHours(Carbon $appointmentAt): bool
    {
        $minutes = ((int) $appointmentAt->format('H') * 60) + (int) $appointmentAt->format('i');

        return $minutes >= (8 * 60) && $minutes <= (17 * 60);
    }

    private function hasValidPanelSectionKey(Request $request, string $section, ?string $providedKey): bool
    {
        if (! $request->user() || ! is_string($providedKey) || $providedKey === '') {
            return false;
        }

        return hash_equals($this->makePanelSectionKey($request, $section), $providedKey);
    }

    private function makePanelSectionKey(Request $request, string $section): string
    {
        return hash_hmac(
            'sha256',
            $section . '|' . $request->user()->id . '|' . $request->session()->token(),
            (string) config('app.key')
        );
    }

    private function panelRouteParams(Request $request, string $section, array $params = []): array
    {
        return array_merge([
            'section' => $section,
            'panel_key' => $this->makePanelSectionKey($request, $section),
        ], $params);
    }

    private function buildFacturaPdf(BillingInvoice $billingInvoice)
    {
        return Pdf::loadView('pdfs.factura', [
            'invoiceNumber' => $billingInvoice->invoice_number,
            'generatedAt' => $billingInvoice->billed_at,
            'clienteNombre' => $billingInvoice->cliente_nombre,
            'clienteCorreo' => $billingInvoice->cliente_correo,
            'clienteDpi' => $billingInvoice->cliente_dpi,
            'citaCosto' => (float) $billingInvoice->cita_costo,
            'extras' => collect($billingInvoice->extras ?? []),
            'extrasTotal' => (float) $billingInvoice->extras_total,
            'total' => (float) $billingInvoice->total,
            'generatedBy' => 'Nutriglow',
        ])->setPaper('a4');
    }

    private function queueBillingInvoiceMail(BillingInvoice $billingInvoice, Request $request, string $pdfPath): void
    {
        if (! filter_var($billingInvoice->cliente_correo, FILTER_VALIDATE_EMAIL)) {
            return;
        }

        $actor = Auth::user();

        app()->terminating(function () use ($billingInvoice, $request, $actor, $pdfPath) {
            try {
                $fileName = 'factura-' . strtolower($billingInvoice->invoice_number) . '.pdf';

                Mail::to($billingInvoice->cliente_correo)->send(
                    new BillingInvoiceMail($billingInvoice, $pdfPath, $fileName)
                );

                if ($actor) {
                    $this->logAdminAudit('invoice_emailed_to_client', $request, $actor, 'billing_invoices', $billingInvoice->id, [
                        'invoice_number' => $billingInvoice->invoice_number,
                        'cliente_correo' => $billingInvoice->cliente_correo,
                    ]);
                }
            } catch (Throwable $exception) {
                if ($actor) {
                    $this->logAdminAudit('invoice_email_failed', $request, $actor, 'billing_invoices', $billingInvoice->id, [
                        'invoice_number' => $billingInvoice->invoice_number,
                        'cliente_correo' => $billingInvoice->cliente_correo,
                        'error' => $exception->getMessage(),
                    ]);
                }

                report($exception);
            }
        });
    }

    private function storeBillingInvoicePdf(BillingInvoice $billingInvoice): string
    {
        $pdfPath = $this->billingInvoicePdfPath($billingInvoice);

        Storage::disk('local')->put($pdfPath, $this->buildFacturaPdf($billingInvoice)->output());

        return $pdfPath;
    }

    private function ensureBillingInvoicePdfExists(BillingInvoice $billingInvoice): string
    {
        $pdfPath = $this->billingInvoicePdfPath($billingInvoice);

        if (! Storage::disk('local')->exists($pdfPath)) {
            return $this->storeBillingInvoicePdf($billingInvoice);
        }

        return $pdfPath;
    }

    private function billingInvoicePdfPath(BillingInvoice $billingInvoice): string
    {
        return 'invoices/factura-' . strtolower($billingInvoice->invoice_number) . '.pdf';
    }

    private function downloadBillingInvoicePdf(BillingInvoice $billingInvoice, string $pdfPath)
    {
        return Storage::disk('local')->download(
            $pdfPath,
            'factura-' . strtolower($billingInvoice->invoice_number) . '.pdf',
            ['Content-Type' => 'application/pdf']
        );
    }

    private function systemUserValidationMessages(): array
    {
        return [
            'name.required' => 'El nombre es obligatorio.',
            'email.required' => 'El correo es obligatorio.',
            'email.email' => 'Ingresa un correo valido.',
            'email.unique' => 'Este correo ya esta registrado.',
            'current_password.string' => 'La contrasena actual no es valida.',
            'password.required' => 'La contrasena es obligatoria.',
            'password.min' => 'La contrasena debe tener al menos 8 caracteres.',
            'password.mixed' => 'La contrasena debe incluir mayusculas y minusculas.',
            'password.numbers' => 'La contrasena debe incluir al menos un numero.',
            'password.symbols' => 'La contrasena debe incluir al menos un simbolo.',
            'role.required' => 'El rol es obligatorio.',
            'role.in' => 'Selecciona un rol valido.',
        ];
    }
}
