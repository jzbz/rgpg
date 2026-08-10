// Hide the console window on Windows release builds. rgpg targets Linux and
// macOS today, but the attribute is free and keeps a cross-compile honest.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rgpg_core::cert::format_time;
use rgpg_core::certify::{self, Certification, CertifyRequest};
use rgpg_core::keygen::{self, KeyGenRequest, KeyType};
use rgpg_core::lifecycle;
use rgpg_core::ops::{self, InputKind, VerifyResult};
use rgpg_core::revoke::{self, Reason, RevokeRequest};
use rgpg_core::{CertSummary, Store, wot};
use slint::{ModelRc, SharedString, VecModel};

slint::include_modules!();

/// Which slice of the store the list is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    All,
    Mine,
    Others,
}

impl Scope {
    fn from_index(index: i32) -> Self {
        match index {
            1 => Scope::Mine,
            2 => Scope::Others,
            _ => Scope::All,
        }
    }

    fn accepts(self, cert: &CertSummary) -> bool {
        match self {
            Scope::All => true,
            Scope::Mine => cert.has_secret,
            Scope::Others => !cert.has_secret,
        }
    }
}

/// A certificate offered as an encryption recipient, plus whether it is ticked.
struct Recipient {
    fingerprint: String,
    label: String,
    sublabel: String,
    initials: String,
    tint: i32,
    selected: bool,
}

/// Everything the callbacks share.
///
/// `all` is the store's contents; `shown` is what the list is displaying after
/// the scope and search filters. A row index from the UI refers to `shown`, so
/// the two are only ever rebuilt together — see [`reload`] and [`apply_filter`].
struct State {
    store: Store,
    all: Vec<CertSummary>,
    shown: Vec<CertSummary>,
    filter: String,
    scope: Scope,

    se_input: Option<PathBuf>,
    se_recipients: Vec<Recipient>,
    /// (fingerprint, label) of every certificate that can sign and has a
    /// secret key in the store.
    se_signers: Vec<(String, String)>,

    dv_input: Option<PathBuf>,
    dv_data: Option<PathBuf>,
    dv_kind: InputKind,

    /// Fingerprint of the certificate the certify dialog is about.
    certify_target: Option<String>,
    /// (user ID, ticked)
    certify_user_ids: Vec<(String, bool)>,
    /// (fingerprint, label) of our own certification-capable keys.
    certify_certifiers: Vec<(String, String)>,

    /// Certificates found on the network, not yet in the store.
    lookup_results: Vec<rgpg_core::keyserver::Found>,

    /// Fingerprint the revoke dialog is about, and whether it is withdrawing a
    /// certification rather than revoking the key itself.
    revoke_target: Option<String>,
    revoke_certification: bool,
}

type Shared = Arc<Mutex<State>>;

// ------------------------------------------------------------------ renderer

/// Set on the restarted process so the software fallback can only happen once.
const FALLBACK_GUARD: &str = "RGPG_SOFTWARE_FALLBACK";

/// Raised by the panic hook when the panic was wgpu failing to find an adapter,
/// so that an unrelated panic is not mistaken for a graphics problem.
static NO_GPU_ADAPTER: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    configure_renderer();
    install_panic_hook();

    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(e)) => {
            eprintln!("rgpg: {e}");
            ExitCode::FAILURE
        }
        Err(payload) => {
            if NO_GPU_ADAPTER.load(Ordering::Relaxed) {
                restart_with_software_renderer()
            } else {
                // Not a graphics failure: let it look like an ordinary crash.
                std::panic::resume_unwind(payload)
            }
        }
    }
}

/// Choose the renderer up front, so a machine without a usable GPU gets a
/// window instead of a crash.
///
/// Asking for wgpu explicitly is what makes this possible: `select()` probes
/// for an adapter and reports failure as an error, where leaving Slint to pick
/// the renderer on its own defers the same question to window-creation time,
/// where it is an `expect` and takes the process with it.
///
/// The probe cannot see everything. It asks wgpu for an adapter without a
/// surface, so a driver that exists but cannot present to a window — a plain X
/// server with no DRI3, some VMs — still satisfies it and still fails later.
/// [`restart_with_software_renderer`] is the net under that case.
///
/// The backend set is pinned to `PRIMARY` on purpose. `WGPUSettings::default()`
/// asks for more than Slint does internally — the GL backend among them — and
/// wgpu's GL backend *hangs indefinitely* on a display it cannot use rather
/// than reporting failure. A machine that would only have managed GL now gets
/// the software renderer, which is slower but appears.
fn configure_renderer() {
    // An explicit choice by the user wins.
    if std::env::var_os("SLINT_BACKEND").is_some() {
        return;
    }

    use slint::wgpu_29::{WGPUConfiguration, WGPUSettings, wgpu};

    // WGPUSettings is #[non_exhaustive], so it has to be built by mutation.
    let mut settings = WGPUSettings::default();
    settings.backends = wgpu::Backends::PRIMARY;

    let gpu = slint::BackendSelector::new()
        .require_wgpu_29(WGPUConfiguration::Automatic(settings))
        .select();

    let Err(e) = gpu else {
        return;
    };

    eprintln!("rgpg: no GPU renderer ({e}); using the software renderer.");
    if let Err(e) = slint::BackendSelector::new()
        .renderer_name("software".into())
        .select()
    {
        eprintln!("rgpg: could not select the software renderer either: {e}");
    }
}

fn install_panic_hook() {
    let inner = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or_default();

        if message.contains("Failed to find an appropriate adapter") {
            NO_GPU_ADAPTER.store(true, Ordering::Relaxed);
            // Swallow the backtrace: main turns this into a restart, and the
            // wall of wgpu diagnostics would only look like a crash.
            return;
        }
        inner(info);
    }));
}

/// Re-run this executable on the software renderer.
///
/// A fresh process rather than a retry in-place: Slint's platform can only be
/// set once, and the failed attempt leaves the winit event loop half-built.
fn restart_with_software_renderer() -> ExitCode {
    if std::env::var_os(FALLBACK_GUARD).is_some() {
        eprintln!("rgpg: the software renderer failed as well; giving up.");
        return ExitCode::FAILURE;
    }

    eprintln!("rgpg: no usable GPU adapter, restarting with the software renderer.");

    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("rgpg: cannot locate this executable to restart it: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut command = std::process::Command::new(executable);
    command
        .args(std::env::args_os().skip(1))
        .env("SLINT_BACKEND", "winit-software")
        .env(FALLBACK_GUARD, "1");

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec replaces this process, so on success nothing below runs.
        let e = command.exec();
        eprintln!("rgpg: could not restart: {e}");
        ExitCode::FAILURE
    }

    #[cfg(not(unix))]
    match command.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("rgpg: could not restart: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------- app

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let ui = AppWindow::new()?;

    let store = match Store::open_default() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("rgpg: cannot open the certificate store: {e}");
            return Err(e.into());
        }
    };

    let state: Shared = Arc::new(Mutex::new(State {
        store,
        all: Vec::new(),
        shown: Vec::new(),
        filter: String::new(),
        scope: Scope::All,
        se_input: None,
        se_recipients: Vec::new(),
        se_signers: Vec::new(),
        dv_input: None,
        dv_data: None,
        dv_kind: InputKind::NotOpenPgp,
        certify_target: None,
        certify_user_ids: Vec::new(),
        certify_certifiers: Vec::new(),
        lookup_results: Vec::new(),
        revoke_target: None,
        revoke_certification: false,
    }));

    reload(&ui, &state);
    wire_list(&ui, &state);
    wire_keygen(&ui, &state);
    wire_sign_encrypt(&ui, &state);
    wire_decrypt_verify(&ui, &state);
    wire_certify(&ui, &state);
    wire_revoke(&ui, &state);
    wire_notepad(&ui, &state);
    wire_lifecycle(&ui, &state);
    wire_lookup(&ui, &state);

    ui.run()?;
    Ok(())
}

// ---------------------------------------------------------------- list pane

fn wire_list(ui: &AppWindow, state: &Shared) {
    ui.on_refresh({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let ui = ui_weak.unwrap();
            reload(&ui, &state);
        }
    });

    ui.on_filter_changed({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |text| {
            let ui = ui_weak.unwrap();
            state.lock().unwrap().filter = text.to_lowercase();
            apply_filter(&ui, &state);
        }
    });

    ui.on_scope_changed({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |index| {
            let ui = ui_weak.unwrap();
            state.lock().unwrap().scope = Scope::from_index(index);
            apply_filter(&ui, &state);
        }
    });

    ui.on_row_selected({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |row| {
            let ui = ui_weak.unwrap();
            let guard = state.lock().unwrap();

            let Some(summary) = usize::try_from(row)
                .ok()
                .and_then(|r| guard.shown.get(r))
                .cloned()
            else {
                ui.set_has_selection(false);
                return;
            };

            ui.set_detail(to_row(&summary));
            ui.set_has_selection(true);
            push_certifications(&ui, &guard, &summary);
        }
    });

    ui.on_import_file({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            // The portal dialog is driven by the Slint event loop rather than a
            // worker thread: on macOS a file dialog has to live on the main
            // thread, and this way one code path works on both platforms.
            let _ = slint::spawn_local(async move {
                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("Import certificates")
                    .add_filter("OpenPGP", &["asc", "pgp", "gpg", "key", "pub", "sec"])
                    .add_filter("All files", &["*"])
                    .pick_file()
                    .await
                else {
                    return;
                };
                let ui = ui_weak.unwrap();
                // A revocation certificate is a bare signature, not a
                // certificate, so CertParser rejects it. Same button, because a
                // user handed a .rev file expects Import to take it.
                let outcome = {
                    let guard = state.lock().unwrap();
                    match guard.store.import_file(file.path()) {
                        Ok(certs) => Ok(format!("Imported {} certificate(s)", certs.len())),
                        Err(import_error) => {
                            match revoke::apply_revocation_file(&guard.store, file.path()) {
                                Ok(cert) => Ok(format!(
                                    "Revoked {}",
                                    rgpg_core::CertSummary::from_cert(&cert).primary_user_id
                                )),
                                Err(_) => Err(import_error),
                            }
                        }
                    }
                };
                match outcome {
                    Ok(message) => {
                        reload(&ui, &state);
                        ui.set_status(message.into());
                    }
                    Err(e) => ui.set_status(format!("Import failed: {e}").into()),
                }
            });
        }
    });

    ui.on_export_selected({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let _ = slint::spawn_local(async move {
                let (fingerprint, suggested) = {
                    let ui = ui_weak.unwrap();
                    let row = ui.get_current_row();
                    let state = state.lock().unwrap();
                    match usize::try_from(row).ok().and_then(|r| state.shown.get(r)) {
                        Some(s) => (s.fingerprint.clone(), format!("{}.asc", s.key_id)),
                        None => return,
                    }
                };

                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("Export certificate")
                    .set_file_name(&suggested)
                    .save_file()
                    .await
                else {
                    return;
                };

                let ui = ui_weak.unwrap();
                let outcome = state
                    .lock()
                    .unwrap()
                    .store
                    .export_file(std::slice::from_ref(&fingerprint), file.path());
                ui.set_status(SharedString::from(match outcome {
                    Ok(()) => format!("Exported to {}", file.path().display()),
                    Err(e) => format!("Export failed: {e}"),
                }));
            });
        }
    });
}

// ------------------------------------------------------------- key generation

fn wire_keygen(ui: &AppWindow, state: &Shared) {
    ui.on_generate_key({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |name, email, password, key_type, expiry| {
            let ui = ui_weak.unwrap();

            let request = KeyGenRequest {
                user_ids: vec![format!("{} <{}>", name.trim(), email.trim())],
                key_type: KeyType::ALL
                    .get(key_type.max(0) as usize)
                    .copied()
                    .unwrap_or_default(),
                validity: expiry_from_index(expiry),
                password: Some(password.to_string()).filter(|p| !p.is_empty()),
            };

            ui.set_busy(true);
            ui.set_status("Generating key…".into());

            // RSA-4096 takes seconds. Run it off the UI thread and hand the
            // finished certificate back through the event loop.
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            std::thread::spawn(move || {
                let generated = keygen::generate(&request);
                let _ = slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_busy(false);
                    match generated.and_then(|key| {
                        let guard = state.lock().unwrap();
                        guard.store.insert_secret(&key.cert)?;
                        // Written once, now: a revocation certificate cannot be
                        // recreated later without the secret key, and this is
                        // the only moment we are certain to have it unlocked.
                        let fingerprint = key.cert.fingerprint().to_hex();
                        guard
                            .store
                            .save_revocation(&fingerprint, &revoke::armor(&key.revocation)?)?;
                        Ok(fingerprint)
                    }) {
                        Ok(fingerprint) => {
                            ui.set_keygen_open(false);
                            reload(&ui, &state);
                            ui.set_status(format!("Created {fingerprint}").into());
                        }
                        Err(e) => ui.set_status(format!("Key generation failed: {e}").into()),
                    }
                });
            });
        }
    });
}

fn expiry_from_index(index: i32) -> Option<Duration> {
    const YEAR: u64 = 365 * 24 * 60 * 60;
    match index {
        0 => Some(Duration::from_secs(2 * YEAR)),
        1 => Some(Duration::from_secs(YEAR)),
        2 => Some(Duration::from_secs(5 * YEAR)),
        _ => None,
    }
}

// ------------------------------------------------------------- sign / encrypt

fn wire_sign_encrypt(ui: &AppWindow, state: &Shared) {
    ui.on_open_sign_encrypt({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let ui = ui_weak.unwrap();
            let mut guard = state.lock().unwrap();

            // Anyone who can receive encrypted mail is a candidate recipient;
            // whatever is selected in the list starts ticked.
            let preselect = usize::try_from(ui.get_current_row())
                .ok()
                .and_then(|r| guard.shown.get(r))
                .map(|s| s.fingerprint.clone());

            let recipients: Vec<Recipient> = guard
                .all
                .iter()
                .filter(|c| c.can_encrypt)
                .map(|c| {
                    let (name, email) = split_user_id(&c.primary_user_id);
                    Recipient {
                        selected: preselect.as_deref() == Some(c.fingerprint.as_str()),
                        initials: initials(&name, &email, &c.key_id),
                        tint: tint_index(&c.fingerprint),
                        label: if name.is_empty() {
                            c.primary_user_id.clone()
                        } else {
                            name
                        },
                        sublabel: if email.is_empty() {
                            c.key_id.clone()
                        } else {
                            email
                        },
                        fingerprint: c.fingerprint.clone(),
                    }
                })
                .collect();

            // A card key has no local secret: the agent holds it. Label those
            // so it is obvious which choice will ask for a PIN.
            let signers: Vec<(String, String)> = guard
                .all
                .iter()
                .filter(|c| c.can_sign && (c.has_secret || c.agent_backed))
                .map(|c| {
                    let label = match &c.card_serial {
                        Some(_) => format!("{} (smartcard)", c.primary_user_id),
                        None => c.primary_user_id.clone(),
                    };
                    (c.fingerprint.clone(), label)
                })
                .collect();

            guard.se_recipients = recipients;
            guard.se_signers = signers;

            push_sign_encrypt(&ui, &guard);
            drop(guard);
            ui.set_signenc_open(true);
        }
    });

    ui.on_se_pick_input({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let _ = slint::spawn_local(async move {
                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("File to sign or encrypt")
                    .pick_file()
                    .await
                else {
                    return;
                };
                let ui = ui_weak.unwrap();
                let mut guard = state.lock().unwrap();
                guard.se_input = Some(file.path().to_path_buf());
                push_sign_encrypt(&ui, &guard);
            });
        }
    });

    ui.on_se_toggle_recipient({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |index| {
            let ui = ui_weak.unwrap();
            let mut guard = state.lock().unwrap();
            if let Some(entry) = usize::try_from(index)
                .ok()
                .and_then(|i| guard.se_recipients.get_mut(i))
            {
                entry.selected = !entry.selected;
            }
            push_sign_encrypt(&ui, &guard);
        }
    });

    ui.on_se_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |encrypt, sign, signer_index, password, secret| {
            let ui = ui_weak.unwrap();
            ui.set_busy(true);
            ui.set_status(if encrypt { "Encrypting…" } else { "Signing…" }.into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let (password, secret) = (password.to_string(), secret.to_string());
            std::thread::spawn(move || {
                let outcome =
                    run_sign_encrypt(&state, encrypt, sign, signer_index, &password, &secret);
                let _ = slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_busy(false);
                    match outcome {
                        Ok(output) => {
                            ui.set_signenc_open(false);
                            ui.set_status(format!("Wrote {}", output.display()).into());
                        }
                        Err(message) => ui.set_status(message.into()),
                    }
                });
            });
        }
    });
}

/// The blocking half of Sign / Encrypt, run on a worker thread.
fn run_sign_encrypt(
    state: &Shared,
    encrypt: bool,
    sign: bool,
    signer_index: i32,
    password: &str,
    secret: &str,
) -> Result<PathBuf, String> {
    let guard = state.lock().unwrap();

    let input = guard
        .se_input
        .clone()
        .ok_or_else(|| "Choose a file first".to_string())?;
    let password = Some(password).filter(|p| !p.is_empty());

    // The signer is resolved from the *secret* store: cert-d only holds the
    // public half, which cannot produce a signature.
    let signer = if sign {
        let (fingerprint, _) = guard
            .se_signers
            .get(signer_index.max(0) as usize)
            .ok_or_else(|| "Choose a key to sign with".to_string())?;
        // Local secret if we have it; otherwise the public certificate, which
        // is all the agent needs — it finds the secret by keygrip.
        Some(
            guard
                .store
                .secret_cert(fingerprint)
                .or_else(|_| guard.store.lookup(fingerprint))
                .map_err(|e| format!("Signing key unavailable: {e}"))?,
        )
    } else {
        None
    };

    if encrypt {
        let mut recipients = Vec::new();
        for entry in guard.se_recipients.iter().filter(|r| r.selected) {
            recipients.push(
                guard
                    .store
                    .lookup(&entry.fingerprint)
                    .map_err(|e| format!("Recipient {} unavailable: {e}", entry.label))?,
            );
        }
        let passwords: Vec<String> = if secret.is_empty() {
            Vec::new()
        } else {
            vec![secret.to_string()]
        };
        if recipients.is_empty() && passwords.is_empty() {
            return Err("Select a recipient, or set a password".to_string());
        }

        let output = ops::encrypted_name(&input);
        ops::encrypt_file(
            &recipients,
            &passwords,
            signer.as_ref().map(|cert| (cert, password)),
            &input,
            &output,
        )
        .map_err(|e| format!("Encryption failed: {e}"))?;
        Ok(output)
    } else {
        let signer = signer.ok_or_else(|| "Nothing to do: tick Encrypt or Sign".to_string())?;
        let output = ops::signature_name(&input);
        ops::sign_detached_file(&signer, password, &input, &output)
            .map_err(|e| format!("Signing failed: {e}"))?;
        Ok(output)
    }
}

fn push_sign_encrypt(ui: &AppWindow, state: &State) {
    let rows: Vec<RecipientRow> = state
        .se_recipients
        .iter()
        .map(|r| RecipientRow {
            fingerprint: r.fingerprint.clone().into(),
            label: r.label.clone().into(),
            sublabel: r.sublabel.clone().into(),
            initials: r.initials.clone().into(),
            tint_index: r.tint,
            selected: r.selected,
        })
        .collect();

    let signers: Vec<SharedString> = state
        .se_signers
        .iter()
        .map(|(_, label)| SharedString::from(label.as_str()))
        .collect();

    ui.set_se_selected_count(state.se_recipients.iter().filter(|r| r.selected).count() as i32);
    ui.set_se_recipients(ModelRc::new(VecModel::from(rows)));
    ui.set_se_signers(ModelRc::new(VecModel::from(signers)));

    match &state.se_input {
        Some(path) => {
            ui.set_se_input(path.display().to_string().into());
            ui.set_se_output_encrypt(ops::encrypted_name(path).display().to_string().into());
            ui.set_se_output_sign(ops::signature_name(path).display().to_string().into());
        }
        None => {
            ui.set_se_input(SharedString::new());
            ui.set_se_output_encrypt(SharedString::new());
            ui.set_se_output_sign(SharedString::new());
        }
    }
}

// ----------------------------------------------------------- decrypt / verify

fn wire_decrypt_verify(ui: &AppWindow, state: &Shared) {
    ui.on_open_decrypt_verify({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let ui = ui_weak.unwrap();
            let mut guard = state.lock().unwrap();
            guard.dv_input = None;
            guard.dv_data = None;
            guard.dv_kind = InputKind::NotOpenPgp;
            ui.set_dv_result(SharedString::new());
            ui.set_dv_tone(0);
            ui.set_dv_signatures(ModelRc::new(VecModel::from(Vec::<SignatureRow>::new())));
            push_decrypt_verify(&ui, &guard);
            ui.set_verify_open(true);
        }
    });

    ui.on_dv_pick_input({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let _ = slint::spawn_local(async move {
                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("Encrypted message or signature")
                    .add_filter("OpenPGP", &["asc", "pgp", "gpg", "sig", "signature"])
                    .add_filter("All files", &["*"])
                    .pick_file()
                    .await
                else {
                    return;
                };

                let path = file.path().to_path_buf();
                // Reading the head of the file decides whether the dialog has
                // to ask for the signed file as well.
                let kind = std::fs::read(&path)
                    .map(|bytes| ops::classify(&bytes))
                    .unwrap_or(InputKind::NotOpenPgp);

                let ui = ui_weak.unwrap();
                let mut guard = state.lock().unwrap();
                guard.dv_input = Some(path);
                guard.dv_kind = kind;
                ui.set_dv_result(SharedString::new());
                ui.set_dv_tone(0);
                push_decrypt_verify(&ui, &guard);
            });
        }
    });

    ui.on_dv_pick_data({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let _ = slint::spawn_local(async move {
                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("File the signature covers")
                    .pick_file()
                    .await
                else {
                    return;
                };
                let ui = ui_weak.unwrap();
                let mut guard = state.lock().unwrap();
                guard.dv_data = Some(file.path().to_path_buf());
                push_decrypt_verify(&ui, &guard);
            });
        }
    });

    ui.on_dv_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |password| {
            let ui = ui_weak.unwrap();
            ui.set_busy(true);
            ui.set_status("Working…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let password = password.to_string();
            std::thread::spawn(move || {
                let outcome = run_decrypt_verify(&state, &password);
                let _ = slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_busy(false);
                    match outcome {
                        Ok((summary, tone, result)) => {
                            let rows: Vec<SignatureRow> = result
                                .signatures
                                .iter()
                                .map(|s| SignatureRow {
                                    good: s.good,
                                    signer: s.signer.clone().into(),
                                    detail: s.detail.clone().into(),
                                })
                                .collect();
                            ui.set_dv_signatures(ModelRc::new(VecModel::from(rows)));
                            ui.set_dv_result(summary.clone().into());
                            ui.set_dv_tone(tone);
                            ui.set_status(summary.into());
                        }
                        Err(message) => {
                            ui.set_dv_signatures(ModelRc::new(VecModel::from(
                                Vec::<SignatureRow>::new(),
                            )));
                            ui.set_dv_result(message.clone().into());
                            ui.set_dv_tone(3);
                            ui.set_status(message.into());
                        }
                    }
                });
            });
        }
    });
}

/// The blocking half of Decrypt / Verify. Returns a summary line, a tone for
/// the result banner (1 good, 2 needs attention, 3 bad) and the signatures.
fn run_decrypt_verify(state: &Shared, password: &str) -> Result<(String, i32, VerifyResult), String> {
    let guard = state.lock().unwrap();

    let input = guard
        .dv_input
        .clone()
        .ok_or_else(|| "Choose a file first".to_string())?;

    if guard.dv_kind == InputKind::DetachedSignature {
        let data = guard
            .dv_data
            .clone()
            .ok_or_else(|| "Choose the file the signature covers".to_string())?;

        let result = ops::verify_detached_files(&guard.store, &input, &data)
            .map_err(|e| format!("Verification failed: {e}"))?;

        let summary = if result.signatures.is_empty() {
            ("The file contains no signature".to_string(), 2)
        } else if result.all_good() {
            ("Signature verified".to_string(), 1)
        } else {
            ("Signature is NOT valid".to_string(), 3)
        };
        return Ok((summary.0, summary.1, result));
    }

    let output = ops::decrypted_name(&input);
    let result = ops::decrypt_file(
        &guard.store,
        &input,
        Some(password).filter(|p| !p.is_empty()),
        &output,
    )
    .map_err(|e| format!("Decryption failed: {e}"))?;

    let written = format!("Decrypted to {}", output.display());
    let summary = if result.signatures.is_empty() {
        (format!("{written}. The message was not signed."), 2)
    } else if result.all_good() {
        (format!("{written}, signature verified"), 1)
    } else {
        (format!("{written}, but a signature is NOT valid"), 3)
    };
    Ok((summary.0, summary.1, result))
}

fn push_decrypt_verify(ui: &AppWindow, state: &State) {
    ui.set_dv_needs_data(state.dv_kind == InputKind::DetachedSignature);

    ui.set_dv_input(match &state.dv_input {
        Some(path) => path.display().to_string().into(),
        None => SharedString::new(),
    });
    ui.set_dv_data(match &state.dv_data {
        Some(path) => path.display().to_string().into(),
        None => SharedString::new(),
    });
    ui.set_dv_output(match &state.dv_input {
        Some(path) => ops::decrypted_name(path).display().to_string().into(),
        None => SharedString::new(),
    });
}

// ------------------------------------------------------------ certify / trust

fn wire_certify(ui: &AppWindow, state: &Shared) {
    ui.on_open_certify({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let ui = ui_weak.unwrap();
            let mut guard = state.lock().unwrap();

            let Some(target) = usize::try_from(ui.get_current_row())
                .ok()
                .and_then(|r| guard.shown.get(r))
                .cloned()
            else {
                return;
            };

            // Every user ID starts ticked: certifying a person usually means
            // certifying the identity you just checked, and they normally have
            // one. Unticking is cheaper than hunting for the right box.
            let user_ids: Vec<(String, bool)> = target
                .user_ids
                .iter()
                .map(|uid| (uid.clone(), true))
                .collect();

            let certifiers: Vec<(String, String)> = guard
                .all
                .iter()
                .filter(|c| c.can_certify && (c.has_secret || c.agent_backed))
                .map(|c| {
                    let label = match &c.card_serial {
                        Some(_) => format!("{} (smartcard)", c.primary_user_id),
                        None => c.primary_user_id.clone(),
                    };
                    (c.fingerprint.clone(), label)
                })
                .collect();

            guard.certify_target = Some(target.fingerprint.clone());
            guard.certify_user_ids = user_ids;
            guard.certify_certifiers = certifiers;

            ui.set_certify_target(target.primary_user_id.clone().into());
            push_certify(&ui, &guard);
            drop(guard);
            ui.set_certify_open(true);
        }
    });

    ui.on_certify_toggle_user_id({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |index| {
            let ui = ui_weak.unwrap();
            let mut guard = state.lock().unwrap();
            if let Some(entry) = usize::try_from(index)
                .ok()
                .and_then(|i| guard.certify_user_ids.get_mut(i))
            {
                entry.1 = !entry.1;
            }
            push_certify(&ui, &guard);
        }
    });

    ui.on_certify_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |certifier_index, publishable, introducer, confidence, password| {
            let ui = ui_weak.unwrap();
            ui.set_busy(true);
            ui.set_status("Certifying…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let password = password.to_string();
            std::thread::spawn(move || {
                let outcome = run_certify(
                    &state,
                    certifier_index,
                    publishable,
                    introducer,
                    confidence,
                    &password,
                );
                let _ = slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_busy(false);
                    match outcome {
                        Ok(count) => {
                            ui.set_certify_open(false);
                            reload(&ui, &state);
                            ui.set_status(
                                format!("Certified {count} user ID(s)").into(),
                            );
                        }
                        Err(message) => ui.set_status(message.into()),
                    }
                });
            });
        }
    });

    ui.on_toggle_trust_root({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let ui = ui_weak.unwrap();
            let fingerprint = ui.get_detail().fingerprint.to_string();
            if fingerprint.is_empty() {
                return;
            }

            let outcome = {
                let guard = state.lock().unwrap();
                let was_root = guard
                    .all
                    .iter()
                    .find(|c| c.fingerprint == fingerprint)
                    .is_some_and(|c| c.is_trust_root);
                guard.store.set_trust_root(&fingerprint, !was_root)
            };

            match outcome {
                Ok(()) => {
                    // Trust roots change what the whole graph authenticates,
                    // so this is a full recompute, not a row update.
                    reload(&ui, &state);
                    reselect(&ui, &state, &fingerprint);
                }
                Err(e) => ui.set_status(format!("Could not change trust root: {e}").into()),
            }
        }
    });
}

/// The blocking half of Certify, run on a worker thread.
fn run_certify(
    state: &Shared,
    certifier_index: i32,
    publishable: bool,
    introducer: bool,
    confidence: i32,
    password: &str,
) -> Result<usize, String> {
    let guard = state.lock().unwrap();

    let target = guard
        .certify_target
        .clone()
        .ok_or_else(|| "No certificate selected".to_string())?;
    let (certifier, _) = guard
        .certify_certifiers
        .get(certifier_index.max(0) as usize)
        .ok_or_else(|| "Choose a key to certify with".to_string())?;

    let user_ids: Vec<String> = guard
        .certify_user_ids
        .iter()
        .filter(|(_, selected)| *selected)
        .map(|(uid, _)| uid.clone())
        .collect();
    if user_ids.is_empty() {
        return Err("Select at least one user ID".to_string());
    }

    let mut request = CertifyRequest::new(certifier, target);
    request.user_ids = user_ids;
    request.exportable = publishable;
    request.depth = if introducer { 1 } else { 0 };
    request.amount = if confidence == 0 {
        certify::FULL
    } else {
        certify::PARTIAL
    };
    request.password = Some(password.to_string()).filter(|p| !p.is_empty());

    let count = request.user_ids.len();
    certify::certify(&guard.store, &request).map_err(|e| format!("Certification failed: {e}"))?;
    Ok(count)
}

fn push_certify(ui: &AppWindow, state: &State) {
    let rows: Vec<UserIdRow> = state
        .certify_user_ids
        .iter()
        .map(|(text, selected)| UserIdRow {
            text: text.clone().into(),
            selected: *selected,
        })
        .collect();

    let certifiers: Vec<SharedString> = state
        .certify_certifiers
        .iter()
        .map(|(_, label)| SharedString::from(label.as_str()))
        .collect();

    ui.set_certify_chosen(state.certify_user_ids.iter().filter(|(_, s)| *s).count() as i32);
    ui.set_certify_user_ids(ModelRc::new(VecModel::from(rows)));
    ui.set_certify_certifiers(ModelRc::new(VecModel::from(certifiers)));
}

/// Load and display the certifications on one certificate.
fn push_certifications(ui: &AppWindow, state: &State, summary: &CertSummary) {
    let certifications = match state.store.lookup(&summary.fingerprint) {
        Ok(cert) => certify::certifications(&state.store, &cert).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    // Offer to withdraw only what is actually still standing.
    let withdrawable = certifications
        .iter()
        .any(|c| c.by_me && !c.is_revocation)
        && !certifications
            .iter()
            .any(|c| c.by_me && c.is_revocation);

    let rows: Vec<CertificationRow> = certifications
        .iter()
        .map(|c| certification_row(c, summary.user_ids.len() > 1))
        .collect();

    ui.set_detail_certifications(ModelRc::new(VecModel::from(rows)));
    ui.set_can_withdraw(withdrawable);
    ui.set_has_revocation_cert(
        summary.has_secret && state.store.has_revocation(&summary.fingerprint),
    );
}

fn certification_row(certification: &Certification, show_user_id: bool) -> CertificationRow {
    let mut parts: Vec<String> = Vec::new();

    if show_user_id {
        parts.push(certification.user_id.clone());
    }
    if certification.is_revocation {
        parts.push("withdrawn".to_string());
    } else {
        parts.push(
            if certification.amount >= certify::FULL {
                "full"
            } else {
                "partial"
            }
            .to_string(),
        );
    }
    parts.push(
        if certification.exportable {
            "publishable"
        } else {
            "local"
        }
        .to_string(),
    );
    if certification.depth > 0 {
        parts.push(format!("introducer, depth {}", certification.depth));
    }
    if let Some(created) = certification.created {
        parts.push(format_time(Some(created)));
    }
    match certification.verified {
        Some(true) => {}
        Some(false) => parts.push("signature does not check out".to_string()),
        None => parts.push("certifier not in this store".to_string()),
    }

    CertificationRow {
        certifier: certification.certifier.clone().into(),
        user_id: certification.user_id.clone().into(),
        detail: parts.join(" · ").into(),
        good: certification.is_good(),
        by_me: certification.by_me,
        is_revocation: certification.is_revocation,
    }
}

/// Re-select the row for `fingerprint` after the list has been rebuilt.
fn reselect(ui: &AppWindow, state: &Shared, fingerprint: &str) {
    let guard = state.lock().unwrap();
    let Some(index) = guard
        .shown
        .iter()
        .position(|c| c.fingerprint == fingerprint)
    else {
        return;
    };

    let summary = guard.shown[index].clone();
    ui.set_current_row(index as i32);
    ui.set_detail(to_row(&summary));
    ui.set_has_selection(true);
    push_certifications(ui, &guard, &summary);
}

// --------------------------------------------------------------------- lookup

fn wire_lookup(ui: &AppWindow, state: &Shared) {
    ui.on_open_lookup({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let ui = ui_weak.unwrap();
            state.lock().unwrap().lookup_results.clear();
            ui.set_lookup_results(ModelRc::new(VecModel::from(Vec::<LookupRow>::new())));
            ui.set_lookup_status(SharedString::new());
            ui.set_lookup_searched(false);
            ui.set_lookup_open(true);
        }
    });

    ui.on_lookup_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |query| {
            let ui = ui_weak.unwrap();
            ui.set_busy(true);
            ui.set_lookup_status("Searching…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let query = query.to_string();
            std::thread::spawn(move || {
                // Off the UI thread: this is a network round trip that can sit
                // on a DNS timeout for seconds.
                let outcome = rgpg_core::keyserver::lookup(&query);
                let _ = slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_busy(false);
                    ui.set_lookup_searched(true);

                    match outcome {
                        Ok(found) => {
                            let mut guard = state.lock().unwrap();
                            let rows: Vec<LookupRow> = found
                                .iter()
                                .map(|f| {
                                    let summary = rgpg_core::CertSummary::from_cert(&f.cert);
                                    let (name, email) = split_user_id(&summary.primary_user_id);
                                    LookupRow {
                                        primary_user_id: summary.primary_user_id.clone().into(),
                                        fingerprint_pretty: summary.fingerprint_pretty().into(),
                                        source: f.source.as_str().into(),
                                        initials: initials(&name, &email, &summary.key_id).into(),
                                        tint_index: tint_index(&summary.fingerprint),
                                        already_known: guard
                                            .store
                                            .lookup(&summary.fingerprint)
                                            .is_ok(),
                                    }
                                })
                                .collect();
                            let count = rows.len();
                            guard.lookup_results = found;
                            drop(guard);

                            ui.set_lookup_results(ModelRc::new(VecModel::from(rows)));
                            ui.set_lookup_status(
                                if count == 0 {
                                    "Nothing found for that.".to_string()
                                } else {
                                    format!("{count} certificate(s) found. Check the fingerprint against the owner before trusting it.")
                                }
                                .into(),
                            );
                        }
                        Err(e) => {
                            ui.set_lookup_results(ModelRc::new(VecModel::from(
                                Vec::<LookupRow>::new(),
                            )));
                            ui.set_lookup_status(format!("Lookup failed: {e}").into());
                        }
                    }
                });
            });
        }
    });

    ui.on_lookup_import({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |index| {
            let ui = ui_weak.unwrap();
            let outcome = {
                let guard = state.lock().unwrap();
                match usize::try_from(index)
                    .ok()
                    .and_then(|i| guard.lookup_results.get(i))
                {
                    Some(found) => guard.store.insert(&found.cert).map(|()| {
                        rgpg_core::CertSummary::from_cert(&found.cert).primary_user_id
                    }),
                    None => return,
                }
            };

            match outcome {
                Ok(who) => {
                    reload(&ui, &state);
                    // Imported, not trusted: a fetched certificate is
                    // unauthenticated until somebody certifies it.
                    ui.set_lookup_status(
                        format!("Imported {who}. It is unverified until you certify it.").into(),
                    );
                    ui.set_status(format!("Imported {who} from the network").into());
                }
                Err(e) => ui.set_lookup_status(format!("Import failed: {e}").into()),
            }
        }
    });
}

// ------------------------------------------------------------------ lifecycle

fn wire_lifecycle(ui: &AppWindow, state: &Shared) {
    let open = |ui: &AppWindow, mode: i32, target: SharedString| {
        ui.set_lifecycle_mode(mode);
        ui.set_lifecycle_target(target);
        ui.set_lifecycle_open(true);
    };

    ui.on_open_expiry({
        let ui_weak = ui.as_weak();
        move || {
            let ui = ui_weak.unwrap();
            open(&ui, 0, SharedString::new());
        }
    });
    ui.on_open_publish({
        let ui_weak = ui.as_weak();
        move || {
            let ui = ui_weak.unwrap();
            open(&ui, 3, SharedString::new());
        }
    });
    ui.on_open_add_user_id({
        let ui_weak = ui.as_weak();
        move || {
            let ui = ui_weak.unwrap();
            open(&ui, 1, SharedString::new());
        }
    });
    ui.on_open_revoke_user_id({
        let ui_weak = ui.as_weak();
        move |user_id| {
            let ui = ui_weak.unwrap();
            open(&ui, 2, user_id);
        }
    });

    ui.on_lifecycle_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |mode, expiry, value, password| {
            let ui = ui_weak.unwrap();
            let fingerprint = ui.get_detail().fingerprint.to_string();
            let target = ui.get_lifecycle_target().to_string();
            ui.set_busy(true);
            ui.set_status("Working…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let (expiry, value, password) =
                (expiry.to_string(), value.to_string(), password.to_string());
            std::thread::spawn(move || {
                let outcome = run_lifecycle(
                    &state,
                    mode,
                    &fingerprint,
                    &target,
                    &expiry,
                    &value,
                    &password,
                );
                let _ = slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_busy(false);
                    match outcome {
                        Ok((message, fingerprint)) => {
                            ui.set_lifecycle_open(false);
                            reload(&ui, &state);
                            reselect(&ui, &state, &fingerprint);
                            ui.set_status(message.into());
                        }
                        Err(message) => ui.set_status(message.into()),
                    }
                });
            });
        }
    });
}

fn run_lifecycle(
    state: &Shared,
    mode: i32,
    fingerprint: &str,
    target: &str,
    expiry: &str,
    value: &str,
    password: &str,
) -> Result<(String, String), String> {
    let guard = state.lock().unwrap();
    let password = Some(password).filter(|p| !p.is_empty());

    match mode {
        0 => {
            let index: i32 = expiry.parse().unwrap_or(0);
            lifecycle::set_expiry(&guard.store, fingerprint, expiry_from_index(index), password)
                .map_err(|e| format!("Could not change the expiry: {e}"))?;
            Ok((
                match expiry_from_index(index) {
                    Some(_) => "Expiry updated. Publish the key again so others see it.",
                    None => "Expiry removed. Publish the key again so others see it.",
                }
                .to_string(),
                fingerprint.to_string(),
            ))
        }
        1 => {
            lifecycle::add_user_id(&guard.store, fingerprint, value, password)
                .map_err(|e| format!("Could not add the user ID: {e}"))?;
            Ok((
                "User ID added. Publish the key again so others see it.".to_string(),
                fingerprint.to_string(),
            ))
        }
        2 => {
            lifecycle::revoke_user_id(&guard.store, fingerprint, target, value, password)
                .map_err(|e| format!("Could not revoke the user ID: {e}"))?;
            Ok((
                "User ID revoked. Publish the key so others stop using it.".to_string(),
                fingerprint.to_string(),
            ))
        }
        _ => {
            // Publish. Only ever the public half — `keyserver::publish` strips
            // secret key material before it serialises anything.
            let cert = guard
                .store
                .lookup(fingerprint)
                .map_err(|e| format!("Certificate unavailable: {e}"))?;
            let published = rgpg_core::keyserver::publish(&cert)
                .map_err(|e| format!("Publishing failed: {e}"))?;

            let pending: Vec<String> = published
                .addresses
                .iter()
                .filter(|(_, state)| state != "published")
                .map(|(address, _)| address.clone())
                .collect();

            // Ask for the confirmation mails, since an unverified address is
            // stored but never served.
            let mut message = format!("Published {}", published.fingerprint);
            if let Some(token) = published.token.as_deref()
                && !pending.is_empty()
                && rgpg_core::keyserver::request_verification(token, &pending).is_ok()
            {
                message.push_str(&format!(
                    ". Confirmation mail sent to {}; the address is not served until it is confirmed.",
                    pending.join(", ")
                ));
            }
            Ok((message, fingerprint.to_string()))
        }
    }
}

// -------------------------------------------------------------------- notepad

fn wire_notepad(ui: &AppWindow, state: &Shared) {
    ui.on_open_details({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let ui = ui_weak.unwrap();
            let guard = state.lock().unwrap();
            let fingerprint = ui.get_detail().fingerprint.to_string();
            let Ok(cert) = guard.store.lookup(&fingerprint) else {
                return;
            };

            let user_ids: Vec<UserIdDetailRow> = rgpg_core::cert::user_ids(&cert)
                .iter()
                .map(|u| UserIdDetailRow {
                    text: u.text.clone().into(),
                    is_primary: u.is_primary,
                    revoked: u.revoked,
                    self_signed: format_time(u.self_signed).into(),
                })
                .collect();
            let subkeys: Vec<SubkeyRow> = rgpg_core::cert::subkeys(&cert)
                .iter()
                .map(|k| SubkeyRow {
                    fingerprint: k.fingerprint.clone().into(),
                    algorithm: k.algorithm.clone().into(),
                    created: format_time(Some(k.created)).into(),
                    expires: format_time(k.expires).into(),
                    capabilities: k.capabilities().into(),
                    revoked: k.revoked,
                    has_secret: k.has_secret,
                })
                .collect();

            ui.set_detail_user_ids(ModelRc::new(VecModel::from(user_ids)));
            ui.set_detail_subkeys(ModelRc::new(VecModel::from(subkeys)));
            drop(guard);
            ui.set_details_open(true);
        }
    });

    ui.on_open_notepad({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let ui = ui_weak.unwrap();
            // Shares the Sign / Encrypt models, so opening the notepad has to
            // fill them the same way.
            load_signing_targets(&ui, &state);
            ui.set_np_output(SharedString::new());
            ui.set_np_result(SharedString::new());
            ui.set_np_tone(0);
            ui.set_np_signatures(ModelRc::new(VecModel::from(Vec::<SignatureRow>::new())));
            ui.set_notepad_open(true);
        }
    });

    ui.on_np_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |action, text, signer_index, password| {
            let ui = ui_weak.unwrap();
            ui.set_busy(true);
            ui.set_status("Working…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let (text, password) = (text.to_string(), password.to_string());
            std::thread::spawn(move || {
                let outcome = run_notepad(&state, action, &text, signer_index, &password);
                let _ = slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_busy(false);
                    match outcome {
                        Ok((output, summary, tone, signatures)) => {
                            let rows: Vec<SignatureRow> = signatures
                                .iter()
                                .map(|s| SignatureRow {
                                    good: s.good,
                                    signer: s.signer.clone().into(),
                                    detail: s.detail.clone().into(),
                                })
                                .collect();
                            ui.set_np_signatures(ModelRc::new(VecModel::from(rows)));
                            ui.set_np_output(output.into());
                            ui.set_np_result(summary.clone().into());
                            ui.set_np_tone(tone);
                            ui.set_status(summary.into());
                        }
                        Err(message) => {
                            ui.set_np_result(message.clone().into());
                            ui.set_np_tone(3);
                            ui.set_status(message.into());
                        }
                    }
                });
            });
        }
    });
}

/// The blocking half of the notepad. Returns the output text, a summary line,
/// a tone for the banner, and any signatures found.
fn run_notepad(
    state: &Shared,
    action: i32,
    text: &str,
    signer_index: i32,
    password: &str,
) -> Result<(String, String, i32, Vec<rgpg_core::ops::SignatureReport>), String> {
    let guard = state.lock().unwrap();
    let password = Some(password).filter(|p| !p.is_empty());

    // Return types inferred: naming them would mean importing a Sequoia
    // type into the GUI, which this crate deliberately avoids.
    let signer = |guard: &State| {
        let (fingerprint, _) = guard
            .se_signers
            .get(signer_index.max(0) as usize)
            .ok_or_else(|| "Choose a key to sign with".to_string())?;
        guard
            .store
            .secret_cert(fingerprint)
            .or_else(|_| guard.store.lookup(fingerprint))
            .map_err(|e| format!("Signing key unavailable: {e}"))
    };

    let recipients = |guard: &State| {
        let mut out = Vec::new();
        for entry in guard.se_recipients.iter().filter(|r| r.selected) {
            out.push(
                guard
                    .store
                    .lookup(&entry.fingerprint)
                    .map_err(|e| format!("Recipient {} unavailable: {e}", entry.label))?,
            );
        }
        if out.is_empty() {
            return Err("Select at least one recipient".to_string());
        }
        Ok::<_, String>(out)
    };

    let mut output = Vec::new();
    match action {
        // Sign, as a detached signature over the text.
        0 => {
            let cert = signer(&guard)?;
            ops::sign_detached(&cert, password, text.as_bytes(), &mut output)
                .map_err(|e| format!("Signing failed: {e}"))?;
            Ok((string_of(output), "Signed".to_string(), 1, Vec::new()))
        }
        1 | 2 => {
            let certs = recipients(&guard)?;
            let signing = if action == 2 { Some(signer(&guard)?) } else { None };
            ops::encrypt(
                &certs,
                &[],
                signing.as_ref().map(|cert| (cert, password)),
                text.as_bytes(),
                &mut output,
            )
            .map_err(|e| format!("Encryption failed: {e}"))?;
            let what = if action == 2 { "Signed and encrypted" } else { "Encrypted" };
            Ok((string_of(output), what.to_string(), 1, Vec::new()))
        }
        // Decrypt, or verify if what was pasted is a bare signature.
        _ => {
            if ops::classify(text.as_bytes()) == InputKind::DetachedSignature {
                return Err(
                    "That is a detached signature; it needs the file it signs, so use \
                     Decrypt / Verify instead."
                        .to_string(),
                );
            }
            let result = ops::decrypt(&guard.store, text.as_bytes(), password, &mut output)
                .map_err(|e| format!("Decryption failed: {e}"))?;

            let (summary, tone) = if result.signatures.is_empty() {
                ("Decrypted. The message was not signed.".to_string(), 2)
            } else if result.all_good() {
                ("Decrypted, signature verified".to_string(), 1)
            } else {
                ("Decrypted, but a signature is NOT valid".to_string(), 3)
            };
            Ok((string_of(output), summary, tone, result.signatures))
        }
    }
}

/// Armored output is text; anything else is shown as a note rather than as
/// mojibake.
fn string_of(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|e| format!("<{} bytes of binary output>", e.as_bytes().len()))
}

/// Fill the shared recipient and signer models from the store.
fn load_signing_targets(ui: &AppWindow, state: &Shared) {
    let mut guard = state.lock().unwrap();
    let recipients: Vec<Recipient> = guard
        .all
        .iter()
        .filter(|c| c.can_encrypt)
        .map(|c| {
            let (name, email) = split_user_id(&c.primary_user_id);
            Recipient {
                selected: false,
                initials: initials(&name, &email, &c.key_id),
                tint: tint_index(&c.fingerprint),
                label: if name.is_empty() { c.primary_user_id.clone() } else { name },
                sublabel: if email.is_empty() { c.key_id.clone() } else { email },
                fingerprint: c.fingerprint.clone(),
            }
        })
        .collect();
    let signers: Vec<(String, String)> = guard
        .all
        .iter()
        .filter(|c| c.can_sign && (c.has_secret || c.agent_backed))
        .map(|c| {
            let label = match &c.card_serial {
                Some(_) => format!("{} (smartcard)", c.primary_user_id),
                None => c.primary_user_id.clone(),
            };
            (c.fingerprint.clone(), label)
        })
        .collect();
    guard.se_recipients = recipients;
    guard.se_signers = signers;
    push_sign_encrypt(ui, &guard);
}

// ----------------------------------------------------------------- revocation

fn wire_revoke(ui: &AppWindow, state: &Shared) {
    ui.on_open_revoke({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let ui = ui_weak.unwrap();
            open_revoke_dialog(&ui, &state, false);
        }
    });

    ui.on_open_withdraw({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let ui = ui_weak.unwrap();
            open_revoke_dialog(&ui, &state, true);
        }
    });

    ui.on_revoke_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |reason, message, password| {
            let ui = ui_weak.unwrap();
            ui.set_busy(true);
            ui.set_status("Revoking…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let (message, password) = (message.to_string(), password.to_string());
            std::thread::spawn(move || {
                let outcome = run_revoke(&state, reason, &message, &password);
                let _ = slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_busy(false);
                    match outcome {
                        Ok((fingerprint, message)) => {
                            ui.set_revoke_open(false);
                            reload(&ui, &state);
                            reselect(&ui, &state, &fingerprint);
                            ui.set_status(message.into());
                        }
                        Err(message) => ui.set_status(message.into()),
                    }
                });
            });
        }
    });

    ui.on_save_revocation_cert({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let _ = slint::spawn_local(async move {
                let (source, suggested) = {
                    let ui = ui_weak.unwrap();
                    let fingerprint = ui.get_detail().fingerprint.to_string();
                    let guard = state.lock().unwrap();
                    (
                        guard.store.revocation_path(&fingerprint),
                        format!("{}-revocation.asc", ui.get_detail().key_id),
                    )
                };

                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("Save revocation certificate")
                    .set_file_name(&suggested)
                    .save_file()
                    .await
                else {
                    return;
                };

                let ui = ui_weak.unwrap();
                ui.set_status(
                    match std::fs::copy(&source, file.path()) {
                        Ok(_) => format!(
                            "Saved to {}. Keep it somewhere you can reach without this key.",
                            file.path().display()
                        ),
                        Err(e) => format!("Could not save the revocation certificate: {e}"),
                    }
                    .into(),
                );
            });
        }
    });
}

fn open_revoke_dialog(ui: &AppWindow, state: &Shared, certification: bool) {
    let mut guard = state.lock().unwrap();

    let Some(target) = usize::try_from(ui.get_current_row())
        .ok()
        .and_then(|r| guard.shown.get(r))
        .cloned()
    else {
        return;
    };

    guard.revoke_target = Some(target.fingerprint.clone());
    guard.revoke_certification = certification;
    drop(guard);

    ui.set_revoke_target(target.primary_user_id.into());
    ui.set_revoke_is_certification(certification);
    ui.set_revoke_open(true);
}

/// The blocking half of revocation. Returns the affected fingerprint so the
/// list can re-select it, and the line to show in the status bar.
fn run_revoke(
    state: &Shared,
    reason: i32,
    message: &str,
    password: &str,
) -> Result<(String, String), String> {
    let guard = state.lock().unwrap();

    let target = guard
        .revoke_target
        .clone()
        .ok_or_else(|| "No certificate selected".to_string())?;
    let reason = Reason::from_index(reason);
    let password = Some(password).filter(|p| !p.is_empty());

    if guard.revoke_certification {
        // Withdrawing our own endorsement: the certifier is whichever of our
        // keys actually made a certification on this certificate.
        let cert = guard
            .store
            .lookup(&target)
            .map_err(|e| format!("Certificate unavailable: {e}"))?;
        let certifications = certify::certifications(&guard.store, &cert).unwrap_or_default();

        let mine: Vec<&Certification> = certifications
            .iter()
            .filter(|c| c.by_me && !c.is_revocation)
            .collect();
        let certifier = mine
            .first()
            .and_then(|c| c.certifier_fingerprint.clone())
            .ok_or_else(|| "You have not certified this key".to_string())?;
        let user_ids: Vec<String> = mine.iter().map(|c| c.user_id.clone()).collect();

        revoke::revoke_certification(
            &guard.store,
            &certifier,
            &target,
            &user_ids,
            reason,
            message,
            password,
        )
        .map_err(|e| format!("Could not withdraw the certification: {e}"))?;

        return Ok((
            target,
            "Certification withdrawn. It stops counting a second from now.".to_string(),
        ));
    }

    let mut request = RevokeRequest::new(&target);
    request.reason = reason;
    request.message = message.to_string();
    request.password = password.map(str::to_owned);

    revoke::revoke_cert(&guard.store, &request).map_err(|e| format!("Revocation failed: {e}"))?;
    Ok((
        target,
        "Key revoked. Publish or send the certificate so others stop using it.".to_string(),
    ))
}

// ------------------------------------------------------------------- plumbing

/// Re-read the store from disk and rebuild the list.
fn reload(ui: &AppWindow, state: &Shared) {
    let mut guard = state.lock().unwrap();

    let certs = match guard.store.certs() {
        Ok(certs) => certs,
        Err(e) => {
            ui.set_status(format!("Cannot read the certificate store: {e}").into());
            return;
        }
    };

    guard.all = certs.iter().map(CertSummary::from_cert).collect();

    // Authentication is a property of the whole graph, so it is computed once
    // for the store rather than per certificate. Trust roots are the explicit
    // list plus every key whose secret half is here.
    let roots: Vec<String> = guard
        .store
        .effective_roots()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let explicit_roots = guard.store.trust_roots().unwrap_or_default();
    let authenticated = wot::authenticate_all(&certs, &roots);
    // One round trip to gpg-agent for the whole store, not one per row.
    let agent_keys = rgpg_core::agent::annotate(&certs);

    // The secret half lives outside cert-d, so ask the store which ones it has.
    let State { store, all, .. } = &mut *guard;
    for summary in all.iter_mut() {
        let key = summary.fingerprint.to_uppercase();
        summary.has_secret = store.has_secret(&summary.fingerprint);
        summary.is_trust_root = explicit_roots.contains(&key);
        summary.authentication = authenticated.get(&key).copied().unwrap_or_default();
        if let Some(agent_key) = agent_keys.get(&summary.fingerprint) {
            summary.agent_backed = true;
            summary.card_serial = agent_key.card_serial.clone();
        }
    }

    // A stable order beats cert-d's, which is by fingerprint. Own keys first:
    // they are the ones a user reaches for.
    guard.all.sort_by(|a, b| {
        b.has_secret.cmp(&a.has_secret).then_with(|| {
            a.primary_user_id
                .to_lowercase()
                .cmp(&b.primary_user_id.to_lowercase())
        })
    });

    drop(guard);
    apply_filter(ui, state);
}

/// Rebuild `shown` and the list model from the current scope and search text.
fn apply_filter(ui: &AppWindow, state: &Shared) {
    let mut guard = state.lock().unwrap();

    let (filter, scope) = (guard.filter.clone(), guard.scope);
    guard.shown = guard
        .all
        .iter()
        .filter(|c| scope.accepts(c) && c.matches(&filter))
        .cloned()
        .collect();

    let rows: Vec<CertRow> = guard.shown.iter().map(to_row).collect();
    let total = guard.all.len();
    let mine = guard.all.iter().filter(|c| c.has_secret).count();
    let shown = rows.len();
    let can_certify = guard
        .all
        .iter()
        .any(|c| c.has_secret && c.can_certify);
    drop(guard);

    ui.set_certs(ModelRc::new(VecModel::from(rows)));
    ui.set_can_certify(can_certify);
    ui.set_count_all(total as i32);
    ui.set_count_mine(mine as i32);
    ui.set_count_others((total - mine) as i32);

    // The old row index is meaningless against a new row set.
    ui.set_current_row(-1);
    ui.set_has_selection(false);
    ui.set_status(
        if shown == total {
            format!("{total} certificate(s), {mine} with a secret key")
        } else {
            format!("{shown} of {total} certificate(s), {mine} with a secret key")
        }
        .into(),
    );
}

fn to_row(summary: &CertSummary) -> CertRow {
    let (name, email) = split_user_id(&summary.primary_user_id);
    CertRow {
        fingerprint: summary.fingerprint.clone().into(),
        fingerprint_pretty: summary.fingerprint_pretty().into(),
        key_id: summary.key_id.clone().into(),
        primary_user_id: summary.primary_user_id.clone().into(),
        initials: initials(&name, &email, &summary.key_id).into(),
        tint_index: tint_index(&summary.fingerprint),
        name: name.into(),
        email: email.into(),
        user_ids: summary.user_ids.join("\n").into(),
        algorithm: summary.algorithm.clone().into(),
        created: format_time(Some(summary.created)).into(),
        expires: format_time(summary.expires).into(),
        validity: summary.validity.as_str().into(),
        capabilities: summary.capabilities().into(),
        has_secret: summary.has_secret,
        authentication: summary.authentication.as_str().into(),
        is_trust_root: summary.is_trust_root,
        revocation: summary.revocation.clone().unwrap_or_default().into(),
        card_serial: summary.card_serial.clone().unwrap_or_default().into(),
    }
}

/// `Alice Smith <alice@example.org>` -> `("Alice Smith", "alice@example.org")`.
fn split_user_id(user_id: &str) -> (String, String) {
    match (user_id.find('<'), user_id.rfind('>')) {
        (Some(open), Some(close)) if close > open => (
            user_id[..open].trim().to_string(),
            user_id[open + 1..close].trim().to_string(),
        ),
        _ if user_id.contains('@') && !user_id.contains(' ') => {
            (String::new(), user_id.trim().to_string())
        }
        _ => (user_id.trim().to_string(), String::new()),
    }
}

/// Up to two letters for the monogram, falling back through name, e-mail and
/// key ID so a certificate with no user ID still gets a legible circle.
fn initials(name: &str, email: &str, key_id: &str) -> String {
    let from_name: String = name
        .split_whitespace()
        .filter_map(|word| word.chars().next())
        .take(2)
        .collect();
    if !from_name.is_empty() {
        return from_name.to_uppercase();
    }
    email
        .chars()
        .chain(key_id.chars())
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string())
}

/// Pick one of Theme.monograms from the fingerprint, so a certificate keeps its
/// colour between sessions. FNV-1a: short, stable, and not a hash that anything
/// depends on for security.
fn tint_index(fingerprint: &str) -> i32 {
    const PALETTE: u64 = 6;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in fingerprint.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash % PALETTE) as i32
}
