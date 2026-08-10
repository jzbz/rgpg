// Hide the console window on Windows release builds. rgpg targets Linux and
// macOS today, but the attribute is free and keeps a cross-compile honest.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rgpg_core::cert::format_time;
use rgpg_core::keygen::{self, KeyGenRequest, KeyType};
use rgpg_core::{CertSummary, Store};
use slint::{ModelRc, SharedString, StandardListViewItem, VecModel};

slint::include_modules!();

/// Everything the callbacks share.
///
/// `all` is the store's contents; `shown` is what the table is displaying after
/// the search filter. The table's row index refers to `shown`, so the two must
/// only ever be rebuilt together — see [`reload`] and [`apply_filter`].
struct State {
    store: Store,
    all: Vec<CertSummary>,
    shown: Vec<CertSummary>,
    filter: String,
}

type Shared = Arc<Mutex<State>>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    }));

    reload(&ui, &state);

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

    ui.on_row_changed({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |row| {
            let ui = ui_weak.unwrap();
            let state = state.lock().unwrap();
            match usize::try_from(row).ok().and_then(|r| state.shown.get(r)) {
                Some(summary) => {
                    ui.set_detail(to_row(summary));
                    ui.set_has_selection(true);
                }
                None => ui.set_has_selection(false),
            }
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
                let outcome = state.lock().unwrap().store.import_file(file.path());
                match outcome {
                    Ok(certs) => {
                        reload(&ui, &state);
                        ui.set_status(format!("Imported {} certificate(s)", certs.len()).into());
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
                        state.lock().unwrap().store.insert_secret(&key.cert)?;
                        Ok(key.cert.fingerprint().to_hex())
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

    ui.run()?;
    Ok(())
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

/// Re-read the store from disk and rebuild the table.
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
    // A stable order beats cert-d's directory order, which is by fingerprint.
    guard
        .all
        .sort_by(|a, b| a.primary_user_id.to_lowercase().cmp(&b.primary_user_id.to_lowercase()));

    // The secret half lives outside cert-d, so ask the store which ones it has.
    let State { store, all, .. } = &mut *guard;
    for summary in all.iter_mut() {
        summary.has_secret = store.has_secret(&summary.fingerprint);
    }

    drop(guard);
    apply_filter(ui, state);
}

/// Rebuild `shown` and the table model from the current filter.
fn apply_filter(ui: &AppWindow, state: &Shared) {
    let mut guard = state.lock().unwrap();

    let filter = guard.filter.clone();
    guard.shown = guard
        .all
        .iter()
        .filter(|c| c.matches(&filter))
        .cloned()
        .collect();

    let rows: Vec<ModelRc<StandardListViewItem>> = guard
        .shown
        .iter()
        .map(|c| {
            let (name, email) = split_user_id(&c.primary_user_id);
            let cells: Vec<StandardListViewItem> = [
                name,
                email,
                format_time(Some(c.created)),
                format_time(c.expires),
                c.key_id.clone(),
                c.algorithm.clone(),
                c.capabilities(),
                if c.has_secret { "yes".into() } else { String::new() },
            ]
            .into_iter()
            .map(|text| StandardListViewItem::from(SharedString::from(text)))
            .collect();
            ModelRc::new(VecModel::from(cells))
        })
        .collect();

    let total = guard.all.len();
    let shown = guard.shown.len();
    let secret = guard.all.iter().filter(|c| c.has_secret).count();
    drop(guard);

    let model = VecModel::from(rows);
    ui.set_rows(ModelRc::new(model));

    // The old selection index is meaningless against a new row set.
    ui.set_current_row(-1);
    ui.set_has_selection(false);
    ui.set_status(
        if shown == total {
            format!("{total} certificate(s), {secret} with a secret key")
        } else {
            format!("{shown} of {total} certificate(s), {secret} with a secret key")
        }
        .into(),
    );
}

/// `Alice <alice@example.org>` -> `("Alice", "alice@example.org")`.
fn split_user_id(user_id: &str) -> (String, String) {
    match (user_id.find('<'), user_id.rfind('>')) {
        (Some(open), Some(close)) if close > open => (
            user_id[..open].trim().to_string(),
            user_id[open + 1..close].trim().to_string(),
        ),
        _ => (user_id.to_string(), String::new()),
    }
}

fn to_row(summary: &CertSummary) -> CertRow {
    CertRow {
        fingerprint: summary.fingerprint.clone().into(),
        fingerprint_pretty: summary.fingerprint_pretty().into(),
        key_id: summary.key_id.clone().into(),
        primary_user_id: summary.primary_user_id.clone().into(),
        user_ids: summary.user_ids.join("\n").into(),
        algorithm: summary.algorithm.clone().into(),
        created: format_time(Some(summary.created)).into(),
        expires: format_time(summary.expires).into(),
        validity: summary.validity.as_str().into(),
        capabilities: summary.capabilities().into(),
        has_secret: summary.has_secret,
    }
}
