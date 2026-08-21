//! What one keystroke in the search box costs.
//!
//! `apply_filter` runs on every keystroke, on the Slint event loop, and it
//! builds a `CertRow` for every *matching* certificate — roughly thirty heap
//! strings each — although the ListView instantiates only the rows the window
//! can show. That is the claim behind the lazy-model proposal, and this is
//! what measures it: if row building dominates, a model that builds rows on
//! demand turns a cost that scales with the keyring into one that scales with
//! the window.
//!
//! Reported against a frame budget, because that is the unit that matters: a
//! keystroke slower than about 16ms is a visible stall, not a slow function.
//!
//! Same shape as `rpgp-core`'s bench, and criterion is absent for the same
//! reason — see the module docs there.
//!
//!     cargo bench -p rpgp-gui
//!     RPGP_BENCH_SIZES=200,1000,5000 cargo bench -p rpgp-gui

use std::time::{Duration, Instant};

use rpgp_core::CertSummary;
use rpgp_core::keygen::{KeyGenRequest, generate};
use rpgp_gui::{Scope, Sort, to_row, visible, visible_rows};

const FRAME: Duration = Duration::from_millis(16);

fn time<T>(samples: usize, mut f: impl FnMut() -> T) -> Duration {
    let _ = f();
    let mut runs: Vec<Duration> = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        std::hint::black_box(f());
        runs.push(start.elapsed());
    }
    runs.sort();
    runs[0]
}

fn report(label: &str, n: usize, d: Duration) {
    let frames = d.as_secs_f64() / FRAME.as_secs_f64();
    let flag = if frames >= 1.0 {
        "  <-- over a frame"
    } else {
        ""
    };
    println!(
        "  {label:<34} {:>9.2?}   {:>5.2} frames   {:>7.1} us/cert{flag}",
        d,
        frames,
        d.as_secs_f64() * 1e6 / n as f64
    );
}

/// `n` summaries, built once. Generating real certificates is slow and the
/// thing under test never touches key material — it reads the flattened
/// summary — so one generated certificate is reshaped into `n` distinct rows.
fn summaries(n: usize) -> Vec<CertSummary> {
    let cert = generate(&KeyGenRequest::new("Person <person@example.org>"))
        .unwrap()
        .cert;
    let base = CertSummary::from_cert(&cert);
    (0..n)
        .map(|i| {
            let mut c = base.clone();
            c.fingerprint = format!("{i:040X}");
            c.key_id = format!("{i:016X}");
            c.primary_user_id = format!("Person {i} <person{i}@example.org>");
            c.user_ids = vec![c.primary_user_id.clone()];
            c.has_secret = i % 500 == 0;
            c
        })
        .collect()
}

fn main() {
    let sizes: Vec<usize> = std::env::var("RPGP_BENCH_SIZES")
        .ok()
        .map(|s| s.split(',').filter_map(|n| n.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![200, 1000, 5000]);
    let samples: usize = std::env::var("RPGP_BENCH_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7);

    println!("rpgp keystroke benchmark — {samples} samples, best of; frame budget {FRAME:?}\n");

    for &n in &sizes {
        let all = summaries(n);
        println!("n = {n} certificates");

        // The worst case, and the common one: an empty box matches everything,
        // so every certificate becomes a row.
        report(
            "visible() — filter + sort only",
            n,
            time(samples, || visible(&all, "", Scope::All, Sort::MineFirst)),
        );
        report(
            "visible_rows() — a keystroke",
            n,
            time(samples, || {
                visible_rows(&all, "", Scope::All, Sort::MineFirst)
            }),
        );

        // What a lazy model would actually build: the rows on screen.
        let shown = visible(&all, "", Scope::All, Sort::MineFirst);
        let window: Vec<&CertSummary> = shown.iter().take(15).filter_map(|&i| all.get(i)).collect();
        report(
            "  15 rows (a full window)",
            15,
            time(samples, || {
                window.iter().map(|c| to_row(c)).collect::<Vec<_>>()
            }),
        );

        // A narrowing filter: fewer matches, so fewer rows to build.
        report(
            "typing \"person 1\" — narrowed",
            n,
            time(samples, || {
                visible_rows(&all, "person 1", Scope::All, Sort::MineFirst)
            }),
        );
        println!();
    }
}
