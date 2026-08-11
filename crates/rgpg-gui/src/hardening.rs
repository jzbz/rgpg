//! Making the process a poor target for memory inspection.
//!
//! Sequoia already does the difficult part: [`Protected`] memzeroes secret
//! buffers on drop, and both `Password` and unlocked secret key MPIs are held
//! AES-sealed in RAM, decrypted only for the span of one operation. That
//! sealing is aimed at *imperfect* readout — Spectre, Rowhammer, coldboot —
//! where a bitflip in the pre-key avalanches and leaves the attacker nothing.
//!
//! It is explicitly not aimed at a *perfect* read of the whole address space,
//! because the pre-key is a static sitting in that same address space. A core
//! file or a debugger attach hands over both halves at once. Those are what
//! this module closes.
//!
//! What it does not close: this is not a privilege boundary. Key material
//! still passes through this process, and root, or anything holding
//! `CAP_SYS_PTRACE`, can still read it. Treat it as defence in depth.
//!
//! [`Protected`]: sequoia_openpgp::crypto::mem::Protected

/// Set to any value to keep the process debuggable.
///
/// Without an escape hatch the first crash report becomes unanswerable: no
/// core, nothing for `coredumpctl`, and `gdb` refusing to attach.
const ALLOW_DEBUG: &str = "RGPG_ALLOW_DEBUG";

/// Refuse to dump core, and on Linux refuse to be attached to.
///
/// Best-effort throughout. Every one of these can fail under a sandbox or a
/// hardened kernel, and none of them failing is a reason not to start — the
/// alternative is an app that will not run rather than one that is slightly
/// easier to inspect.
pub fn harden() {
    if std::env::var_os(ALLOW_DEBUG).is_some() {
        eprintln!("rgpg: {ALLOW_DEBUG} is set: core dumps and debugger attach are permitted");
        return;
    }

    #[cfg(unix)]
    {
        // Belt and braces, and the only one of the two available on macOS.
        // On a systemd machine this is close to useless on its own, because
        // `kernel.core_pattern` pipes to systemd-coredump and a pipe target
        // ignores RLIMIT_CORE; PR_SET_DUMPABLE below is what actually stops
        // it there.
        let no_core = rustix::process::Rlimit { current: Some(0), maximum: Some(0) };
        if let Err(e) = rustix::process::setrlimit(rustix::process::Resource::Core, no_core) {
            eprintln!("rgpg: could not disable core dumps: {e}");
        }
    }

    // PR_SET_DUMPABLE also revokes same-user ptrace, so this covers both a
    // core file and someone attaching gdb to a running rgpg. There is no
    // portable equivalent: macOS has PT_DENY_ATTACH, which is bypassable and
    // breaks crash reporting, so the macOS answer is the hardened runtime at
    // signing time instead.
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        if let Err(e) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
            eprintln!("rgpg: could not make the process non-dumpable: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    /// The flag is what makes the difference, so assert on the kernel's view
    /// of it rather than on `harden` having been called.
    #[test]
    #[cfg(target_os = "linux")]
    fn harden_clears_the_dumpable_flag() {
        use rustix::process::{DumpableBehavior, dumpable_behavior};

        // Not `harden()`: this runs in the shared test process, and the test
        // binary should stay debuggable. Exercise the same call directly and
        // put it back.
        let before = dumpable_behavior().unwrap();
        rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable).unwrap();
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        rustix::process::set_dumpable_behavior(before).unwrap();
    }
}
