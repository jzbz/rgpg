# rgpg

An OpenPGP certificate manager for Linux and macOS, in the spirit of KDE's
Kleopatra: a window that lists your certificates and lets you generate, import,
export, sign, encrypt, decrypt and verify without touching a command line.

Rust throughout, Slint for the GUI, Sequoia for the OpenPGP implementation. No
webview, no Qt, no C++, no `gpg` subprocess.

**Status: scaffold.** The store, key generation and the four message operations
work and are covered by tests. The GUI lists, searches, imports, exports and
generates. Everything under [Not built yet](#not-built-yet) is missing.

## Layout

| Crate | Contents |
| --- | --- |
| `crates/rgpg-core` | Certificate store, key generation, encrypt/decrypt/sign/verify. No GUI types. |
| `crates/rgpg-gui` | Slint front end. Binary is `rgpg`. |

The GUI depends only on `rgpg-core`'s own types — no `sequoia_openpgp` type
reaches a Slint callback — so the OpenPGP layer stays replaceable.

## Build and run

```bash
source ~/.bashrc && cargo run -p rgpg-gui
```

```bash
source ~/.bashrc && cargo test --workspace
```

## Stack decisions

### GUI: Slint on winit, rendering through wgpu

`slint` is pulled in with `default-features = false`. Two of its defaults are
actively unwanted:

- **`backend-default`** compiles in the Qt backend whenever `qmake` is on the
  build machine's `PATH`, and Slint's runtime backend order is `qt`, `winit`,
  `linuxkms` — so a default build on a KDE developer's machine silently renders
  through Qt, and through winit everywhere else. Naming `backend-winit`
  explicitly makes the build reproducible and keeps C++ out.
- **`renderer-femtovg`** is FemtoVG over OpenGL. OpenGL is deprecated on macOS.
  `renderer-femtovg-wgpu` is the same renderer over wgpu — Vulkan on Linux,
  Metal on macOS — and is still pure Rust.

`renderer-software` stays enabled as an escape hatch for machines without a
usable GPU:

```bash
SLINT_BACKEND=winit-software cargo run -p rgpg-gui
```

`renderer-skia` is never enabled: it needs a C++ toolchain.

### OpenPGP: Sequoia with the RustCrypto backend

`sequoia-openpgp` defaults to Nettle (C). This build selects `crypto-rust`,
which requires two explicit opt-ins:

- `allow-experimental-crypto` — the RustCrypto backend is not one of Sequoia's
  "mature" backends.
- `allow-variable-time-crypto` — it does not guarantee constant-time operation
  for every algorithm.

Both are load-bearing warnings, not paperwork: this build is more exposed to
timing side channels than a Nettle or OpenSSL build would be. On a desktop
machine where an attacker is not co-resident that is an acceptable trade for a
single-language build; it would not be on a shared host.

`compression-bzip2` is also off, because it links C bzip2. The cost is that
BZip2-compressed messages — rare, and not produced by anything modern — cannot
be read.

### What is *not* pure Rust

Three C libraries survive in the dependency graph. Two are unavoidable on a
Linux desktop; one is a choice worth revisiting:

| Library | Via | Why |
| --- | --- | --- |
| `libsqlite3` | `sequoia-cert-store` → `rusqlite` | cert-d keeps a SQLite index next to the directory for lookup by e-mail and subkey. Not optional in that crate. |
| `fontconfig` | `i-slint-core` | System font discovery on Linux. |
| `libwayland` | `winit` | Loaded at runtime on a Wayland session. |

Dropping SQLite means dropping `sequoia-cert-store` and driving
`openpgp-cert-d` (already in the tree, pure Rust) directly, which costs the
lookup-by-e-mail and merge-strategy machinery — those would have to be
hand-rolled. The crypto path itself is unaffected either way.

## Where certificates live

Public certificates go in a [pgp-cert-d][certd] directory, the same layout `sq`
uses, so they are shared with other Sequoia tooling rather than locked in this
app:

    $XDG_DATA_HOME/pgp.cert.d          (override with RGPG_CERT_STORE)

Secret keys do **not** go there — cert-d is a store of public certificates, and
a transferable secret key in it would be readable by every tool that scans the
directory. They live in their own directory, one binary TSK per file:

    $XDG_DATA_HOME/rgpg/secrets/<fingerprint>.pgp

That secret store is scaffold-grade. Keys sit on disk protected only by their
own passphrase, and every operation that needs one loads it into the GUI
process. The intended replacement is `sequoia-keystore`, which holds key
material in a separate daemon — and which is also the only realistic route to
smartcard and YubiKey support.

[certd]: https://www.ietf.org/archive/id/draft-nwjw-openpgp-cert-d-02.html

## Not built yet

Roughly in the order Kleopatra users would notice them missing:

- **Sign / encrypt / decrypt / verify from the GUI.** `rgpg_core::ops` implements
  all four and they are tested, but no window calls them yet.
- **Certificate details beyond the summary pane** — subkey list, per-user-ID
  signatures, certifications received.
- **Certifying other people's keys**, setting ownertrust, and any web-of-trust
  display (`sequoia-wot`).
- **Revocation** — `keygen` produces a revocation certificate and currently
  throws it away. It cannot be regenerated without the secret key.
- **Keyserver and WKD lookup** — re-enable `sequoia-cert-store`'s `keyserver`
  feature, deliberately, with rustls rather than native-tls.
- **Smartcard / YubiKey** (`sequoia-keystore-openpgp-card`).
- **Deleting certificates**, editing expiry, adding and revoking user IDs.
- **Column sorting.** `StandardTableView` emits `sort-ascending`/`sort-descending`;
  nothing handles them.
- **Clipboard operations** and drag-and-drop import.

## Licence

`GPL-3.0-only`, which is the licence Slint's GPL option requires. Slint is
tri-licensed (GPLv3 / royalty-free / commercial); switching to the royalty-free
terms is possible but changes the attribution obligations. `sequoia-openpgp` is
LGPL-2.0-or-later.
