# rgpg

An OpenPGP certificate manager for Linux and macOS, in the spirit of KDE's
Kleopatra: a window that lists your certificates and lets you generate, import,
export, sign, encrypt, decrypt and verify without touching a command line.

Rust throughout, Slint for the GUI, Sequoia for the OpenPGP implementation. No
webview, no Qt, no C++, no `gpg` subprocess.

**Status: early, but end to end.** Generating, importing, exporting, signing,
encrypting, decrypting and verifying all work from the window. Everything under
[Not built yet](#not-built-yet) is missing.

## Layout

| Crate | Contents |
| --- | --- |
| `crates/rgpg-core` | Certificate store, key generation, encrypt/decrypt/sign/verify. No GUI types. |
| `crates/rgpg-gui` | Slint front end. Binary is `rgpg`. |

The GUI depends only on `rgpg-core`'s own types — no `sequoia_openpgp` type
reaches a Slint callback — so the OpenPGP layer stays replaceable.

Inside `crates/rgpg-gui/ui`:

| File | Contents |
| --- | --- |
| `theme.slint` | Colour, spacing and type tokens, plus the icon paths. |
| `widgets.slint` | Buttons, fields, pills, dialogs — the app's own controls. |
| `dialogs.slint` | New key pair, Sign / Encrypt, Decrypt / Verify. |
| `app-window.slint` | The shell that assembles them. |
| `types.slint` | Structs shared with Rust. |

## Look and feel

The app follows the system light/dark setting but not the system *widget style*.
Slint would otherwise give macOS `cupertino` controls and Linux `fluent` ones,
which reads as two different products; `build.rs` pins the style so the only
platform character left is the window frame, the UI font, and the scrollbars.

Everything else is drawn by the design system in `theme.slint` and
`widgets.slint`: buttons, text fields, checkboxes, the dropdown, pills, the
monogram avatars and the modal shell. Only `ListView` comes from std-widgets,
for its virtualised scrolling.

Icons are `Path` elements on a 24×24 grid rather than image assets or an icon
font, so they take the theme's colour directly and cannot go missing at runtime.

Two consequences worth knowing:

- Certificate colours are a hash of the fingerprint, so a key keeps its monogram
  tint between sessions and across light and dark.
- Long operations run on a worker thread and report back through the event loop,
  so generating an RSA-4096 key does not freeze the window.

## Build and run

```bash
source ~/.bashrc && cargo run -p rgpg-gui
```

```bash
source ~/.bashrc && cargo test --workspace
```

To look at the app with content in it, seed a throwaway store first. It writes
only inside the `XDG_DATA_HOME` you give it, never your real one:

```bash
source ~/.bashrc && XDG_DATA_HOME=/home/jz/zx/dev/artifacts/rgpg/demo-home cargo run -p rgpg-core --example seed-demo-store && XDG_DATA_HOME=/home/jz/zx/dev/artifacts/rgpg/demo-home cargo run -p rgpg-gui
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

The SQLite one is a deliberate choice to keep. Dropping it means dropping
`sequoia-cert-store` and driving `openpgp-cert-d` (already in the tree, pure
Rust) directly, which costs the lookup-by-e-mail and merge-strategy machinery —
both would have to be hand-rolled, and the merge rules for combining two
versions of the same certificate are exactly the kind of thing worth not
reimplementing. None of it is in the crypto path.

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

## Coming from GnuPG

rgpg does not read `~/.gnupg`, and nothing it does will disturb it. Migrating
means exporting from GnuPG and importing here:

```bash
gpg --export --armor > /tmp/rgpg-public.asc && gpg --export-secret-keys --armor > /tmp/rgpg-secret.asc
```

Import both with the Import button. Public certificates land in cert-d and
secret keys in the secrets directory; a file containing both is handled in one
pass.

Three caveats:

- **This copies secret key material.** The keys then exist twice, under two
  different protections: gpg-agent's, and rgpg's weaker on-disk one. Delete
  `/tmp/rgpg-secret.asc` afterwards, and understand that rgpg's copy is only as
  safe as the passphrase on it.
- **Smartcard keys cannot come across.** `--export-secret-keys` emits a stub for
  a key that lives on a YubiKey. Those need the gpg-agent route below.
- **Ownertrust does not come across.** rgpg has no trust model yet, so
  `--export-ownertrust` has nowhere to go.

Reading `~/.gnupg` in place is possible but not built:

- `pubring.kbx` is GnuPG's Keybox container, not an OpenPGP keyring, so
  `CertParser` cannot read it. `sequoia-ipc`'s `keybox` module can, which would
  make a read-only "GnuPG certificates" source a small piece of work.
- Secret keys under `private-keys-v1.d` are in gpg-agent's own S-expression
  format, not OpenPGP. The only sound way to use them is to ask gpg-agent, via
  `sequoia-keystore`'s gpg-agent backend — which would also solve smartcards and
  would mean rgpg never holds key material at all.
- A pre-2.1 `~/.gnupg/pubring.gpg` *is* a plain OpenPGP keyring and imports
  as-is today.

## Not built yet

Roughly in the order Kleopatra users would notice them missing:

- **Reading GnuPG's store directly** — see [Coming from GnuPG](#coming-from-gnupg).
- **Certificate details beyond the summary pane** — subkey list, per-user-ID
  signatures, certifications received.
- **Clipboard and inline text** operations; today every operation is on a file.
- **Column sorting.** The list sorts own-keys-first then by name, and the rail
  filters by scope, but there is no sort control.
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

rgpg's own source is MIT — see [LICENSE](LICENSE).

Two dependencies carry obligations that MIT does not, and both are worth
knowing about before the first release:

- **Slint** is tri-licensed: GPLv3, a royalty-free desktop/mobile licence, or a
  commercial licence. An MIT release of rgpg is not the GPLv3 option, so it
  relies on the royalty-free terms, which require attribution in the
  application. There is no attribution in the UI yet.
- **`sequoia-openpgp`** is LGPL-2.0-or-later and Rust links it statically.
  LGPL §6 asks that recipients be able to relink against a modified version of
  the library, which a statically linked binary does not offer on its own.

Neither is a blocker for source distribution; both need a decision before
shipping binaries.
