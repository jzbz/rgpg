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
| `crates/rgpg-core` | Certificate store, key generation, encrypt/decrypt/sign/verify, certification and web-of-trust. No GUI types. |
| `crates/rgpg-gui` | Slint front end. Binary is `rgpg`. |

The GUI depends only on `rgpg-core`'s own types — no `sequoia_openpgp` type
reaches a Slint callback — so the OpenPGP layer stays replaceable.

Inside `crates/rgpg-gui/ui`:

| File | Contents |
| --- | --- |
| `theme.slint` | Colour, spacing and type tokens, plus the icon paths. |
| `widgets.slint` | Buttons, fields, pills, dialogs — the app's own controls. |
| `dialogs.slint` | New key pair, Sign / Encrypt, Decrypt / Verify, Certify, Revoke, Notepad. |
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

Icons are [Lucide](https://lucide.dev/) SVGs in `ui/icons`, vendored rather than
fetched, and recoloured through `Image`'s `colorize` so one file serves every
tone in both light and dark. They are 24×24 on a 2px round-cap stroke; the one
place an icon is drawn at 44px uses a thinned copy, because SVG scales the
stroke along with the shape. Lucide is ISC licensed and its notice is kept at
`ui/icons/LICENSE`.

`Icon` decides whether a button or pill has a glyph by asking the image for its
intrinsic width — a loaded SVG reports 24, an unset one reports 0 — so text-only
controls need no extra flag.

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

To screenshot the UI without a desktop — for reviewing a layout change, or from
a machine with no display — run it against Xvfb. The software renderer is
required here; see the adapter note under
[Stack decisions](#gui-slint-on-winit-rendering-through-wgpu):

```bash
Xvfb :99 -screen 0 1400x900x24 & sleep 2; DISPLAY=:99 SLINT_BACKEND=winit-software XDG_DATA_HOME=/home/jz/zx/dev/artifacts/rgpg/demo-home cargo run -p rgpg-gui & sleep 8; DISPLAY=:99 import -window root /home/jz/zx/dev/artifacts/rgpg/shot.png
```

Drop shadows and other GPU-only effects will not appear in that capture.

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

Setting it by hand should not be necessary. Left to itself, Slint decides
whether wgpu can work at window-creation time, and answers "no" with an
`expect` — so a machine without a usable GPU gets

    Failed to find an appropriate adapter: NotFound { .. incompatible_surface_backends: Backends(VULKAN) }

instead of a window. That is not a rare configuration: it is any display with
no presentable Vulkan surface, which covers plain X servers, a good number of
VMs, and remote sessions. `configure_renderer` and `restart_with_software_renderer`
in `main.rs` handle it in two stages, because one is not enough:

1. **Ask for wgpu explicitly, before any window exists.** `BackendSelector`'s
   `select()` probes for an adapter and *returns* failure rather than panicking,
   so the software renderer can be chosen cleanly. This catches every machine
   with no GPU adapter at all.
2. **Catch the panic and re-exec.** The probe asks for an adapter without a
   surface, so a driver that exists but cannot present still passes it and still
   fails later. A panic hook recognises that one message, and the process
   restarts itself with `SLINT_BACKEND=winit-software`. A fresh process rather
   than a retry in place: Slint's platform can only be set once. A guard
   variable stops it looping, and any *other* panic is re-raised untouched
   rather than being mistaken for a graphics fault.

The backend set is pinned to wgpu's `PRIMARY`. `WGPUSettings::default()` is
wider and includes the GL backend, which looks like a free extra fallback and
is not: on a display it cannot use, wgpu's GL backend **hangs** instead of
failing. A crash that restarts is recoverable; a window that never appears is
not. A GL-only machine therefore gets the software renderer.

Verified against five graphics configurations under Xvfb — working software
Vulkan, no Vulkan with GL present, no graphics stack at all, a real GPU ICD
that cannot present, and a mismatched ICD — plus a real Wayland desktop, which
still maps `libvulkan_radeon.so` and prints nothing.

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

## Certifying and trust

Two different questions get asked about a certificate, and rgpg shows both
because confusing them is how people end up trusting the wrong key:

- **Validity** — is the certificate internally sound? Self-signatures check
  out, not expired, not revoked. This is the `valid` / `expired` / `revoked`
  pill, and it says nothing about who the certificate belongs to.
- **Authentication** — does the name on it belong to the person you think? This
  is the `verified` / `partly verified` pill, computed by `sequoia-wot` from the
  certifications in the store. A perfectly valid certificate from a stranger is
  unauthenticated, and a key you confirmed years ago stays authenticated after
  it expires.

Certifying is done from a certificate's details pane. A certification always
names one *user ID* — OpenPGP has no way to vouch for a certificate as a whole
— so the dialog lists them and you tick the ones you actually checked. The
options map onto OpenPGP as follows:

| Dialog | What it writes |
| --- | --- |
| Confidence: Full / Partial | trust amount 120 / 60; anything but Full becomes a trust signature |
| Publishable | an exportable certification, shareable and included in exports |
| *(unticked)* | a local certification, never written out by `export_file` |
| Trusted introducer | a trust signature of depth 1: keys *they* certify count here too |

Trust roots are where authentication starts. Every key whose secret half is in
the store is a root automatically — the alternative is a fresh install where
nothing authenticates until the user finds a checkbox — and any other
certificate can be marked one by hand from its details pane.

The graph is rebuilt on every store reload rather than cached, which is fine
for the sizes tested and will need revisiting for a keyring of thousands.

## Revocation

Revocation is one-way and public: the signature becomes part of the certificate,
and anyone who already has a copy keeps it forever. Three separate things can be
retracted, and the UI keeps them apart:

- **Your own key**, from its details pane. Pick a reason and optionally leave a
  note. Choosing *secret key may be compromised* makes it a **hard** revocation,
  which also invalidates signatures the key made in the past — including every
  certification it ever issued, so anyone it had authenticated drops back to
  unverified.
- **A certification you made**, without touching the other person's key. Only
  your endorsement is withdrawn.
- **Someone else's key**, by importing the revocation certificate they
  published. The Import button takes it: a revocation is a bare signature rather
  than a certificate, so it falls through `CertParser` to `apply_revocation_file`.

A **revocation certificate** is now written at key generation, to
`$XDG_DATA_HOME/rgpg/revocations/<fingerprint>.rev`, and can be exported from
the details pane. It is the way back if the secret key or its passphrase is
lost: applying it needs neither, because it was signed while the key was in
hand. It cannot be recreated afterwards, which is why it is written once, at
the only moment the key is certainly available.

One timing wrinkle worth knowing. A revocation only supersedes a certification
made *strictly earlier*, and OpenPGP timestamps have one-second granularity, so
certifying and immediately changing your mind would otherwise leave the
certification standing. `revoke_certification` dates the revocation one second
past the certification it retracts — which means it takes effect a second
later, and the status bar says so.

## Smartcards and YubiKeys

Card keys are reached **through the user's `gpg-agent`**, not by talking to the
reader. That is not a preference, it is the only thing that works: `scdaemon`
holds the card with an exclusive PC/SC transaction, and a second process asking
the reader gets `SCARD_E_SHARING_VIOLATION` in both shared and exclusive mode.
It is why Kleopatra goes through gpg-agent too.

Two things fall out of that choice, both good:

- **rgpg never sees a PIN.** The agent runs the user's own `pinentry`, so the
  card PIN and any passphrase stay between the user and GnuPG.
- **No PC/SC dependency.** An earlier plan went through `sequoia-keystore`,
  whose gpg-agent backend uses its own home under `~/.sequoia` rather than the
  user's `~/.gnupg` — asked for real keys by fingerprint, it returns nothing.
  `sequoia-gpg-agent`, the layer beneath it, connects to the running agent
  directly.

**Building needs the Cap'n Proto compiler** (`capnp`). Not for the keystore,
which is gone, but for `sequoia-ipc`, which `sequoia-gpg-agent` sits on and
whose build script invokes it. Install `capnproto` before `cargo build`.

`rgpg_core::agent` enumerates what the agent holds and marks which keys are on
a card by their smartcard serial. Only connecting is async; the `KeyPair` it
returns implements Sequoia's `Signer` and `Decryptor` synchronously, so it
drops into the existing stream builders unchanged.

`ops::sign_detached` and `ops::encrypt` use it: local key material when the
certificate carries it, the agent otherwise. Sign / Encrypt lists card-backed
certificates as signers, labelled `(smartcard)`, and the list marks them with a
`smartcard` pill. Signing on a real YubiKey is covered by an `#[ignore]`d test —
ignored because it is interactive, since the agent may raise a PIN prompt:

```bash
RGPG_TEST_CERT=/path/to/cert.asc cargo test -p rgpg-core signs_through_the_agent -- --ignored --nocapture
```

`certify` takes the same fallback, so a card key can certify — verified on the
YubiKey.

**Decryption on a card does not work yet.** The plumbing is there and the key is
correctly identified: all three of the card's subkeys, encryption included,
match the agent's keys by keygrip and report the right smartcard serial. The
failure is in the PKESK decryption call itself, not in finding the key, and is
the agent rejecting it with `Inappropriate ioctl for device <Pinentry>` — no terminal or display to raise a PIN prompt on. Signing and certifying escape it only while their PIN is cached, so this is one bug, not three. Passing gpg's usual `OPTION ttyname=/display=` lines on connect is the obvious fix and does not work as written: a rejected OPTION leaves the Assuan connection returning nothing and key enumeration silently goes empty. Whatever lands here must check each OPTION's reply. The `#[ignore]`d test
`decrypts_and_certifies_through_the_agent` fails at that assertion on purpose,
so the gap is not forgotten.

`revoke` is still local-only.

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
  self-signatures.
- **Revoking a single user ID or subkey.** Revocation today is all-or-nothing
  on the certificate, plus withdrawing certifications.
- **Column sorting.** The list sorts own-keys-first then by name, and the rail
  filters by scope, but there is no sort control.
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
