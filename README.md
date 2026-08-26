# CH32X035 FIDO2 Passkey — an open-source USB security key

A working, from-scratch **FIDO2 / WebAuthn USB security key (passkey authenticator)**
built on the tiny, cheap **WCH CH32X035** RISC-V microcontroller.

Registration, login and passkey management are verified end-to-end with **GitHub**
(Chrome + Windows Hello) and exercise the full CTAP2 stack — including **both
PIN protocols**, **discoverable (resident) passkeys**, **multi-account per site**
and **CredentialManagement** with per-command token verification.

```
┌──────────────────────────────┐        ┌────────────────────────────────┐
│  Host (Chrome / Windows)     │  USB   │  CH32X035 (RISC-V @ 48 MHz)     │
│  WebAuthn → CTAP2            │ ─────► │  CTAPHID transport (USB HID)    │
│                              │        │  CTAP2.0 + subset CTAP2.1       │
│  • register passkey          │        │  P-256 ECDSA • SHA-256          │
│  • sign in with passkey      │        │  HMAC • AES-256-CBC • HKDF      │
│  • manage passkeys (CLI)     │ ◄───── │  Flash-backed resident store    │
└──────────────────────────────┘        │  Capacitive touch user presence │
                                        └────────────────────────────────┘
```

---

## Download prebuilt firmware

No toolchain required to try it — grab the latest prebuilt binaries from the
**[Releases](https://github.com/root643/unsolo-key/releases)** page:

- `firmware-main.bin` — raw binary, base address `0x08000000` (for `minichlink` / `wlink`)
- `firmware-main.hex` — Intel HEX (for WCH-ISPStudio / `wchisp`)

Each release lists SHA-256 checksums and step-by-step flashing instructions
(WCH-LinkE 3-wire SDI or USB-bootloader methods).

---

## Table of contents

- [Why](#why)
- [Features](#features)
- [How it works / architecture](#how-it-works--architecture)
- [Hardware](#hardware)
- [Build & flash](#build--flash)
- [Host tools](#host-tools)
- [Testing](#testing)
- [Comparison with other open-source projects](#comparison-with-other-open-source-projects)
- [Comparison with commercial security keys](#comparison-with-commercial-security-keys)
- [Security considerations](#security-considerations)
- [Limitations & roadmap](#limitations--roadmap)
- [Project layout](#project-layout)
- [License & credits](#license--credits)

---

## Why

Passkeys are the modern replacement for passwords, and a hardware security key is
the most phishing-resistant way to store them. Commercial keys cost 30–70 € and are
closed source. This project shows that a **fully open**, spec-compliant CTAP2
authenticator fits on a **~5 € development board**, and it was built as a learning
journey through the FIDO2/CTAP2 protocol from the register level up.

The firmware, transport, CBOR encoding, crypto integration and flash storage are all
hand-written C for the CH32X035 — no SDK bloat, no dynamic memory, no RTOS.

---

## Features

### Protocol
- **CTAPHID** over USB HID: INIT, PING, WINK, CANCEL, LOCK, CBOR; 64-byte reports,
  fragmentation for messages up to 1024 bytes.
- **CTAP2.0** plus a practical **CTAP2.1** subset:
  - `authenticatorGetInfo` (versions, aaguid, options incl. `rk`, `up`,
    `clientPin`, `pinUvAuthToken`, `credMgmt`, `makeCredUvNotRqd`, algorithms, transports)
  - `authenticatorMakeCredential` — discoverable (resident) and non-discoverable
    credentials, `excludeList` → `CREDENTIAL_EXCLUDED`, PIN-token user verification
  - `authenticatorGetAssertion` — bare-RP (passkey) and `allowList` flows,
    **pre-flight `up=false`** support (what Windows Hello uses to probe),
    `numberOfCredentials`
  - `authenticatorGetNextAssertion` — **multiple accounts per site**
  - `authenticatorClientPIN` — **protocol 1 and protocol 2** (HKDF),
    `getRetries`, `getKeyAgreement`, `setPIN`, `changePIN`, `getPinToken`,
    `getPinUvAuthTokenUsingPinWithPermissions` (with permissions field)
  - `authenticatorCredentialManagement` — metadata, enumerate RPs / credentials,
    delete; **pinAuth verified per sub-command** using the CTAP2.1 PRF
    (`HMAC(token, subCommand [|| params])`)
  - `authenticatorReset` — touch + power-on window
- Correct CTAP semantics that trip up many DIY keys: empty `allowList` ≡ absent,
  `up=false` must not demand a touch, CANCEL must not be answered directly,
  `PUAT_REQUIRED` vs `PIN_AUTH_INVALID` vs `PIN_NOT_SET`, etc.

### Cryptography
- **P-256 (secp256r1)** ECDSA signing and ECDH — [micro-ecc](https://github.com/kmackay/micro-ecc)
  (patched: only P-256 is compiled in, saving ~4 KB of flash).
- SHA-256, HMAC-SHA256, **AES-256-CBC** (kokke tiny-AES), **HKDF-SHA256** for
  PIN/UV auth protocol 2.
- Software RNG seeded with on-chip ADC noise + timer jitter.

### Storage
- 5 resident-key slots in flash (256 B each): RP ID hash, **RP name**, **64-byte
  user handle**, username, credential ID and private key.
- Re-registering the same account replaces its slot (no duplicates).
- Full chip erase on reset; `KEY_STORE_FULL` reported honestly.

### User experience
- Capacitive touch pad for user presence (re-calibrated per prompt, debounced,
  sustained-drop detection — no phantom touches).
- LED heartbeat on `PB12`.
- **Host CLI** (`host-tools/key_manager.py`) to list passkeys with **real site
  names**, delete passkeys, and change the PIN.

---

## How it works / architecture

```
USB OUT (EP1) / EP0 SET_REPORT
   │
   ▼
ProcessCTAPHID (main.c)          ← fragmentation, INIT/CID, CANCEL, PING/WINK
   │  (full CTAP2 message)
   ▼
fido2_process_cbor (fido2.c)     ← command dispatch (0x01..0x0D)
   ├── MakeCredential  ──► keygen (uECC) → attestation (packed/self) → flash save
   ├── GetAssertion    ──► credential lookup → sign authData‖clientDataHash → DER
   │                        (0x08 getNextAssertion walks the rest)
   ├── ClientPIN       ──► pin.c: ECDH → AES/HMAC/HKDF session → token issuance
   ├── CredMgmt        ──► flash enumeration + per-command pinAuth verification
   └── Reset           ──► full erase (touch + 10 s power-on window)
   │
   ▼
ctap_send_response (main.c)      ← 64-byte CTAPHID response frames + keepalives
```

Key design decisions:

- **Single-threaded, interrupt-driven USB.** Incoming reports land in a ring buffer;
  the main loop dispatches. During a touch wait, out-of-band CTAPHID commands
  (CANCEL / INIT / WINK) are still serviced.
- **No dynamic allocation** anywhere in the firmware.
- **Strict error-code discipline** — the response code the platform needs to drive
  the correct UI (`0x36 PUAT_REQUIRED`, `0x2D` vs `0x2F`, `0x30`…) is returned
  exactly where the spec demands it.
- **Robust CBOR parsing.** A proper map walker (`cbor_map_get_string`) is used for
  RP/user fields instead of byte greps, so requests from Chrome/Windows (with
  `excludeList`, `displayName`, etc.) parse correctly.

---

## Hardware

- **MCU:** WCH **CH32X035** (QingKe RISC-V4C, up to 48 MHz, 62 KB flash, 20 KB SRAM,
  native USB FS + PD).
- **Board:** [WeAct CH32X035 CoreBoard](https://github.com/WeActStudio/WeActStudio.CH32X035CoreBoard)
  (micro-USB, breakouts for PA/PB, BOOT button, touch pad on **PA2**).
- **Programmer (recommended):** WCH-LinkE — 3 wires: `SWDIO → DIO (PC18)`,
  `SWCLK → DCK (PC19)`, `GND → GND`. (CH32X035 debug is the **2-wire SDI**;
  the clock line is required.)

> ⚠️ The first time you use a WCH-LinkE on Windows you must bind **WinUSB** to the
> probe (interface 0, VID `1A86` PID `8010`) with [Zadig](https://zadig.akeo.ie) so
> `minichlink`/`wlink` can talk to it.

---

## Build & flash

Requirements: `riscv-none-elf-gcc` (≥ 12), GNU make, `minichlink`
(built from `ch32fun/minichlink`, or use `wlink`).

```bash
cd usb_hid_fido2
make build                                        # → main.bin
../ch32fun/minichlink/minichlink -w main.bin 0x08000000 -b   # flash + boot
```

Full workflow (no BOOT button, no UAC, no ISP studio):

```bash
make build
../ch32fun/minichlink/minichlink -w main.bin 0x08000000 -b
../ch32fun/minichlink/minichlink -r dump.bin 0x08000000 0xF000   # verify (optional)
```

- The device enumerates as **VID `1A86` : PID `FE07`**, product “FIDO2 Key”.
- If read-protection ever gets re-enabled, `minichlink -p` unlocks it (wipes flash).
- Alternative flasher: `wlink --chip ch32x035 flash main.bin`.

---

## Host tools

All host tools are plain Python 3 + `python-fido2`, `cbor2`, `cryptography`.
The default device PIN in the examples is `8565`.

```bash
# List passkeys stored on the key (real site names)
python host-tools/list_credentials.py

# Management CLI
python host-tools/key_manager.py list
python host-tools/key_manager.py delete github.com            # remove a site
python host-tools/key_manager.py delete github.com root643    # remove one account
python host-tools/key_manager.py change-pin 4321              # change the PIN

# Automated conformance/regression suite (no touch required)
python host-tools/validate_full.py                            # 27 checks, PIN 8565
```

### Registering a passkey on GitHub

1. GitHub → **Settings → Password and authentication → Passkeys → Add a passkey**.
2. In Chrome’s save dialog choose **USB security key** (not “This Windows device”).
3. Enter the key’s **PIN**, then **touch the pad** when prompted.
4. Done — you can now sign in with the passkey from the lock screen / login page.

> Note: Windows **Settings → Accounts → Passkeys** offers PIN change and reset for
> USB keys, but it does *not* list the passkeys stored on a USB key (that is a
> Windows limitation, not a firmware one). Use the CLI above for that.

---

## Testing

The project ships with two layers of verification:

- **Automated (no touch):** `host-tools/validate_full.py` — 27 checks covering the
  transport, GetInfo fields, CredentialManagement with/without token (including the
  CTAP2.1 pinAuth PRF), the full PIN **protocol-1 and protocol-2** lifecycles with
  real crypto (ECDH / AES / HMAC / HKDF), platform probes and more.
- **Interactive (touch):** `host-tools/test_rt_reg.py uid name` registers a user;
  `test_rt_assert.py` walks a multi-account RP (bare getAssertion →
  `getNextAssertion` → end-of-list), allowList-directed assertions and pre-flight.

Everything is verified against a real **GitHub** account: passkey registration and
login work in Chrome on Windows 11 (Windows Hello as the WebAuthn platform).

---

## Comparison with other open-source projects

| | **This project** | [SoloKeys Solo 1](https://github.com/solokeys/solo1) | [LionKey](https://github.com/pokusew/lionkey) | [pico-fido](https://github.com/pico-fido/pico-fido) | [OpenSK](https://github.com/google/opensk) |
|---|---|---|---|---|---|
| MCU | CH32X035 (RISC-V) | STM32L432 (Cortex-M4) | STM32H533 (Cortex-M33) | RP2040 (Cortex-M0+) | nRF52840 (Cortex-M4) |
| Board price (approx.) | ~5 € | ~25–50 € | NUCLEO board ~25 €+ | ~10 € | ~25–40 € |
| Language | C | C | C | C | Rust |
| CTAP2 | 2.0 + 2.1 subset | 2.0 (+2.1-preview) | 2.1 | 2.0/2.1 subset | 2.0/2.1 |
| PIN protocols | **1 and 2** | 1 | 1 and 2 | 1 | 1 and 2 |
| Resident (passkey) store | yes (5 slots) | yes | yes | yes | yes |
| CredentialManagement | yes (with PRF auth) | partial | yes | limited | limited |
| USB stack | hand-written CTAPHID | hand-written | TinyUSB | TinyUSB | custom (Tock) |
| Attestation | packed / self | self + others | self | self | self |

Strengths of this project: the lowest-cost full-CTAP2 path on a generic
microcontroller, both PIN protocols, and a strict-spec CTAP2.1 management surface —
while remaining fully open and hand-written.

---

## Comparison with commercial security keys

| | **This project** | YubiKey 5 | SoloKeys Solo | Nitrokey FIDO2 | Feitian / Token2 FIDO2 |
|---|---|---|---|---|---|
| Firmware | **open source** | closed | open | closed | closed |
| Secure element | none (MCU flash) | certified secure element | none | certified | certified (varies) |
| FIDO2 certification | none | FIDO2 / FIDO / U2F | FIDO2 / U2F | FIDO2 / U2F | FIDO2 / U2F |
| Protocols beyond FIDO2 | — | PIV, OATH, OpenPGP, HMAC-SHA1 | (custom applets) | (U2F/FIDO2) | OTP / other |
| Price | ~5 € (DIY) | 30–70 € | ~30 € | ~30–50 € | 10–50 € |
| Hardware TRNG | no (SW seeded) | yes | yes (nRF) | yes | yes |
| Physical button | capacitive pad | rated button | rated button | rated button | button |
| Attestation | self only | vendor/certified | self + vendor | self | vendor |

**Trade-offs, honestly:** a commercial key buys you a certified secure element,
certified attestation and platform certifications. This project trades those for
total openness, a ~10× lower price and a fully auditable CTAP2 implementation. If
you need it for production security, keep the private keys out of reach of a debug
probe (enable read-protection) and understand that the RNG is software-based.

---

## Security considerations

- **No secure element.** Private keys are stored in plaintext in the MCU flash.
  Anyone with SWD/debug access (and no read protection) can extract them.
  For a real deployment, enable read protection after flashing:
  `minichlink -P`.
- **Software RNG.** The TRNG-less CH32X035 uses an xorshift RNG mixed with ADC
  noise and timer jitter. Adequate for development and casual use; not a
  hardware-certified entropy source.
- **Self attestation only.** The AAGUID is a placeholder; no vendor attestation.
- **No certifications** (FIDO Alliance / CC).
- Capacitive-touch “button” is a convenience, not a tamper-rated switch.

---

## Limitations & roadmap

Currently not implemented (Chrome / Windows Hello flows do not need them):

- CTAP1/U2F (`MSG`) — intentionally disabled (`NMSG` capability).
- `hmac-secret`, `largeBlobs`, `authenticatorConfig`, `authenticatorSelection`,
  biometric enrollment.
- pinUvAuthToken **permission enforcement** (mc/ga/cm) — the token is issued with
  permissions but not yet gated per command (defence-in-depth item).
- Persistent `signCount`, on-flash key encryption, wear-leveling.
- 5-slot resident store (plenty for typical use).

Natural next steps: add `hmac-secret` (derive per-credential secrets from a master
secret stored in the PIN page), enforce token permissions, persist `signCount`, and
optionally port the transport to other CH32/CH55 boards.

---

## Project layout

```
├── usb_hid_fido2/        # Firmware (CTAPHID + CTAP2 + crypto + flash storage)
│   ├── main.c            # USB ring buffer, CTAPHID parser, response framing
│   ├── fido2.c           # CTAP2 command dispatch, MakeCredential/GetAssertion/…
│   ├── pin.c             # ClientPIN protocols 1 & 2 (ECDH/AES/HMAC/HKDF)
│   ├── flash_passkey.c   # resident-key + PIN-state flash store
│   ├── cbor.c            # minimal CBOR encoder/decoder helpers
│   ├── sha256.c, aes.c   # SHA-256, HMAC, AES-256-CBC
│   └── ch32x035_usbfs_device.c  # CH32X035 USBFS device driver
├── ch32fun/              # CH32X0xx framework + minichlink (MIT)
├── micro-ecc/            # P-256 ECDSA/ECDH (BSD-2), trimmed to P-256 only
└── host-tools/           # Python CLI: list/delete/change-pin + test suites
```

---

## License & credits

- The firmware and host tools are licensed under the **MIT License**
  (see [LICENSE](LICENSE)).
- `ch32fun` is © CNLohr / WCH / E. Brombaugh, **MIT** (see `ch32fun/LICENSE`).
- `micro-ecc` is © Kenneth MacKay, **BSD-2-Clause** (see `micro-ecc/LICENSE.txt`).
- CTAP2 / FIDO2 are specifications of the **FIDO Alliance**.
- Inspired by and interop-tested against [python-fido2](https://github.com/Yubico/python-fido2).

Built and verified on Windows 11 with GitHub + Chrome (Windows Hello as platform).
