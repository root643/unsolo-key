# Host tools (Python)

Plain Python 3 scripts. Dependencies: `python-fido2`, `cbor2`, `cryptography`.

```bash
pip install fido2 cbor2 cryptography
```

On Windows, FIDO HID devices are restricted to elevated processes by the OS
(Windows applies a restrictive security descriptor to the FIDO usage page), so
**run these from an elevated shell** (or use `run_validation.bat`).

Default device PIN in the scripts: `8565`.

| Script | Purpose |
|---|---|
| `list_credentials.py` | List stored passkeys with real site names |
| `key_manager.py` | `list` / `delete <site> [user]` / `change-pin <new>` |
| `validate_full.py` | 27-check automated conformance suite (no touch) |
| `test_phase1.py` | Quick smoke test |
| `test_rt_reg.py` / `test_rt_assert.py` / `test_roundtrip.py` | Interactive touch tests (registration, multi-account getAssertion + getNextAssertion) |
| `test_pin_flow.py` / `test_setpin.py` / `test_probe.py` | PIN lifecycle and platform-probe tests |

Quick start:

```bash
python list_credentials.py
python key_manager.py list
python key_manager.py change-pin 4321
```
