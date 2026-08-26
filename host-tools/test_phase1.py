# -*- coding: utf-8 -*-
"""
Phase 0/1 verification suite for the CH32X035 FIDO2 firmware.

Non-destructive checks exercising exactly the paths fixed in Phase 1:

  1. GetInfo                       -> document advertised capabilities
  2. GetAssertion up=false         -> pre-flight probe (old fw demanded touch -> 0x2F)
  3. GetAssertion empty allowList  -> old fw treated it as non-empty -> wrong result
  4. MakeCredential rk, no token   -> old fw: 0x33; new fw: 0x36 (PUAT_REQUIRED) if PIN set
  5. PING sanity

NOTE: on the OLD firmware tests #2/#3 stall ~15 s (touch wait) before answering.
Usage: python test_phase1.py
"""
import sys
import hashlib
import struct

from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from fido2.ctap import CtapError

# Workaround: python-fido2's Windows enumerator can hang querying serial strings
try:
    import fido2.hid.windows as whid
    whid.get_serial = lambda dev: "none"
except Exception:
    pass

RP_ID = "phase1-test.example"


# ------------------------- minimal CBOR encoder ------------------------------
def _head(major, val):
    if val < 24:
        return bytes([(major << 5) | val])
    elif val < 256:
        return bytes([(major << 5) | 24, val])
    elif val < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", val)
    return bytes([(major << 5) | 26]) + struct.pack(">I", val)


def enc(v):
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        # CBOR: major 0 = unsigned, major 1 = negative (-1-n)
        return _head(0, v) if v >= 0 else _head(1, -v - 1)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        out = _head(5, len(v))
        for k, val in v.items():
            out += enc(k) + enc(val)
        return out
    raise TypeError(type(v))


def errcode(e):
    try:
        return int(e.code)
    except Exception:
        try:
            return e.code.value
        except Exception:
            return -1


def raw_cbor(ctap2, cmd_id, payload):
    """Send raw CTAPHID_CBOR: first byte = CTAP2 command, rest = CBOR map."""
    return ctap2.device.call(0x10, bytes([cmd_id]) + enc(payload))


def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    return ok


def main():
    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print("No FIDO2 device found!")
        return 1
    ctap2 = Ctap2(dev)

    # ---- 1. GetInfo --------------------------------------------------------
    info = ctap2.get_info()
    print("\n=== GetInfo ===")
    print(f"  versions:            {info.versions}")
    print(f"  options:             {info.options}")
    print(f"  aaguid:              {info.aaguid}")
    print(f"  max_msg_size:        {info.max_msg_size}")
    print(f"  pin_uv_protocols:    {info.pin_uv_protocols}")

    # ---- 2. Pre-flight getAssertion (up=false), RP without credentials -----
    print(f"\n=== GetAssertion up=false, unknown RP ({RP_ID}) ===")
    print("  (OLD firmware stalls ~15 s here waiting for touch)")
    req = {
        0x01: RP_ID,
        0x02: hashlib.sha256(b"cdh").digest(),
        0x05: {"up": False},
    }
    try:
        resp = raw_cbor(ctap2, 0x02, req)
        st = resp[0]
        check("pre-flight answers instantly with 0x2E NO_CREDENTIALS",
              st == 0x2E, f"status=0x{st:02X}")
    except CtapError as e:
        check("pre-flight answers instantly with 0x2E", False,
              f"CtapError 0x{errcode(e):02X} (timeout here = up:false ignored)")

    # ---- 3. getAssertion with EMPTY allowList -------------------------------
    print("\n=== GetAssertion EMPTY allowList + up=false ===")
    req[0x03] = []
    try:
        resp = raw_cbor(ctap2, 0x02, req)
        st = resp[0]
        check("empty allowList treated like absent -> 0x2E",
              st == 0x2E, f"status=0x{st:02X}")
    except CtapError as e:
        check("empty allowList treated like absent -> 0x2E", False,
              f"CtapError 0x{errcode(e):02X}")

    # ---- 4. MakeCredential rk=true without token ----------------------------
    print("\n=== MakeCredential {'rk': True} without pinUvAuthParam ===")
    mc = {
        0x01: hashlib.sha256(b"cdh").digest(),
        0x02: {"id": RP_ID, "name": "Phase1 Test"},
        0x03: {"id": b"uid-phase1", "name": "phase1"},
        0x04: [{"type": "public-key", "alg": -7}],
        0x07: {"rk": True},
    }
    pin_set = bool(info.options.get("clientPin"))
    try:
        t0 = __import__("time").time()
        resp = raw_cbor(ctap2, 0x01, mc)
        st = resp[0]
        dt = __import__("time").time() - t0
        if pin_set:
            check("MC rk w/o token -> PUAT_REQUIRED", st == 0x36,
               f"status=0x{st:02X}")
        else:
            # No PIN set: per spec registration must PROCEED to touch ->
            # nobody touches -> USER_ACTION_TIMEOUT after ~15 s.
            check("MC rk w/o token (no PIN) waits for touch -> 0x2F",
               st == 0x2F and dt > 10, f"status=0x{st:02X} dt={dt:.1f}s")
    except CtapError as e:
        check("MC rk w/o token rejected", False, f"CtapError 0x{errcode(e):02X}")

    # ---- 5. PING ------------------------------------------------------------
    print("\n=== CTAPHID PING ===")
    try:
        echo = ctap2.device.ping(b"x" * 32)
        check("PING echo 32 bytes", echo == b"x" * 32)
    except Exception as e:
        check("PING echo 32 bytes", False, str(e))

    print("\nDone. Registration/login round-trip needs physical touch - run separately.")
    return 0


if __name__ == "__main__":
    sys.exit(main())


