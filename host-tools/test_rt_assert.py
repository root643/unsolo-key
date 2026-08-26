# -*- coding: utf-8 -*-
"""GetAssertion tests on roundtrip.example: bare [touch], allowList [touch], preflight [no touch]."""
import sys, time, hashlib
sys.path.insert(0, r"C:\Users\Usuario\Downloads\solokey\fido2")
from test_phase1 import enc
from validate_full import raw_cbor, pin_session, hmac_sha256, aes_cbc_dec, sha256, aes_cbc
from fido2.hid import CtapHidDevice

try:
    import fido2.hid.windows as whid
    whid.get_serial = lambda dev: "none"
except Exception:
    pass

import cbor2

RP = "roundtrip.example"
PIN = "8565"


def raw(device, cmd_id, payload):
    return device.call(0x10, bytes([cmd_id]) + enc(payload))


def get_cm_token(dev):
    """PIN token (proto2, perms cm) for CredentialManagement calls."""
    sess = pin_session(dev, 2)
    iv = __import__("os").urandom(16)
    phe = iv + aes_cbc(sess["aes"], sha256(PIN.encode())[:16], iv)
    st, resp = raw_cbor(dev, 0x06, {1: 2, 2: 9, 3: sess["plat"], 6: phe, 9: 0x04})
    if st != 0:
        return None
    e = bytes(resp[2])
    return aes_cbc_dec(sess["aes"], e[16:], e[:16])


def ok(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    return bool(cond)


def main():
    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print("no device"); return 1

    # Enumerate stored creds of this RP via CredentialManagement
    # (PIN puesto -> requiere token + pinAuth con PRF 0x04||params)
    rph = hashlib.sha256(RP.encode()).digest()
    token = get_cm_token(dev)
    if token is None:
        print("no se pudo obtener token CM"); return 1
    params = {1: rph}
    pa = hmac_sha256(token, bytes([0x04]) + cbor2.dumps(params))[:32]
    re_ = raw(dev, 0x0A, {1: 0x04, 2: params, 3: 2, 4: pa})
    if re_[0] != 0x00:
        print(f"enumerate failed: 0x{re_[0]:02X}"); return 1
    en = cbor2.loads(bytes(re_[1:]))
    total = en.get(3)
    cred_desc = en.get(2)
    cred_alice = cred_desc["id"]
    print(f"total={total} first_cred={cred_alice.hex()[:16]}...")
    ok("enumerateCredentials returns descriptor", cred_desc.get("type") == "public-key")

    # STEP A: bare-RP assertion (touch)
    print("\n=== GetAssertion bare RP - TOCA ===")
    t0 = time.time()
    g1 = raw(dev, 0x02, {0x01: RP, 0x02: hashlib.sha256(b"login1").digest()})
    st = g1[0]
    print(f"  ({time.time()-t0:.1f}s)")
    if not ok("bare RP assertion", st == 0x00, f"status=0x{st:02X}"):
        return 1
    ass = cbor2.loads(bytes(g1[1:]))
    got = ass[1]["id"]
    flags_bare = ass[2][32]
    ok("UP flag set", bool(flags_bare & 0x01), f"flags=0x{flags_bare:02X}")
    ok("user entity present", isinstance(ass.get(4), dict) and "id" in ass[4],
       f"user={ass.get(4)}")
    print(f"  got: {got.hex()[:16]}...")

    # STEP A2: getNextAssertion walk (alice+bob = 2 creds -> key 6 + one 0x08)
    if ass.get(6, 0) > 1:
        ok("numberOfCredentials=2 anunciado", ass[6] == 2, f"n={ass[6]}")
        print("\n=== GetNextAssertion (0x08) - TOCA ===")
        g8 = dev.call(0x10, bytes([0x08]))
        st = g8[0]
        if not ok("getNextAssertion status OK", st == 0x00, f"status=0x{st:02X}"):
            return 1
        ass8 = cbor2.loads(bytes(g8[1:]))
        ok("0x08 devuelve la OTRA credencial", ass8[1]["id"] != got,
           f"got {ass8[1]['id'].hex()[:16]}")
        ok("0x08 incluye numberOfCredentials", ass8.get(6) == 2)
        g8b = dev.call(0x10, bytes([0x08]))
        ok("0x08 extra -> 0x2E (fin de lista)", g8b[0] == 0x2E, f"st={g8b[0]}")
    else:
        ok("numberOfCredentials (solo 1 cred, key 6 ausente)", 6 not in ass)

    # STEP B: allowList with the enumerated credential (touch)
    print("\n=== GetAssertion allowList=[enumerada] - TOCA ===")
    t0 = time.time()
    g2 = raw(dev, 0x02, {
        0x01: RP,
        0x02: hashlib.sha256(b"login2").digest(),
        0x03: [{"type": "public-key", "id": cred_alice}],
    })
    st = g2[0]
    print(f"  ({time.time()-t0:.1f}s)")
    if not ok("allowList assertion", st == 0x00, f"status=0x{st:02X}"):
        return 1
    ass2 = cbor2.loads(bytes(g2[1:]))
    ok("returned exactly the requested credential", ass2[1]["id"] == cred_alice)

    # STEP C: preflight up=false (NO touch; signing takes ~3.4s so no 15s stall = proof)
    print("\n=== Pre-flight up=false (sin touch) ===")
    t0 = time.time()
    g3 = raw(dev, 0x02, {
        0x01: RP,
        0x02: hashlib.sha256(b"preflight").digest(),
        0x05: {"up": False},
    })
    dt = time.time() - t0
    st = g3[0]
    ok("pre-flight sin touch (sin stall de 15s)", st == 0x00 and dt < 8.0,
       f"status=0x{st:02X} dt={dt:.2f}s")
    if st == 0x00:
        ass3 = cbor2.loads(bytes(g3[1:]))
        f = ass3[2][32]
        ok("pre-flight UP=0", not (f & 0x01), f"flags=0x{f:02X}")

    print("\nHecho.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

