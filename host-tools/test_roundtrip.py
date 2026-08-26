# -*- coding: utf-8 -*-
"""
Round-trip end-to-end test: needs PHYSICAL TOUCH.

Sequence (each touch-wait lasts up to 15 s):
  1. MakeCredential user A (rk)          -> TOUCH
  2. MakeCredential user B (same RP, rk) -> TOUCH   (multi-slot test)
  3. CredentialManagement metadata       -> no touch (existing=2, max=10)
  4. GetAssertion bare RP                -> TOUCH   (returns some credential)
  5. GetAssertion allowList=[credA]      -> TOUCH   (returns exactly credA)
  6. GetAssertion pre-flight up=false    -> NO TOUCH (instant, up flag must be 0)
Prints PASS/FAIL per step.
"""
import sys, time, hashlib
sys.path.insert(0, r"C:\Users\Usuario\Downloads\solokey\fido2")
from test_phase1 import enc
from fido2.hid import CtapHidDevice

try:
    import fido2.hid.windows as whid
    whid.get_serial = lambda dev: "none"
except Exception:
    pass

import cbor2

RP = "roundtrip.example"


def raw(device, cmd_id, payload):
    return device.call(0x10, bytes([cmd_id]) + enc(payload))


def ok(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    return bool(cond)


def main():
    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print("no device"); return 1
    cdh = hashlib.sha256(b"rt-cdh").digest()

    # Pre-existing keys may exist from earlier experiments; measure baseline
    def get_meta():
        rm = raw(dev, 0x0A, {0x01: 0x01})
        if rm[0] == 0x00:
            m = cbor2.loads(bytes(rm[1:]))
            return m.get(1), m.get(2)
        return None, None

    m_existing_0, _ = get_meta()
    print(f"(passkeys ya almacenadas antes del test: {m_existing_0})")


    def mc_req(uid, uname):
        return {
            0x01: cdh,
            0x02: {"id": RP, "name": "Roundtrip RP"},
            0x03: {"id": uid, "name": uname},
            0x04: [{"type": "public-key", "alg": -7}],
            0x07: {"rk": True},
        }

    print("=== STEP 1: MakeCredential user A - TOCA LA PLACA ===")
    t0 = time.time()
    r1 = raw(dev, 0x01, mc_req(b"uid-alice", "alice"))
    print(f"  ({time.time()-t0:.1f}s)")
    st = r1[0]
    if not ok("register alice", st == 0x00, f"status=0x{st:02X}"):
        return 1
    att = cbor2.loads(bytes(r1[1:]))
    authdata = att[2]
    aaguid = authdata[37:53]
    cred_id_a = authdata[55:55 + 32]
    print(f"  alice credId: {cred_id_a.hex()[:16]}...")

    print("=== STEP 2: MakeCredential user B - TOCA LA PLACA OTRA VEZ ===")
    t0 = time.time()
    r2 = raw(dev, 0x01, mc_req(b"uid-bob", "bob"))
    print(f"  ({time.time()-t0:.1f}s)")
    st = r2[0]
    if not ok("register bob", st == 0x00, f"status=0x{st:02X}"):
        return 1
    att2 = cbor2.loads(bytes(r2[1:]))
    cred_id_b = att2[2][55:55 + 32]
    ok("distinct credential ids", cred_id_a != cred_id_b)

    print("=== STEP 3: CredentialManagement metadata (sin touch) ===")
    rm = raw(dev, 0x0A, {0x01: 0x01})
    st = rm[0]
    meta_ok = False
    if st == 0x00:
        m = cbor2.loads(bytes(rm[1:]))
        existing, maximum = m.get(1), m.get(2)
        print(f"  existing={existing} max={maximum}")
        # Same RP+user re-registration REPLACES the slot (by design), so the
        # count must NOT grow on repeated runs of this test.
        meta_ok = (m_existing_0 is not None and existing == m_existing_0 and maximum == 10)
        ok(f"metadata: replace-same-user keeps existing={m_existing_0}, max=10", meta_ok)
    else:
        ok("metadata status OK", False, f"status=0x{st:02X}")

    print("=== STEP 4: GetAssertion bare RP - TOCA LA PLACA ===")
    t0 = time.time()
    g1 = raw(dev, 0x02, {
        0x01: RP,
        0x02: hashlib.sha256(b"login1").digest(),
    })
    print(f"  ({time.time()-t0:.1f}s)")
    st = g1[0]
    if not ok("getAssertion bare RP", st == 0x00, f"status=0x{st:02X}"):
        return 1
    ass = cbor2.loads(bytes(g1[1:]))
    got_id = ass[1]["id"]
    got_user = ass.get(4, {})
    flags_bare = ass[2][32]
    ok("assertion has user entity", 4 in ass)
    ok("bare-RP flags UP=1", bool(flags_bare & 0x01), f"flags=0x{flags_bare:02X}")
    print(f"  got cred: {got_id.hex()[:16]}... user={got_user}")

    print("=== STEP 5: GetAssertion allowList=[alice] - TOCA LA PLACA ===")
    g2 = raw(dev, 0x02, {
        0x01: RP,
        0x02: hashlib.sha256(b"login2").digest(),
        0x03: [{"type": "public-key", "id": cred_id_a}],
    })
    st = g2[0]
    if not ok("getAssertion allowList alice", st == 0x00, f"status=0x{st:02X}"):
        return 1
    ass2 = cbor2.loads(bytes(g2[1:]))
    ok("allowList returned alice's credential", ass2[1]["id"] == cred_id_a,
       f"got {ass2[1]['id'].hex()[:16]}")

    print("=== STEP 6: Pre-flight up=false (SIN touch, debe ser instantaneo) ===")
    t0 = time.time()
    g3 = raw(dev, 0x02, {
        0x01: RP,
        0x02: hashlib.sha256(b"preflight").digest(),
        0x05: {"up": False},
    })
    dt = time.time() - t0
    st = g3[0]
    ok("pre-flight returns credential without touch", st == 0x00 and dt < 8.0,
       f"status=0x{st:02X} dt={dt:.2f}s")
    if st == 0x00:
        ass3 = cbor2.loads(bytes(g3[1:]))
        flags_pf = ass3[2][32]
        ok("pre-flight flags UP=0", not (flags_pf & 0x01), f"flags=0x{flags_pf:02X}")
        ok("pre-flight found a credential for RP", ass3[1]["id"] in (cred_id_a, cred_id_b))

    print("\nRound-trip terminado.")
    return 0


if __name__ == "__main__":
    sys.exit(main())



