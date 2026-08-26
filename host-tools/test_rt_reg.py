# -*- coding: utf-8 -*-
"""Register one user on roundtrip.example with full PIN-token flow. Args: uid name"""
import sys, os, time, hashlib
sys.path.insert(0, r"C:\Users\Usuario\Downloads\solokey\fido2")
from validate_full import raw_cbor, pin_session, hmac_sha256, aes_cbc_dec, sha256
from fido2.hid import CtapHidDevice

try:
    import fido2.hid.windows as whid
    whid.get_serial = lambda dev: "none"
except Exception:
    pass

import cbor2

RP = "roundtrip.example"
PIN = "8565"


def main():
    uid = sys.argv[1].encode() if len(sys.argv) > 1 else b"uid-x"
    uname = sys.argv[2] if len(sys.argv) > 2 else "x"

    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print("no device"); return 1

    # PIN token via 0x09 proto2 (permisos mc|ga)
    sess = pin_session(dev, 2)
    iv = os.urandom(16)
    from validate_full import aes_cbc
    phe = iv + aes_cbc(sess["aes"], sha256(PIN.encode())[:16], iv)
    st, resp = raw_cbor(dev, 0x06, {1: 2, 2: 9, 3: sess["plat"], 6: phe, 9: 0x03})
    if st != 0:
        print(f"token fail: 0x{st:02X}"); return 1
    enc_tok = bytes(resp[2])
    token = aes_cbc_dec(sess["aes"], enc_tok[16:], enc_tok[:16])

    cdh = hashlib.sha256(b"rt-cdh").digest()
    mc = {
        0x01: cdh,
        0x02: {"id": RP, "name": "Roundtrip RP"},
        0x03: {"id": uid, "name": uname},
        0x04: [{"type": "public-key", "alg": -7}],
        0x07: {"rk": True},
        0x08: hmac_sha256(token, cdh)[:32],
        0x09: 2,
    }
    t0 = time.time()
    st, att = raw_cbor(dev, 0x01, mc)
    print(f"register {uname}: status=0x{st:02X} ({time.time()-t0:.1f}s)")
    if st == 0x00:
        authdata = bytes(att[2])
        flags = authdata[32]
        print(f"  credId: {authdata[55:87].hex()}")
        print(f"  flags=0x{flags:02X} UP={bool(flags&1)} UV={bool(flags&4)}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())


