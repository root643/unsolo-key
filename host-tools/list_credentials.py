# -*- coding: utf-8 -*-
"""Lista credenciales registradas en la llave via CredentialManagement.
Uso: python list_credentials.py [pin]   (default pin: 8565)"""
import sys, hashlib
sys.path.insert(0, r"C:\Users\Usuario\Downloads\solokey\fido2")
from validate_full import raw_cbor, pin_session, hmac_sha256, aes_cbc_dec, sha256, aes_cbc
import os
import cbor2
from fido2.hid import CtapHidDevice

try:
    import fido2.hid.windows as whid
    whid.get_serial = lambda dev: "none"
except Exception:
    pass

PIN = sys.argv[1] if len(sys.argv) > 1 else "8565"


def main():
    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print("no device"); return 1
    sess = pin_session(dev, 2)
    iv = os.urandom(16)
    phe = iv + aes_cbc(sess["aes"], sha256(PIN.encode())[:16], iv)
    st, resp = raw_cbor(dev, 0x06, {1: 2, 2: 9, 3: sess["plat"], 6: phe, 9: 0x04})
    if st != 0:
        print(f"token fallo 0x{st:02X}"); return 1
    e = bytes(resp[2]); token = aes_cbc_dec(sess["aes"], e[16:], e[:16])

    pa = hmac_sha256(token, bytes([0x01]))[:32]
    st, meta = raw_cbor(dev, 0x0A, {1: 0x01, 3: 2, 4: pa})
    print(f"Credenciales: {meta.get(1)} de {meta.get(2)} slots\n")

    pa = hmac_sha256(token, bytes([0x02]))[:32]
    st, rps = raw_cbor(dev, 0x0A, {1: 0x02, 3: 2, 4: pa})
    if st != 0:
        print(f"enumerateRPs: 0x{st:02X} (tienda vacia)"); return 0
    total = rps.get(3, 0)
    print(f"Sitios registrados ({total}):")
    for i in range(total):
        if i > 0:
            pa = hmac_sha256(token, bytes([0x03]))[:32]
            st, rps = raw_cbor(dev, 0x0A, {1: 0x03, 3: 2, 4: pa})
            if st != 0:
                break
        rp = rps.get(1, {})
        rp_id = rp.get("id", "?")
        rph = bytes(rps.get(2))
        print(f"  [{i+1}] {rp_id}")
        params = {1: rph}
        pa2 = hmac_sha256(token, bytes([0x04]) + cbor2.dumps(params))[:32]
        stc, creds = raw_cbor(dev, 0x0A, {1: 0x04, 2: params, 3: 2, 4: pa2})
        if stc == 0:
            n = creds.get(3, 0)
            for j in range(n):
                if j > 0:
                    pa2 = hmac_sha256(token, bytes([0x05]) + cbor2.dumps(params))[:32]
                    stc, creds = raw_cbor(dev, 0x0A, {1: 0x05, 2: params, 3: 2, 4: pa2})
                    if stc != 0:
                        break
                u = creds.get(1, {})
                uid = bytes(u.get("id", b""))
                try:
                    uid_s = uid.decode()
                except Exception:
                    uid_s = uid.hex()[:20]
                print(f"      - usuario: {u.get('name', '?')} (id: {uid_s})")
    return 0

if __name__ == "__main__":
    sys.exit(main())
