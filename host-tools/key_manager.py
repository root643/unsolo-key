# -*- coding: utf-8 -*-
"""Gestion de credenciales de la llave FIDO2.

Uso:
  python key_manager.py list                 # lista passkeys
  python key_manager.py delete <sitio> [user] # borra passkey(s) de un sitio (y usuario opcional)
  python key_manager.py change-pin <nuevo>   # cambia el PIN
  python key_manager.py reset                # (requiere toque en los primeros 10s tras encender)

PIN actual por defecto: 8565  (puedes pasarlo como 4to arg o variable)
"""
import sys, os, hashlib
sys.path.insert(0, r"C:\Users\Usuario\Downloads\solokey\fido2")
from validate_full import raw_cbor, pin_session, hmac_sha256, aes_cbc_dec, aes_cbc, sha256
import cbor2
from fido2.hid import CtapHidDevice

try:
    import fido2.hid.windows as whid
    whid.get_serial = lambda dev: "none"
except Exception:
    pass

DEFAULT_PIN = "8565"


def get_token(dev, pin, perms):
    sess = pin_session(dev, 2)
    iv = os.urandom(16)
    phe = iv + aes_cbc(sess["aes"], sha256(pin.encode())[:16], iv)
    st, resp = raw_cbor(dev, 0x06, {1: 2, 2: 9, 3: sess["plat"], 6: phe, 9: perms})
    if st != 0:
        print(f"token fallo 0x{st:02X}"); return None, None
    e = bytes(resp[2])
    return aes_cbc_dec(sess["aes"], e[16:], e[:16]), sess


def cm(dev, token, sub, params=None, perms=0x04):
    req = {1: sub, 3: 2}
    if params is not None:
        req[2] = params
    msg = bytes([sub]) + (cbor2.dumps(params) if params is not None else b"")
    req[4] = hmac_sha256(token, msg)[:32]
    return raw_cbor(dev, 0x0A, req)


def list_all(dev, token):
    st, meta = cm(dev, token, 0x01)
    print(f"Credenciales: {meta.get(1)} de {meta.get(2)} slots\n")
    st, rps = cm(dev, token, 0x02)
    if st != 0:
        print("(tienda vacia)"); return []
    out = []
    total = rps.get(3, 0)
    for i in range(total):
        if i > 0:
            st, rps = cm(dev, token, 0x03)
            if st != 0:
                break
        rp_id = rps.get(1, {}).get("id", "?")
        rph = bytes(rps.get(2))
        stc, creds = cm(dev, token, 0x04, {1: rph})
        if stc != 0:
            continue
        n = creds.get(3, 0)
        for j in range(n):
            if j > 0:
                stc, creds = cm(dev, token, 0x05, {1: rph})
                if stc != 0:
                    break
            u = creds.get(1, {})
            cid = bytes(creds.get(2, {}).get("id", b""))
            out.append({"rp": rp_id, "user": u.get("name", "?"), "uid": bytes(u.get("id", b"")), "cid": cid})
            print(f"  {rp_id}  /  {u.get('name', '?')}")
    return out


def delete(dev, token, rp_filter, user_filter=None):
    all_ = list_all(dev, token)
    target = [c for c in all_ if c["rp"] == rp_filter and (user_filter is None or c["user"] == user_filter)]
    if not target:
        print(f"No hay passkeys de '{rp_filter}'"); return
    for c in target:
        params = {2: {"id": c["cid"], "type": "public-key"}}
        st, _ = cm(dev, token, 0x06, params)
        print(f"  borrar {c['rp']}/{c['user']}: {'OK' if st == 0 else '0x%02X' % st}")
    print("Lista actual:")
    list_all(dev, token)


def change_pin(dev, pin, nuevo):
    sess = pin_session(dev, 2)
    iv = os.urandom(16)
    npe = iv + aes_cbc(sess["aes"], nuevo.encode().ljust(64, b"\x00"), iv)
    phe = iv + aes_cbc(sess["aes"], sha256(pin.encode())[:16], iv)
    pa = hmac_sha256(sess["hmac"], npe + phe)[:32]
    st, _ = raw_cbor(dev, 0x06, {1: 2, 2: 4, 3: sess["plat"], 4: pa, 5: npe, 6: phe})
    print(f"changePIN -> {'OK' if st == 0 else '0x%02X' % st}")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); return 1
    cmd = args[0]
    pin = DEFAULT_PIN
    if len(args) >= 2 and args[-1].isdigit() and len(args[-1]) >= 4 and cmd != "change-pin":
        # permitir pin como ultimo arg si no es el nuevo pin de change-pin
        pass
    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print("no device"); return 1

    if cmd == "list":
        token, _ = get_token(dev, pin, 0x04)
        if token: list_all(dev, token)
    elif cmd == "delete":
        if len(args) < 2:
            print("uso: key_manager.py delete <sitio> [usuario]"); return 1
        token, _ = get_token(dev, pin, 0x04)
        if token: delete(dev, token, args[1], args[2] if len(args) > 2 else None)
    elif cmd == "change-pin":
        if len(args) < 2:
            print("uso: key_manager.py change-pin <nuevo_pin>"); return 1
        change_pin(dev, pin, args[1])
    else:
        print(__doc__); return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
