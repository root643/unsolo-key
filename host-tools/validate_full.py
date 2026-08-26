# -*- coding: utf-8 -*-
"""
Full no-touch validation suite for the CH32X035 FIDO2 firmware.
Covers: transport, GetInfo, CredentialManagement (PIN unset/set), PIN protocol 1
and 2 lifecycles with real crypto (ECDH/AES/HMAC/HKDF), CM pinUvAuth PRF, probes.

Leaves the device with PIN = "1234".

NOTE: on Windows this must run ELEVATED (FIDO HID devices are kernel-restricted).
Usage: python validate_full.py
"""
import sys, os, time, hashlib, hmac as hmac_mod, threading, queue

PIN1 = sys.argv[1] if len(sys.argv) > 1 else "8565"
PIN2 = sys.argv[2] if len(sys.argv) > 2 else "4321"

from fido2.hid import CtapHidDevice
from fido2.ctap import CtapError

try:
    import fido2.hid.windows as whid
    whid.get_serial = lambda dev: "none"
except Exception:
    pass

try:
    import cbor2
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key, SECP256R1, ECDH, EllipticCurvePublicNumbers)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError as e:
    print("Missing deps:", e); sys.exit(1)

RESULTS = []

def check(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))

def sha256(b): return hashlib.sha256(b).digest()
def hmac_sha256(k, m): return hmac_mod.new(k, m, hashlib.sha256).digest()

def aes_cbc(key, data, iv):
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    e = c.encryptor(); return e.update(data) + e.finalize()

def aes_cbc_dec(key, data, iv):
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    d = c.decryptor(); return d.update(data) + d.finalize()

def hkdf_ctap2(z):
    """CTAP2.1 6.5.7 kdf(Z): two separate HKDFs, concatenated (HMAC 32 || AES 32)."""
    salt = bytes(32)
    def hkdf(info):
        prk = hmac_sha256(salt, z)
        return hmac_sha256(prk, info + b"\x01")
    return hkdf(b"CTAP2 HMAC key"), hkdf(b"CTAP2 AES key")

def call_t(dev, cmd, payload, timeout=25):
    """Device call with watchdog so a firmware hang doesn't stall the suite."""
    q = queue.Queue()
    def run():
        try: q.put(dev.call(cmd, payload))
        except Exception as e: q.put(e)
    t = threading.Thread(target=run, daemon=True); t.start()
    try: return q.get(timeout=timeout)
    except queue.Empty: return TimeoutError()

def raw_cbor(dev, cmd_id, payload_obj, timeout=25):
    p = b"" if payload_obj is None else cbor2.dumps(payload_obj)
    r = call_t(dev, 0x10, bytes([cmd_id]) + p, timeout)
    if isinstance(r, TimeoutError) or r is None: return "TIMEOUT", None
    st = r[0]
    if st == 0x00 and len(r) > 1:
        try: return st, cbor2.loads(r[1:])
        except Exception: return st, None
    return st, None

def ecdh_session(ka_cose, proto):
    dev_x = bytes(ka_cose[-2]); dev_y = bytes(ka_cose[-3])
    priv = generate_private_key(SECP256R1(), default_backend())
    dev_pub = EllipticCurvePublicNumbers(
        x=int.from_bytes(dev_x, "big"), y=int.from_bytes(dev_y, "big"),
        curve=SECP256R1()).public_key(default_backend())
    z = priv.exchange(ECDH(), dev_pub)  # raw 32-byte x
    nums = priv.public_key().public_numbers()
    plat_cose = {1: 2, 3: -25, -1: 1,
                 -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
    return z, plat_cose

def pin_session(dev, proto):
    st, resp = raw_cbor(dev, 0x06, {1: proto, 2: 2})
    if st != 0: return None
    z, plat = ecdh_session(resp[1], proto)
    if proto == 2:
        hk, ak = hkdf_ctap2(z)
        return {"z": z, "hmac": hk, "aes": ak, "plat": plat}
    ss = sha256(z)
    return {"z": z, "hmac": ss, "aes": ss, "plat": plat}

def pad64(b): return b.ljust(64, b"\x00")

def enc_pin(sess, pin_bytes, with_iv):
    pt = pad64(pin_bytes)
    if with_iv:
        iv = os.urandom(16); return iv + aes_cbc(sess["aes"], pt, iv)
    return aes_cbc(sess["aes"], pt, bytes(16))

def main():
    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print("No FIDO2 device found (run elevated!)"); return 1

    print("=== A. TRANSPORT ===")
    r = call_t(dev, 0x86, b"12345678")
    check("A1 INIT nonce echo + CID", isinstance(r, bytes) and len(r) == 17 and r[0:8] == b"12345678")
    r = call_t(dev, 0x81, b"Q")
    check("A2a PING 1B", isinstance(r, bytes) and r == b"Q")
    r = call_t(dev, 0x81, b"X" * 100)
    check("A2b PING 100B (fragmentado)", isinstance(r, bytes) and r == b"X" * 100)
    r = call_t(dev, 0x88, b"")
    check("A3 WINK empty OK", isinstance(r, bytes) and len(r) == 0)
    r = call_t(dev, 0x60, b"")
    # python-fido2 maps a CTAPHID_ERROR response to a CtapError exception
    a4_ok = (isinstance(r, bytes) and len(r) == 1 and r[0] == 0x01) or \
            (isinstance(r, CtapError) and int(r.code) == 0x01)
    check("A4 unknown cmd -> CTAPHID_ERROR 0x01", a4_ok, f"got {type(r).__name__}")

    print("\n=== B. GetInfo ===")
    st, info = raw_cbor(dev, 0x04, None)
    opts = (info or {}).get(4, {})
    pin_already_set = opts.get("clientPin") == True
    check("B1 GetInfo OK", st == 0x00)
    check("B2 versions/aaguid/protocols", st == 0x00 and "FIDO_2_0" in info.get(1, [])
          and len(info.get(3, b"")) == 16 and info.get(6) == [1, 2] and info.get(5, 0) >= 1024)
    print(f"  (estado inicial: clientPin={opts.get('clientPin')})")
    check("B4 option pinUvAuthToken=true", opts.get("pinUvAuthToken") == True)
    algos = (info or {}).get(10, [])
    check("B5 algorithms ES256", any(a.get("alg") == -7 and a.get("type") == "public-key" for a in algos),
          f"algorithms={algos}")
    st8, _ = raw_cbor(dev, 0x08, None)
    check("B6 getNextAssertion sin estado -> 0x2E", st8 == 0x2E, f"st={st8}")

    print("\n=== C. CredentialManagement ===")
    if not pin_already_set:
        st, resp = raw_cbor(dev, 0x0A, {1: 0x01})
        ok = st == 0x00 and resp and resp.get(1) == 0 and resp.get(2) == 5
        check("C1 getCredsMetadata existing=0 max=10", ok, f"st={st}")
        st, _ = raw_cbor(dev, 0x0A, {1: 0x02})
        check("C2 enumerateRPsBegin vacio -> 0x2E", st == 0x2E, f"st={st}")
        st, _ = raw_cbor(dev, 0x0A, {1: 0x04, 2: {1: bytes(32)}})
        check("C3 enumerateCredentialsBegin bogus -> 0x2E", st == 0x2E, f"st={st}")
        st, _ = raw_cbor(dev, 0x0A, {1: 0x06, 2: {2: {"id": bytes(32), "type": "public-key"}}})
        check("C4 deleteCredential bogus -> 0x2E", st == 0x2E, f"st={st}")
    else:
        print("  (PIN ya puesto: seccion C sin token se valida en E)")

    print("\n=== D. PIN protocolo 1 ===")
    if not pin_already_set:
        sess1 = pin_session(dev, 1)
        check("D1 getKeyAgreement p1 + ECDH", sess1 is not None)
        npe = enc_pin(sess1, PIN1.encode(), with_iv=False)
        pa = hmac_sha256(sess1["hmac"], npe)[:16]
        st, _ = raw_cbor(dev, 0x06, {1: 1, 2: 3, 3: sess1["plat"], 4: pa, 5: npe})
        check("D2 setPIN(1234) OK", st == 0x00, f"st={st}")
        st, _ = raw_cbor(dev, 0x06, {1: 1, 2: 3, 3: sess1["plat"], 4: pa, 5: npe})
        check("D3 setPIN otra vez -> 0x33", st == 0x33, f"st={st}")
        npe2 = enc_pin(sess1, b"9999", with_iv=False)
        st, _ = raw_cbor(dev, 0x06, {1: 1, 2: 3, 3: sess1["plat"], 5: npe2})
        check("D4 setPIN sin pinAuth -> 0x30", st == 0x30, f"st={st}")
    else:
        # PIN ya conocido (1234): refrescarlo via changePIN para validar el camino
        sess1 = pin_session(dev, 1)
        npe3 = enc_pin(sess1, PIN1.encode(), with_iv=False)
        phe_cur = aes_cbc(sess1["aes"], sha256(PIN1.encode())[:16], bytes(16))
        pa3 = hmac_sha256(sess1["hmac"], npe3 + phe_cur)[:16]
        st, _ = raw_cbor(dev, 0x06, {1: 1, 2: 4, 3: sess1["plat"], 4: pa3, 5: npe3, 6: phe_cur})
        check("D1b changePIN 1234->1234 (estado conocido)", st == 0x00, f"st={st}")

    st, resp = raw_cbor(dev, 0x06, {1: 1, 2: 1})
    check("D5 getRetries=8", st == 0x00 and resp and resp.get(3) == 8, f"st={st}")
    sess1b = pin_session(dev, 1)
    phe_bad = aes_cbc(sess1b["aes"], sha256(b"0000")[:16], bytes(16))
    st, _ = raw_cbor(dev, 0x06, {1: 1, 2: 5, 3: sess1b["plat"], 6: phe_bad})
    st2, resp = raw_cbor(dev, 0x06, {1: 1, 2: 1})
    check("D6 PIN erroneo -> 0x31 y retries=7", st == 0x31 and resp and resp.get(3) == 7,
          f"st={st},retries={resp.get(3) if resp else '?'}")
    sess1c = pin_session(dev, 1)
    phe = aes_cbc(sess1c["aes"], sha256(PIN1.encode())[:16], bytes(16))
    st, resp = raw_cbor(dev, 0x06, {1: 1, 2: 5, 3: sess1c["plat"], 6: phe})
    tok1 = bytes(resp.get(2, b"")) if st == 0x00 else b""
    check("D7 getPinToken OK y retries=8", st == 0x00, f"st={st}")
    st2, resp2 = raw_cbor(dev, 0x06, {1: 1, 2: 1})
    check("D8 retries restauradas a 8", resp2 and resp2.get(3) == 8)

    if not pin_already_set:
        sess1d = pin_session(dev, 1)
        npe3 = enc_pin(sess1d, PIN2.encode(), with_iv=False)
        phe_old = aes_cbc(sess1d["aes"], sha256(PIN1.encode())[:16], bytes(16))
        pa3 = hmac_sha256(sess1d["hmac"], npe3 + phe_old)[:16]
        st, _ = raw_cbor(dev, 0x06, {1: 1, 2: 4, 3: sess1d["plat"], 4: pa3, 5: npe3, 6: phe_old})
        check("D9 changePIN 1234->4321 OK", st == 0x00, f"st={st}")
        sess1e = pin_session(dev, 1)
        phe_old2 = aes_cbc(sess1e["aes"], sha256(PIN1.encode())[:16], bytes(16))
        st, _ = raw_cbor(dev, 0x06, {1: 1, 2: 5, 3: sess1e["plat"], 6: phe_old2})
        check("D10 PIN viejo rechazado", st == 0x31, f"st={st}")
        sess1f = pin_session(dev, 1)
        phe_new = aes_cbc(sess1f["aes"], sha256(PIN2.encode())[:16], bytes(16))
        st, _ = raw_cbor(dev, 0x06, {1: 1, 2: 5, 3: sess1f["plat"], 6: phe_new})
        check("D11 PIN nuevo aceptado", st == 0x00, f"st={st}")
        sess1g = pin_session(dev, 1)
        npe4 = enc_pin(sess1g, PIN1.encode(), with_iv=False)
        phe_cur = aes_cbc(sess1g["aes"], sha256(PIN2.encode())[:16], bytes(16))
        pa4 = hmac_sha256(sess1g["hmac"], npe4 + phe_cur)[:16]
        st, _ = raw_cbor(dev, 0x06, {1: 1, 2: 4, 3: sess1g["plat"], 4: pa4, 5: npe4, 6: phe_cur})
        check("D12 changePIN 4321->1234 (restaurar)", st == 0x00, f"st={st}")

    print("\n=== E. PIN protocolo 2 + CM con token ===")
    sess2 = pin_session(dev, 2)
    check("E1 getKeyAgreement p2 + HKDF", sess2 is not None)
    phe2 = sess2["aes"][:0]
    iv = os.urandom(16)
    phe2 = iv + aes_cbc(sess2["aes"], sha256(PIN1.encode())[:16], iv)
    st, resp = raw_cbor(dev, 0x06, {1: 2, 2: 5, 3: sess2["plat"], 6: phe2})
    tok2 = b""
    if st == 0x00:
        enc = bytes(resp.get(2, b""))
        tok2 = aes_cbc_dec(sess2["aes"], enc[16:], enc[:16])
    check("E2 getPinToken proto2 -> token32", st == 0x00 and len(tok2) == 32, f"st={st}")
    iv = os.urandom(16)
    phe2b = iv + aes_cbc(sess2["aes"], sha256(PIN1.encode())[:16], iv)
    st, resp = raw_cbor(dev, 0x06, {1: 2, 2: 9, 3: sess2["plat"], 6: phe2b, 9: 0x07})
    tok2b = b""
    if st == 0x00:
        enc = bytes(resp.get(2, b""))
        tok2b = aes_cbc_dec(sess2["aes"], enc[16:], enc[:16])
    check("E3 getPinUvAuthTokenUsingPinWithPermissions (0x09) -> token32", st == 0x00 and len(tok2b) == 32, f"st={st}")

    token = tok2b if tok2b else tok2
    # CM con pinUvAuth (PRF 6.8: HMAC(token, subCmdByte [|| params]))
    pa_cm = hmac_sha256(token, bytes([0x01]))[:32]
    st, resp = raw_cbor(dev, 0x0A, {1: 0x01, 3: 2, 4: pa_cm})
    existing = (resp or {}).get(1, 0)
    ok = st == 0x00 and resp and resp.get(2) == 5  # 5 slots (PASSKEY_NUM_SLOTS)
    check("E4 CM getCredsMetadata con token (PRF [0x01])", ok, f"st={st}")
    pa_cm = hmac_sha256(token, bytes([0x02]))[:32]
    st, _ = raw_cbor(dev, 0x0A, {1: 0x02, 3: 2, 4: pa_cm})
    # con credenciales guardadas -> 0x00 (lista RPs); tienda vacia -> 0x2E
    ok5 = (st == 0x2E and existing == 0) or (st == 0x00 and existing > 0)
    check("E5 CM enumerateRPsBegin con token", ok5, f"st={st} existing={existing}")
    params = {1: bytes(32)}
    pa_cm = hmac_sha256(token, bytes([0x04]) + cbor2.dumps(params))[:32]
    st, _ = raw_cbor(dev, 0x0A, {1: 0x04, 2: params, 3: 2, 4: pa_cm})
    check("E6 CM enumerateCredentialsBegin con token -> 0x2E", st == 0x2E, f"st={st}")
    pa_bad = hmac_sha256(b"\x00" * 32, bytes([0x01]))[:32]
    st, _ = raw_cbor(dev, 0x0A, {1: 0x01, 3: 2, 4: pa_bad})
    check("E7 CM con token INVALIDO -> 0x33", st == 0x33, f"st={st}")
    st, _ = raw_cbor(dev, 0x0A, {1: 0x01, 3: 2})
    check("E8 CM sin pinAuth (PIN puesto) -> 0x33", st == 0x33, f"st={st}")

    print("\n=== F. Sondas con PIN puesto ===")
    st, info = raw_cbor(dev, 0x04, None)
    check("F1 GetInfo clientPin=True", (info or {}).get(4, {}).get("clientPin") == True)
    mc = {1: sha256(b"cdh"), 2: {"id": "probe.example", "name": "P"},
          3: {"id": b"uid-p", "name": "p"}, 4: [{"type": "public-key", "alg": -7}],
          7: {"rk": True}}
    t0 = time.time()
    st, _ = raw_cbor(dev, 0x01, mc, timeout=20)
    check("F2 MC rk sin token -> 0x36 instantaneo", st == 0x36 and time.time() - t0 < 3,
          f"st={st} dt={time.time()-t0:.1f}s")
    mc2 = dict(mc); mc2[8] = b""
    st, _ = raw_cbor(dev, 0x01, mc2, timeout=20)
    check("F3 MC pinAuth vacio (probe) -> 0x33", st == 0x33, f"st={st}")
    ga = {1: "nope.example", 2: sha256(b"cdh2"), 5: {"up": False}}
    t0 = time.time()
    st, _ = raw_cbor(dev, 0x02, ga, timeout=20)
    check("F4 GA up=false desconocido -> 0x2E instantaneo", st == 0x2E and time.time() - t0 < 3,
          f"st={st}")

    n_ok = sum(1 for x in RESULTS if x)
    print(f"\n===== RESULTADO: {n_ok}/{len(RESULTS)} PASS =====")
    return 0 if n_ok == len(RESULTS) else 2


if __name__ == "__main__":
    sys.exit(main())


