"""
Full CTAP2 PIN Protocol 1 test - simulates exactly what Windows Hello does.
Run this to verify the device PIN flow works step by step.

Usage: python test_pin_flow.py [pin]
Default PIN: 1234
"""

import sys
import hashlib
import hmac as hmac_mod
import os
import cbor2
from fido2.hid import CtapHidDevice

PIN = sys.argv[1] if len(sys.argv) > 1 else "1234"
PIN_BYTES = PIN.encode("utf-8")

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key, SECP256R1, ECDH, EllipticCurvePublicNumbers
    )
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("Install: pip install cryptography cbor2")
    sys.exit(1)

def aes_cbc_encrypt(key, plaintext):
    iv = bytes(16)
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    e = c.encryptor()
    return e.update(plaintext) + e.finalize()

def aes_cbc_decrypt(key, ciphertext):
    iv = bytes(16)
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    d = c.decryptor()
    return d.update(ciphertext) + d.finalize()

def hmac_sha256(key, msg):
    return hmac_mod.new(key, msg, hashlib.sha256).digest()

def sha256(data):
    return hashlib.sha256(data).digest()

def ctap_cbor(dev, cmd_byte, cbor_obj):
    payload = bytes([cmd_byte]) + cbor2.dumps(cbor_obj)
    raw = dev.call(0x10, payload)
    status = raw[0]
    if status != 0x00:
        return status, None
    if len(raw) > 1:
        return status, cbor2.loads(raw[1:])
    return status, {}

def make_ecdh_session(dev_cose_key):
    """Given device COSE_Key, return (platform_private, shared_secret, plat_cose_key)"""
    dev_x = bytes(dev_cose_key.get(-2, b''))
    dev_y = bytes(dev_cose_key.get(-3, b''))
    print(f"      dev x={dev_x.hex()[:16]}... y={dev_y.hex()[:16]}...")

    plat_priv = generate_private_key(SECP256R1(), default_backend())
    dev_pub = EllipticCurvePublicNumbers(
        x=int.from_bytes(dev_x, 'big'),
        y=int.from_bytes(dev_y, 'big'),
        curve=SECP256R1()
    ).public_key(default_backend())

    shared_x = plat_priv.exchange(ECDH(), dev_pub)
    shared_secret = sha256(shared_x)

    plat_nums = plat_priv.public_key().public_numbers()
    plat_cose = {
        1: 2, 3: -25, -1: 1,
        -2: plat_nums.x.to_bytes(32, 'big'),
        -3: plat_nums.y.to_bytes(32, 'big')
    }
    return plat_priv, shared_secret, plat_cose

def run():
    devs = list(CtapHidDevice.list_devices())
    if not devs:
        print("No FIDO2 device found"); return
    dev = devs[0]
    print(f"Device: {dev}\nPIN: '{PIN}'\n")

    # [1] GetInfo
    print("[1] GetInfo...")
    raw = dev.call(0x10, bytes([0x04]))
    st = raw[0]
    info = cbor2.loads(raw[1:]) if st == 0 else {}
    opts = info.get(4, {})
    print(f"    clientPin={opts.get('clientPin')}, versions={info.get(1)}")
    if st != 0: print(f"    FAIL 0x{st:02X}"); return

    # [2] GetKeyAgreement
    print("[2] GetKeyAgreement...")
    st, resp = ctap_cbor(dev, 0x06, {1: 1, 2: 2})
    if st != 0: print(f"    FAIL 0x{st:02X}"); return
    ka1 = resp.get(1)
    print(f"    OK, COSE_Key keys={list(ka1.keys())}")
    try:
        _, ss1, plat_cose1 = make_ecdh_session(ka1)
        print(f"    shared_secret={ss1.hex()[:16]}...")
    except Exception as e:
        print(f"    ECDH failed: {e}"); return

    # [3] SetPIN
    print(f"[3] SetPIN ('{PIN}')...")
    pin_padded = PIN_BYTES.ljust(64, b'\x00')
    new_pin_enc = aes_cbc_encrypt(ss1, pin_padded)
    pin_auth = hmac_sha256(ss1, new_pin_enc)[:16]
    st, _ = ctap_cbor(dev, 0x06, {1: 1, 2: 3, 3: plat_cose1, 4: pin_auth, 5: new_pin_enc})
    if st != 0:
        print(f"    FAIL 0x{st:02X}")
        if st == 0x34: print("    -> PIN_AUTH_INVALID (HMAC mismatch in SetPIN)")
        return
    print("    OK - PIN stored in flash!")

    # [4] GetKeyAgreement (new session)
    print("[4] GetKeyAgreement (new session for GetPinToken)...")
    st, resp = ctap_cbor(dev, 0x06, {1: 1, 2: 2})
    if st != 0: print(f"    FAIL 0x{st:02X}"); return
    ka2 = resp.get(1)
    try:
        _, ss2, plat_cose2 = make_ecdh_session(ka2)
    except Exception as e:
        print(f"    ECDH failed: {e}"); return
    print("    OK")

    # [5] GetPinToken
    print(f"[5] GetPinToken ('{PIN}')...")
    pin_hash = sha256(PIN_BYTES)[:16]
    pin_hash_enc = aes_cbc_encrypt(ss2, pin_hash)
    st, resp = ctap_cbor(dev, 0x06, {1: 1, 2: 5, 3: plat_cose2, 6: pin_hash_enc})
    if st != 0:
        print(f"    FAIL 0x{st:02X}")
        if st == 0x31: print("    -> PIN_INVALID: hash mismatch")
        if st == 0x32: print("    -> PIN_BLOCKED")
        if st == 0x35: print("    -> PIN_NOT_SET: flash write in SetPIN failed!")
        return
    enc_token = bytes(resp.get(2, b''))
    pin_token = aes_cbc_decrypt(ss2, enc_token)
    print(f"    OK - token={pin_token.hex()}")

    # [6] MakeCredential with pinAuth
    print("[6] MakeCredential with pinAuth...")
    cdh = os.urandom(32)
    pin_uv_auth = hmac_sha256(pin_token, cdh)[:16]
    st, resp = ctap_cbor(dev, 0x01, {
        1: cdh,
        2: {"id": "test.example.com", "name": "Test"},
        3: {"id": b'\x01\x02\x03\x04', "name": "testuser"},
        4: [{"type": "public-key", "alg": -7}],
        8: pin_uv_auth,
        9: 1,
    })
    if st == 0:
        auth_data = bytes(resp.get(2, b''))
        flags = auth_data[32] if len(auth_data) > 32 else 0
        uv = bool(flags & 0x04)
        print(f"    OK! fmt={resp.get(1)}, flags=0x{flags:02X}, UV={uv}, UP={bool(flags&1)}")
        if uv: print("    SUCCESS: UV=1 - full passkey registration works!")
        else:  print("    WARNING: UV=0 despite sending pinAuth!")
    else:
        print(f"    FAIL 0x{st:02X}")
        if st == 0x33: print("    -> PIN_AUTH_INVALID")
        if st == 0x35: print("    -> PIN_NOT_SET")

if __name__ == "__main__":
    run()
