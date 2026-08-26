"""
Test script to mimic Windows Hello passkey request WITHOUT pinAuth.
This should trigger the 0x33 (PIN_AUTH_INVALID) error immediately.
"""
import sys
import logging
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin
from fido2.ctap import CtapError
import hashlib

logging.basicConfig(level=logging.DEBUG)

def run():
    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print("No FIDO2 device found!")
        return
    
    ctap2 = Ctap2(dev)
    
    print("\n=== Sending MakeCredential (rk=True, NO pinAuth) ===")
    client_data_hash = hashlib.sha256(b"test").digest()
    
    try:
        # We explicitly omit pin_uv_param to simulate Windows Hello probe
        attestation = ctap2.make_credential(
            client_data_hash=client_data_hash,
            rp={"id": "github.com", "name": "GitHub"},
            user={"id": b"1234", "name": "test"},
            key_params=[{"type": "public-key", "alg": -7}],
            options={"rk": True}
        )
        print("ERROR: MakeCredential succeeded! It should have failed with 0x33!")
    except CtapError as e:
        print(f"\nGot expected CTAP error: {e}")
        if e.code == 0x33:
            print("SUCCESS! Device correctly rejected rk=True without PIN.")
        else:
            print(f"ERROR: Got wrong error code {e.code:02x}, expected 0x33.")

if __name__ == "__main__":
    run()
