import sys
import logging
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin

def test_set_pin():
    devs = list(CtapHidDevice.list_devices())
    if not devs:
        print("No device found!")
        return

    dev = devs[0]
    ctap2 = Ctap2(dev)
    
    # Monkey patch send_cbor to print the exact request and response
    original_send_cbor = ctap2.send_cbor
    
    def hooked_send_cbor(cmd, data=None, **kwargs):
        print(f"\n>> Sending CMD: 0x{cmd:02X}")
        if data:
            print(f">> Data: {data}")
            
        original_on_keepalive = kwargs.get('on_keepalive')
        def my_keepalive(status):
            print(f"   [Keepalive received: status={status}]")
            if original_on_keepalive:
                original_on_keepalive(status)
                
        kwargs['on_keepalive'] = my_keepalive
            
        try:
            resp = original_send_cbor(cmd, data, **kwargs)
            print(f"<< Response CBOR: {resp}")
            return resp
        except Exception as e:
            print(f"<< Error: {e}")
            raise e
            
    ctap2.send_cbor = hooked_send_cbor
    
    print("\n=== Testing GetInfo ===")
    info = ctap2.get_info()
    
    client_pin = ClientPin(ctap2)
    
    if info.options.get('clientPin'):
        print("PIN is already set. Cannot test set_pin.")
        return
        
    print("\n=== Testing set_pin (setting PIN to '1234') ===")
    try:
        client_pin.set_pin("1234")
        print("Successfully set PIN!")
    except Exception as e:
        print(f"Failed to set PIN: {e}")

test_set_pin()
