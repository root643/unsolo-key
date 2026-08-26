#include "pin.h"
#include "fido2.h"
#include "aes.h"
#include "sha256.h"
#include "cbor.h"
#include "flash_passkey.h"
#include "uECC.h"
#include "debug_info.h"
#include <string.h>

extern void fido2_send_keepalive(uint32_t cid, uint8_t status);

// Global session state for PIN protocol
uint8_t pin_shared_secret[32];  // AES key (SHA256 or HKDF of ECDH x-coordinate)
uint8_t hmac_key[32];           // HMAC key (same as AES for Protocol 1, derived for Protocol 2)
uint32_t active_pin_protocol = 1; // 1 or 2
uint8_t g_pin_debug[32] = {0};
uint8_t pin_token[32];
uint16_t pin_token_len = 0;
bool has_pin_token = false;

// ECDH private key for current PIN session - persists between GetKeyAgreement and SetPIN/GetPinToken
static uint8_t ecdh_private_key[32];
static uint8_t ecdh_public_key[64];   // cached public key
static bool ecdh_key_valid = false;   // true once we have a key pair

// Removed get_cbor_map_neg_key since get_cbor_map_neg_value is now in fido2.c



// HKDF-SHA256 for CTAP2 pinUvAuthProtocol 2
static void hkdf_sha256_ctap2(const uint8_t* ikm, uint8_t* okm_hmac, uint8_t* okm_aes) {
    uint8_t salt[32] = {0};
    uint8_t prk[32];
    hmac_sha256(salt, 32, ikm, 32, prk);
    
    // HKDF-Expand for HMAC key (info="CTAP2 HMAC key")
    uint8_t info_hmac[15] = {'C','T','A','P','2',' ','H','M','A','C',' ','k','e','y', 0x01};
    hmac_sha256(prk, 32, info_hmac, 15, okm_hmac);
    
    // HKDF-Expand for AES key (info="CTAP2 AES key")
    uint8_t info_aes[14] = {'C','T','A','P','2',' ','A','E','S',' ','k','e','y', 0x01};
    hmac_sha256(prk, 32, info_aes, 14, okm_aes);
}

// AES-256-CBC Decrypt
static void aes_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* ciphertext, uint8_t* plaintext, size_t len) {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    memcpy(plaintext, ciphertext, len);
    for (size_t i = 0; i < len; i += 16) {
        AES_CBC_decrypt_buffer(&ctx, plaintext + i, 16);
    }
}

// AES-256-CBC Encrypt
static void aes_encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* plaintext, uint8_t* ciphertext, size_t len) {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    memcpy(ciphertext, plaintext, len);
    for (size_t i = 0; i < len; i += 16) {
        AES_CBC_encrypt_buffer(&ctx, ciphertext + i, 16);
    }
}

void process_client_pin(const uint8_t* req, uint16_t req_len, uint8_t* resp, uint16_t* resp_len, uint32_t cid) {
    if (req_len < 1) return;
    
    // Default response error
    resp[0] = 0x01; *resp_len = 1;
    
    // Parse request map
    uint32_t sub_cmd = 0;
    if (!get_cbor_map_int(req, req_len, 0x02, &sub_cmd)) {
        return; // subCommand is required
    }
    
    uint32_t proto_val = 0;
    if (get_cbor_map_int(req, req_len, 0x01, &proto_val)) {
        active_pin_protocol = proto_val;
    }

    if (sub_cmd != 0x01 && (active_pin_protocol != 1 && active_pin_protocol != 2)) {
        resp[0] = 0x2B; *resp_len = 1; return; // CTAP2_ERR_UNSUPPORTED_OPTION
    }
    
    
    CborEncoder encoder;
    cbor_init(&encoder, resp + 1, 1024);
    
    if (sub_cmd == 0x01) { // getPINRetries
        const PINState* p = pin_load();
        if (!p) {
            resp[0] = 0x35; // CTAP2_ERR_PIN_NOT_SET
            *resp_len = 1;
            return;
        }
        
        resp[0] = 0x00; // Success
        cbor_encode_map(&encoder, 1);
        cbor_encode_uint(&encoder, 3); // retries
        cbor_encode_uint(&encoder, p->retries);
        *resp_len = 1 + encoder.length;
    } 
    else if (sub_cmd == 0x02) { // getKeyAgreement
        // Generate a fresh ephemeral ECDH key pair for this session
        uECC_set_rng(rng);
        uECC_make_key(ecdh_public_key, ecdh_private_key, uECC_secp256r1());
        ecdh_key_valid = true;
        has_pin_token = false; // Invalidate any existing token when new key agreement starts
        
        resp[0] = 0x00;
        cbor_encode_map(&encoder, 1);
        cbor_encode_uint(&encoder, 1); // keyAgreement
        
        // Encode COSE_Key
        cbor_encode_map(&encoder, 5);
        cbor_encode_uint(&encoder, 1); cbor_encode_uint(&encoder, 2); // kty: EC2
        cbor_encode_uint(&encoder, 3); cbor_encode_int(&encoder, -25); // alg: ECDH-ES + HKDF-256
        cbor_encode_int(&encoder, -1); cbor_encode_uint(&encoder, 1); // crv: P-256
        cbor_encode_int(&encoder, -2); cbor_encode_byte_string(&encoder, ecdh_public_key, 32); // x
        cbor_encode_int(&encoder, -3); cbor_encode_byte_string(&encoder, ecdh_public_key + 32, 32); // y
        
        *resp_len = 1 + encoder.length;
    }

    else if (sub_cmd == 0x03 || sub_cmd == 0x04 || sub_cmd == 0x05 || sub_cmd == 0x09) {
        if (!ecdh_key_valid) { resp[0] = 0x01; *resp_len = 1; return; } // No key agreement done
        
        uint16_t ka_len = 0;
        const uint8_t* ka = get_cbor_map_item(req, req_len, 0x03, &ka_len);
        if (!ka) { resp[0] = 0x01; *resp_len = 1; return; }
        
        uint16_t x_len = 0, y_len = 0;
        const uint8_t* x_ptr = get_cbor_map_neg_value(ka, ka_len, 2, &x_len, NULL); // -2
        const uint8_t* y_ptr = get_cbor_map_neg_value(ka, ka_len, 3, &y_len, NULL); // -3
        
        if (!x_ptr || !y_ptr || x_len < 31 || x_len > 33 || y_len < 31 || y_len > 33) {
            resp[0] = 0x91; *resp_len = 1; return;
        }
        
        uint8_t host_pub[64] = {0};
        
        // Copy X (right-aligned)
        if (x_len == 33) memcpy(host_pub, x_ptr + 1, 32);
        else if (x_len == 32) memcpy(host_pub, x_ptr, 32);
        else if (x_len == 31) memcpy(host_pub + 1, x_ptr, 31);
        
        // Copy Y (right-aligned)
        if (y_len == 33) memcpy(host_pub + 32, y_ptr + 1, 32);
        else if (y_len == 32) memcpy(host_pub + 32, y_ptr, 32);
        else if (y_len == 31) memcpy(host_pub + 33, y_ptr, 31);
        
        uint8_t shared_secret_x[32];
        // Use our ECDH private key (from GetKeyAgreement) to compute shared secret
        uECC_shared_secret(host_pub, ecdh_private_key, shared_secret_x, uECC_secp256r1());
        
        if (active_pin_protocol == 2) {
            hkdf_sha256_ctap2(shared_secret_x, hmac_key, pin_shared_secret);
        } else {
            uint8_t shared_secret_hashed[32];
            SHA256_CTX sha;
            sha256_init(&sha);
            sha256_update(&sha, shared_secret_x, 32);
            sha256_final(&sha, shared_secret_hashed);
            memcpy(pin_shared_secret, shared_secret_hashed, 32);
            memcpy(hmac_key, shared_secret_hashed, 32); // For protocol 1, keys are identical
        }
        
        uint8_t iv_zero[16] = {0};
        
        if (sub_cmd == 0x03) { // setPIN
            uint16_t pin_auth_len = 0;
            const uint8_t* pin_auth = get_cbor_map_string(req, req_len, 0x04, &pin_auth_len);
            uint16_t new_pin_enc_len = 0;
            const uint8_t* new_pin_enc = get_cbor_map_string(req, req_len, 0x05, &new_pin_enc_len);

            // Spec 6.5.5.5: setPIN REQUIRES pinUvAuthParam, and is only valid
            // when no PIN is currently set (use changePIN otherwise).
            if (!pin_auth) {
                resp[0] = 0x30; *resp_len = 1; return; // CTAP2_ERR_MISSING_PARAMETER
            }
            if (pin_load() != NULL) {
                resp[0] = 0x33; *resp_len = 1; return; // CTAP2_ERR_PIN_AUTH_INVALID (PIN already set)
            }
            if (!new_pin_enc) {
                resp[0] = 0x01; *resp_len = 1; return;
            }
            if (active_pin_protocol == 1 && new_pin_enc_len != 64) {
                resp[0] = 0x01; *resp_len = 1; return;
            }
            if (active_pin_protocol == 2 && new_pin_enc_len != 80) {
                resp[0] = 0x01; *resp_len = 1; return;
            }
            
            // Validate pinAuth HMAC if present
            if (pin_auth) {
                uint16_t expected_auth_len = (active_pin_protocol == 2) ? 32 : 16;
                if (pin_auth_len != expected_auth_len) {
                    resp[0] = 0x01; *resp_len = 1; return;
                }
                uint8_t mac[32];
                if (active_pin_protocol == 2) {
                    hmac_sha256(hmac_key, 32, new_pin_enc, new_pin_enc_len, mac);
                } else {
                    hmac_sha256(pin_shared_secret, 32, new_pin_enc, new_pin_enc_len, mac);
                }
                if (memcmp(mac, pin_auth, expected_auth_len) != 0) {
                    resp[0] = 0x33; // CTAP2_ERR_PIN_AUTH_INVALID
                    *resp_len = 1; return;
                }
            }
            
            // Decrypt newPinEnc
            uint8_t new_pin[64];
            if (active_pin_protocol == 2) {
                // Protocol 2: first 16 bytes are random IV, remaining 64 bytes are ciphertext
                aes_decrypt(pin_shared_secret, new_pin_enc, new_pin_enc + 16, new_pin, 64);
            } else {
                // Protocol 1: IV is 16 zero bytes
                aes_decrypt(pin_shared_secret, iv_zero, new_pin_enc, new_pin, 64);
            }
            
            // Hash the PIN - CTAP2 spec: pinHash = SHA-256(PIN)[0:16]
            size_t pin_len = 64;
            while (pin_len > 0 && new_pin[pin_len - 1] == 0x00) pin_len--;
            if (pin_len < 4) { resp[0] = 0x37; *resp_len = 1; return; } // CTAP2_ERR_PIN_POLICY_VIOLATION
            
            uint8_t pin_hash_full[32];
            SHA256_CTX sha;
            sha256_init(&sha);
            sha256_update(&sha, new_pin, pin_len);
            sha256_final(&sha, pin_hash_full);
            // Store only first 16 bytes (per CTAP2 spec: pinHash = SHA256(PIN)[0:16])
            
            fido2_send_keepalive(cid, 1); // PROCESSING
            pin_save(pin_hash_full);
            
            resp[0] = 0x00; *resp_len = 1; return;
        }
        else if (sub_cmd == 0x04) { // changePIN
            uint16_t pin_auth_len = 0;
            const uint8_t* pin_auth = get_cbor_map_string(req, req_len, 0x04, &pin_auth_len);
            uint16_t new_pin_enc_len = 0;
            const uint8_t* new_pin_enc = get_cbor_map_string(req, req_len, 0x05, &new_pin_enc_len);
            uint16_t pin_hash_enc_len = 0;
            const uint8_t* pin_hash_enc = get_cbor_map_string(req, req_len, 0x06, &pin_hash_enc_len);
            
            uint16_t expected_auth_len = (active_pin_protocol == 2) ? 32 : 16;
            if (!pin_auth || !new_pin_enc || !pin_hash_enc || pin_auth_len != expected_auth_len) {
                resp[0] = 0x01; *resp_len = 1; return;
            }
            if (active_pin_protocol == 1 && (new_pin_enc_len != 64 || pin_hash_enc_len != 16)) {
                resp[0] = 0x01; *resp_len = 1; return;
            }
            if (active_pin_protocol == 2 && (new_pin_enc_len != 80 || pin_hash_enc_len != 32)) {
                resp[0] = 0x01; *resp_len = 1; return;
            }
            
            // HMAC is over newPinEnc || pinHashEnc
            uint8_t mac_msg[120];
            memcpy(mac_msg, new_pin_enc, new_pin_enc_len);
            memcpy(mac_msg + new_pin_enc_len, pin_hash_enc, pin_hash_enc_len);
            uint8_t mac[32];
            if (active_pin_protocol == 2) {
                hmac_sha256(hmac_key, 32, mac_msg, new_pin_enc_len + pin_hash_enc_len, mac);
            } else {
                hmac_sha256(pin_shared_secret, 32, mac_msg, new_pin_enc_len + pin_hash_enc_len, mac);
            }
            if (memcmp(mac, pin_auth, expected_auth_len) != 0) {
                resp[0] = 0x33; *resp_len = 1; return; // CTAP2_ERR_PIN_AUTH_INVALID
            }
            
            // Check old PIN hash (first 16 bytes of SHA256)
            uint8_t current_hash_enc[16];
            if (active_pin_protocol == 2) {
                aes_decrypt(pin_shared_secret, pin_hash_enc, pin_hash_enc + 16, current_hash_enc, 16);
            } else {
                aes_decrypt(pin_shared_secret, iv_zero, pin_hash_enc, current_hash_enc, 16);
            }
            const PINState* p = pin_load();
            if (!p || memcmp(current_hash_enc, p->pin_hash, 16) != 0) {
                pin_decrement_retries();
                resp[0] = 0x31; *resp_len = 1; return; // CTAP2_ERR_PIN_INVALID
            }
            
            // Decrypt new PIN
            uint8_t new_pin[64];
            if (active_pin_protocol == 2) {
                aes_decrypt(pin_shared_secret, new_pin_enc, new_pin_enc + 16, new_pin, 64);
            } else {
                aes_decrypt(pin_shared_secret, iv_zero, new_pin_enc, new_pin, 64);
            }
            size_t pin_len = 64;
            while (pin_len > 0 && new_pin[pin_len - 1] == 0x00) pin_len--;
            if (pin_len < 4) { resp[0] = 0x37; *resp_len = 1; return; } // CTAP2_ERR_PIN_POLICY_VIOLATION
            
            uint8_t pin_hash[32];
            SHA256_CTX sha;
            sha256_init(&sha);
            sha256_update(&sha, new_pin, pin_len);
            sha256_final(&sha, pin_hash);
            
            fido2_send_keepalive(cid, 1); // PROCESSING
            pin_save(pin_hash);
            
            resp[0] = 0x00; *resp_len = 1; return;
        }
        else if (sub_cmd == 0x05 || sub_cmd == 0x09) { // getPinToken (0x05) or getPinUvAuthTokenUsingPinWithPermissions (0x09)
            uint16_t pin_hash_enc_len = 0;
            const uint8_t* pin_hash_enc = get_cbor_map_string(req, req_len, 0x06, &pin_hash_enc_len); // FIXED TO 0x06
            if (!pin_hash_enc) {
                resp[0] = 0x93; *resp_len = 1; return;
            }
            if (active_pin_protocol == 1 && pin_hash_enc_len < 16) {
                resp[0] = 0x93; *resp_len = 1; return;
            }
            if (active_pin_protocol == 2 && pin_hash_enc_len < 32) {
                resp[0] = 0x93; *resp_len = 1; return;
            }
            
            uint8_t current_hash_enc[16];
            if (active_pin_protocol == 2) {
                aes_decrypt(pin_shared_secret, pin_hash_enc, pin_hash_enc + 16, current_hash_enc, 16);
            } else {
                aes_decrypt(pin_shared_secret, iv_zero, pin_hash_enc, current_hash_enc, 16);
            }
            
            const PINState* p = pin_load();
            if (!p) {
                resp[0] = 0x35; *resp_len = 1; return; // CTAP2_ERR_PIN_NOT_SET
            }
            if (p->retries == 0) {
                resp[0] = 0x32; *resp_len = 1; return; // CTAP2_ERR_PIN_BLOCKED
            }
            if (memcmp(p->pin_hash, current_hash_enc, 16) != 0) {
                memcpy(g_pin_debug, p->pin_hash, 16);
                memcpy(g_pin_debug + 16, current_hash_enc, 16);
                pin_decrement_retries();
                resp[0] = 0x31; *resp_len = 1; return; // CTAP2_ERR_PIN_INVALID
            }
            
            pin_reset_retries();
            
            // Generate token
            rng(pin_token, 32);
            has_pin_token = true;
            
            // FIDO2.0 specifies 16 byte pinToken for Protocol 1 (subCmd 0x05)
            // FIDO2.1 specifies 32 byte pinUvAuthToken for Protocol 1 (subCmd 0x09)
            uint8_t iv[16] = {0};
            if (active_pin_protocol == 2) {
                rng(iv, 16);
            }
            
            if (sub_cmd == 0x05) {
                if (active_pin_protocol == 2) {
                    pin_token_len = 32;
                    uint8_t token_enc[48]; // 16 IV + 32 ciphertext
                    memcpy(token_enc, iv, 16);
                    aes_encrypt(pin_shared_secret, iv, pin_token, token_enc + 16, 32);
                    resp[0] = 0x00;
                    cbor_encode_map(&encoder, 1);
                    cbor_encode_uint(&encoder, 2); // pinToken
                    cbor_encode_byte_string(&encoder, token_enc, 48);
                } else {
                    pin_token_len = 16;
                    uint8_t token_enc[16];
                    aes_encrypt(pin_shared_secret, iv_zero, pin_token, token_enc, 16);
                    resp[0] = 0x00;
                    cbor_encode_map(&encoder, 1);
                    cbor_encode_uint(&encoder, 2); // pinToken
                    cbor_encode_byte_string(&encoder, token_enc, 16);
                }
            } else {
                pin_token_len = 32;
                if (active_pin_protocol == 2) {
                    uint8_t token_enc[48]; // 16 IV + 32 ciphertext
                    memcpy(token_enc, iv, 16);
                    aes_encrypt(pin_shared_secret, iv, pin_token, token_enc + 16, 32);
                    resp[0] = 0x00;
                    cbor_encode_map(&encoder, 1);
                    cbor_encode_uint(&encoder, 2); // pinUvAuthToken
                    cbor_encode_byte_string(&encoder, token_enc, 48);
                } else {
                    uint8_t token_enc[32];
                    aes_encrypt(pin_shared_secret, iv_zero, pin_token, token_enc, 32);
                    resp[0] = 0x00;
                    cbor_encode_map(&encoder, 1);
                    cbor_encode_uint(&encoder, 2); // pinUvAuthToken
                    cbor_encode_byte_string(&encoder, token_enc, 32);
                }
            }
            
            *resp_len = 1 + encoder.length;
        }
        else {
            resp[0] = 0x27; *resp_len = 1; return;
        }
    }
}
