#include "fido2.h"
#include "cbor.h"
#include "sha256.h"
#include "uECC.h"
#include "flash_passkey.h"
#include "pin.h"
#include "ch32fun.h"
#include "ch32fun.h"
#include "debug_info.h"
#include <string.h>

uint8_t g_last_mc_req[32] = {0}; // First 32 bytes of last MakeCredential request

uint32_t g_current_cid = 0;

static uint32_t g_enum_rp_idx = 0;
static uint32_t g_enum_cred_idx = 0;
static uint8_t g_enum_rp_hash[32] = {0};

// GetNextAssertion (0x08) state - set up by a bare-RP getAssertion
static uint8_t g_ga_rp_hash[32] = {0};
static uint32_t g_ga_count = 0;
static uint32_t g_ga_idx = 0;
uint8_t g_ga_cdh[32] = {0}; // clientDataHash of the original getAssertion

void uECC_yield(void) {
    if (g_current_cid != 0) {
        fido2_send_keepalive(g_current_cid, 1); // 1 = UP_NEEDED / PROCESSING
    }
}



static int touch_adc_init_done = 0;
static uint32_t touch_baseline = 0;

static uint32_t read_touch_pa2(void) {
    uint32_t sum = 0;
    for(int i = 0; i < 4; i++) {
        GPIOA->CFGLR = (GPIOA->CFGLR & ~(0xF << 8)) | (0x3 << 8); // PA2 output PP
        GPIOA->OUTDR &= ~(1 << 2);
        
        Delay_Us(10);
        
        __disable_irq();
        GPIOA->CFGLR = (GPIOA->CFGLR & ~(0xF << 8)) | (0x8 << 8); // PA2 input PU
        GPIOA->OUTDR |= (1 << 2); 
        ADC1->CTLR2 |= ADC_SWSTART;
        __enable_irq();
        
        for(int t = 0; t < 100000 && !(ADC1->STATR & ADC_EOC); t++);
        sum += ADC1->RDATAR;
    }
    return sum;
}

void init_touch_adc(void) {
    if (touch_adc_init_done) return;
    
    RCC->APB2PCENR |= RCC_APB2Periph_ADC1 | RCC_APB2Periph_GPIOA;
    GPIOA->CFGLR &= ~(0xF << 8); // PA2 Analog input
    
    ADC1->RSQR1 = 0;
    ADC1->RSQR2 = 0;
    ADC1->RSQR3 = 2; // Channel 2 (PA2)
    
    ADC1->SAMPTR2 &= ~(ADC_SMP0<<(3*2)); // Fast sampling
    
    ADC1->CTLR2 |= ADC_ADON | ADC_EXTSEL;
    
    ADC1->CTLR2 |= ADC_RSTCAL;
    for(int t = 0; t < 100000 && (ADC1->CTLR2 & ADC_RSTCAL); t++);
    ADC1->CTLR2 |= ADC_CAL;
    for(int t = 0; t < 100000 && (ADC1->CTLR2 & ADC_CAL); t++);
    
    // Discard first samples
    for(int i = 0; i < 8; i++) {
        read_touch_pa2();
        Delay_Ms(2);
    }
    
    // Calibrate baseline ONCE
    uint32_t base_sum = 0;
    for(int i = 0; i < 16; i++) {
        base_sum += read_touch_pa2();
        Delay_Ms(2);
    }
    touch_baseline = base_sum / 16;
    touch_adc_init_done = 1;
}

extern void Process_OOB_Commands(void);
extern volatile bool cancel_requested;

uint8_t fido2_wait_for_user_presence(uint32_t cid) {
    cancel_requested = false;
    // Init ADC if not done
    if (!touch_adc_init_done) {
        init_touch_adc();
    }

    // Recalibrate baseline on EVERY wait - adapts to environment/noise and
    // prevents stale baselines from causing phantom touches.
    uint32_t base_sum = 0;
    for (int i = 0; i < 16; i++) {
        base_sum += read_touch_pa2();
        Delay_Ms(2);
    }
    uint32_t base = base_sum / 16;
    touch_baseline = base;

    // Feed ADC jitter into the RNG entropy pool (floating pad = noise source)
    {
        extern uint32_t g_adc_entropy;
        for (int i = 0; i < 8; i++) {
            g_adc_entropy ^= read_touch_pa2() + 0x9E3779B9u + (g_adc_entropy << 3);
            Delay_Us(31);
        }
    }

    // Send UP_NEEDED immediately to let the host know we are interactive
    fido2_send_keepalive(cid, 2); // UP_NEEDED

    uint32_t loops = 0;
    uint8_t confirm = 0;
    // Touch threshold: a real finger pulls the pad hard towards GND, so we
    // require a LARGE proportional drop (>25% below baseline), not a fixed
    // delta - ADC noise on a ~4000-count sum easily exceeds any constant.
    uint32_t delta = base / 4;
    while (1) {
        uint32_t val = read_touch_pa2();

        // Touch = SUSTAINED significant drop below baseline (3 consecutive
        // samples). NOTE: there is deliberately NO "very low value" shortcut:
        // a stuck/saturated sensor reading ~0 must never count as a touch.
        if ((base > 64) && (val < (base - delta))) {
            if (++confirm >= 3) break; // User touched the pad!
        } else {
            confirm = 0;
        }

        Delay_Ms(50);
        Process_OOB_Commands();
        if (cancel_requested) return 0x2D; // CTAP2_ERR_KEEPALIVE_CANCEL

        loops++;
        if (loops % 4 == 0) {
            fido2_send_keepalive(cid, 2); // UP_NEEDED (~200ms period)
        }

        // Timeout after 15 seconds to prevent permanent hang
        if (loops > 300) {
            return 0x2F; // CTAP2_ERR_USER_ACTION_TIMEOUT
        }
    }

    fido2_send_keepalive(cid, 1); // PROCESSING
    return 0x00; // success
}


static uint32_t hardware_rand() {
    static uint32_t prng_state = 0x12345678; // Non-zero seed
    static uint32_t call_counter = 0;

    // Mix ADC noise (touch pad floats -> real entropy) and SysTick jitter.
    // adc_entropy is refreshed by init_touch_adc()/UP waits.
    extern uint32_t g_adc_entropy;
    prng_state ^= g_adc_entropy ^ (uint32_t)SysTick->CNT ^ (call_counter++ * 0x9E3779B9u);
    prng_state ^= prng_state << 13;
    prng_state ^= prng_state >> 17;
    prng_state ^= prng_state << 5;

    return prng_state;
}

uint32_t g_adc_entropy = 0x13579BDF;

// Hardware-seeded RNG for uECC
int rng(uint8_t *dest, unsigned size) {
    for (unsigned i = 0; i < size; i++) {
        uint32_t r = hardware_rand();
        dest[i] = (uint8_t)(r >> 24);
    }
    return 1;
}

// Very basic CBOR value scanner (Proof of Concept)
// Looks for a map key and returns pointer to the string/bytes
static const uint8_t* find_cbor_string(uint8_t* data, uint16_t len, const char* key, uint16_t* out_len) {
    size_t key_len = strlen(key);
    if (len <= key_len) return NULL;
    for (uint16_t i = 0; i < len - key_len; i++) {
        if (data[i] == (0x60 | key_len)) {
            if (memcmp(&data[i+1], key, key_len) == 0) {
                // Found key! Next byte is the value
                uint16_t val_idx = i + 1 + key_len;
                if (val_idx < len) {
                    uint8_t header = data[val_idx];
                    if ((header & 0xE0) == 0x40 || (header & 0xE0) == 0x60) {
                        *out_len = header & 0x1F;
                        if (*out_len == 24) {
                            *out_len = data[val_idx+1];
                            return &data[val_idx+2];
                        }
                        return &data[val_idx+1];
                    } else if (header == 0xF4 || header == 0xF5) {
                        // Return pointer directly to the boolean byte
                        *out_len = 1;
                        return &data[val_idx];
                    }
                }
            }
        }
    }
    return NULL;
}

uint16_t skip_cbor_item(const uint8_t* data, uint16_t len) {
    if (len == 0) return 0;
    uint8_t type = data[0] & 0xE0;
    uint8_t vlen = data[0] & 0x1F;
    uint16_t header_len = 1;
    uint32_t count = vlen;
    
    if (vlen == 24) { count = data[1]; header_len = 2; }
    else if (vlen == 25) { count = (data[1] << 8) | data[2]; header_len = 3; }
    
    if (type == 0x00 || type == 0x20 || type == 0xE0) { // uint, nint, simple
        return header_len;
    } else if (type == 0x40 || type == 0x60) { // bytes, string
        return header_len + count;
    } else if (type == 0x80) { // array
        uint16_t offset = header_len;
        for (uint32_t i = 0; i < count; i++) {
            if (offset >= len) break;
            offset += skip_cbor_item(data + offset, len - offset);
        }
        return offset;
    } else if (type == 0xA0) { // map
        uint16_t offset = header_len;
        for (uint32_t i = 0; i < count * 2; i++) {
            if (offset >= len) break;
            offset += skip_cbor_item(data + offset, len - offset);
        }
        return offset;
    }
    return header_len; // fallback
}

// Robust text-string value lookup inside a CBOR map (proper walk, no grep).
// `data` must point at the map start; returns value payload + length.
static const uint8_t* cbor_map_get_string(const uint8_t* data, uint16_t len,
                                          const char* key, uint16_t* out_len) {
    if (len == 0 || (data[0] & 0xE0) != 0xA0) return NULL;
    uint8_t vlen = data[0] & 0x1F;
    uint16_t offset = 1;
    uint32_t count = vlen;
    if (vlen == 24) { count = data[1]; offset = 2; }
    else if (vlen == 25) { count = (data[1] << 8) | data[2]; offset = 3; }
    size_t klen = strlen(key);
    for (uint32_t i = 0; i < count; i++) {
        if (offset + 1 >= len) break;
        const uint8_t* kp = data + offset;
        uint16_t key_len = skip_cbor_item(kp, len - offset);
        if (key_len == 0) break;
        // key must be a text string matching `key`
        if ((kp[0] & 0xE0) == 0x60) {
            uint8_t kl = kp[0] & 0x1F;
            const uint8_t* kb = kp + 1;
            if (kl == 24) { kl = kp[1]; kb = kp + 2; }
            else if (kl == 25) { kl = (uint8_t)((kp[1] << 8) | kp[2]); kb = kp + 3; }
            if ((size_t)kl == klen && memcmp(kb, key, klen) == 0) {
                const uint8_t* val = kp + key_len;
                if (val >= data + len) break;
                uint8_t vh = val[0];
                if ((vh & 0xE0) == 0x40 || (vh & 0xE0) == 0x60) {
                    uint8_t vl = vh & 0x1F;
                    const uint8_t* vp = val + 1;
                    if (vl == 24) { vl = val[1]; vp = val + 2; }
                    else if (vl == 25) { vl = (uint8_t)((val[1] << 8) | val[2]); vp = val + 3; }
                    *out_len = vl;
                    return vp;
                }
                return NULL;
            }
        }
        offset += key_len;
        if (offset >= len) break;
        offset += skip_cbor_item(data + offset, len - offset);
    }
    return NULL;
}

const uint8_t* get_cbor_map_value(const uint8_t* data, uint16_t len, uint8_t key, uint16_t* out_len, uint8_t* out_type) {
    if (len == 0 || (data[0] & 0xE0) != 0xA0) return NULL;
    uint8_t vlen = data[0] & 0x1F;
    uint16_t offset = 1;
    uint32_t count = vlen;
    if (vlen == 24) { count = data[1]; offset = 2; }
    else if (vlen == 25) { count = (data[1] << 8) | data[2]; offset = 3; }
    
    for (uint32_t i = 0; i < count; i++) {
        if (offset >= len) break;
        uint8_t k_type = data[offset] & 0xE0;
        uint8_t k_val = data[offset] & 0x1F;
        uint16_t k_len = 1;
        if (k_val == 24) k_len = 2;
        else if (k_val == 25) k_len = 3;
        
        uint32_t current_key = 0;
        if (k_type == 0x00) {
            if (k_len == 1) current_key = k_val;
            else if (k_len == 2) current_key = data[offset+1];
        }
        
        offset += skip_cbor_item(data + offset, len - offset); // skip key
        if (offset >= len) break;
        
        if (current_key == key && k_type == 0x00) {
            uint8_t header = data[offset];
            if (out_type) *out_type = header & 0xE0;
            uint8_t val_vlen = header & 0x1F;
            if (val_vlen == 24) {
                *out_len = data[offset+1];
                return &data[offset+2];
            } else if (val_vlen == 25) {
                *out_len = (data[offset+1] << 8) | data[offset+2];
                return &data[offset+3];
            }
            *out_len = val_vlen;
            return &data[offset+1];
        } else {
            offset += skip_cbor_item(data + offset, len - offset); // skip value
        }
    }
    return NULL;
}

bool get_cbor_map_int(const uint8_t* data, uint16_t len, uint8_t key, uint32_t* out_val) {
    if (len == 0 || (data[0] & 0xE0) != 0xA0) return false;
    uint8_t vlen = data[0] & 0x1F;
    uint16_t offset = 1;
    uint32_t count = vlen;
    if (vlen == 24) { count = data[1]; offset = 2; }
    else if (vlen == 25) { count = (data[1] << 8) | data[2]; offset = 3; }
    
    for (uint32_t i = 0; i < count; i++) {
        if (offset >= len) break;
        uint8_t k_type = data[offset] & 0xE0;
        uint8_t k_val = data[offset] & 0x1F;
        uint16_t k_len = 1;
        if (k_val == 24) k_len = 2;
        else if (k_val == 25) k_len = 3;
        
        uint32_t current_key = 0;
        if (k_type == 0x00) {
            if (k_len == 1) current_key = k_val;
            else if (k_len == 2) current_key = data[offset+1];
        }
        
        offset += skip_cbor_item(data + offset, len - offset);
        if (offset >= len) break;
        
        if (current_key == key && k_type == 0x00) {
            uint8_t header = data[offset];
            uint8_t val_type = header & 0xE0;
            if (val_type != 0x00) return false; // not an integer
            uint8_t val_vlen = header & 0x1F;
            if (val_vlen < 24) {
                *out_val = val_vlen;
                return true;
            } else if (val_vlen == 24) {
                *out_val = data[offset+1];
                return true;
            } else if (val_vlen == 25) {
                *out_val = (data[offset+1] << 8) | data[offset+2];
                return true;
            }
            return false;
        } else {
            offset += skip_cbor_item(data + offset, len - offset);
        }
    }
    return false;
}

const uint8_t* get_cbor_map_item(const uint8_t* data, uint16_t len, uint8_t key, uint16_t* out_len) {
    if (len == 0 || (data[0] & 0xE0) != 0xA0) return NULL;
    uint8_t vlen = data[0] & 0x1F;
    uint16_t offset = 1;
    uint32_t count = vlen;
    if (vlen == 24) { count = data[1]; offset = 2; }
    else if (vlen == 25) { count = (data[1] << 8) | data[2]; offset = 3; }
    
    for (uint32_t i = 0; i < count; i++) {
        if (offset >= len) break;
        uint8_t k_type = data[offset] & 0xE0;
        uint8_t k_val = data[offset] & 0x1F;
        uint16_t k_len = 1;
        if (k_val == 24) k_len = 2;
        else if (k_val == 25) k_len = 3;
        
        uint32_t current_key = 0;
        if (k_type == 0x00) {
            if (k_len == 1) current_key = k_val;
            else if (k_len == 2) current_key = data[offset+1];
        }
        
        offset += skip_cbor_item(data + offset, len - offset);
        if (offset >= len) break;
        
        if (current_key == key && k_type == 0x00) {
            uint16_t item_len = skip_cbor_item(data + offset, len - offset);
            if (out_len) *out_len = item_len;
            return data + offset;
        } else {
            offset += skip_cbor_item(data + offset, len - offset);
        }
    }
}

const uint8_t* get_cbor_map_string(const uint8_t* data, uint16_t len, uint8_t key, uint16_t* out_len) {
    uint8_t val_type = 0;
    const uint8_t* val = get_cbor_map_value(data, len, key, out_len, &val_type);
    if (!val) return NULL;
    if (val_type != 0x40 && val_type != 0x60) return NULL; // Must be bstr or tstr
    return val;
}

const uint8_t* get_cbor_map_neg_value(const uint8_t* data, uint16_t len, uint8_t neg_val, uint16_t* out_len, uint8_t* out_type) {
    if (len == 0 || (data[0] & 0xE0) != 0xA0) return NULL;
    uint8_t vlen = data[0] & 0x1F;
    uint16_t offset = 1;
    uint32_t count = vlen;
    if (vlen == 24) { count = data[1]; offset = 2; }
    else if (vlen == 25) { count = (data[1] << 8) | data[2]; offset = 3; }
    
    for (uint32_t i = 0; i < count; i++) {
        if (offset >= len) break;
        bool match = false;
        if ((data[offset] & 0xE0) == 0x20 && data[offset] == (0x20 | (neg_val - 1))) {
            match = true;
        }
        offset += skip_cbor_item(data + offset, len - offset); // skip key
        if (offset >= len) break;
        
        if (match) {
            uint8_t header = data[offset];
            if (out_type) *out_type = header & 0xE0;
            uint8_t val_vlen = header & 0x1F;
            if (val_vlen == 24) {
                if (out_len) *out_len = data[offset+1];
                return &data[offset+2];
            } else if (val_vlen == 25) {
                if (out_len) *out_len = (data[offset+1] << 8) | data[offset+2];
                return &data[offset+3];
            }
            if (out_len) *out_len = val_vlen;
            return &data[offset+1];
        } else {
            offset += skip_cbor_item(data + offset, len - offset); // skip value
        }
    }
    return NULL;
}

static int ecdsa_sig_to_der(const uint8_t *sig_raw, uint8_t *der) {
    int r_len = 32;
    const uint8_t *r = sig_raw;
    while (r_len > 1 && *r == 0 && (r[1] & 0x80) == 0) { r++; r_len--; }
    int r_pad = (*r & 0x80) ? 1 : 0;

    int s_len = 32;
    const uint8_t *s = sig_raw + 32;
    while (s_len > 1 && *s == 0 && (s[1] & 0x80) == 0) { s++; s_len--; }
    int s_pad = (*s & 0x80) ? 1 : 0;

    int total_len = 2 + r_len + r_pad + 2 + s_len + s_pad;
    
    der[0] = 0x30;
    der[1] = total_len;
    
    der[2] = 0x02;
    der[3] = r_len + r_pad;
    int idx = 4;
    if (r_pad) der[idx++] = 0x00;
    memcpy(&der[idx], r, r_len);
    idx += r_len;
    
    der[idx++] = 0x02;
    der[idx++] = s_len + s_pad;
    if (s_pad) der[idx++] = 0x00;
    memcpy(&der[idx], s, s_len);
    idx += s_len;
    
    return idx;
}

// Shared by getAssertion (0x02) and getNextAssertion (0x08): signs
// authData(37) || cdh(32) with the credential key and encodes the assertion
// response map {1:descriptor, 2:authData, 3:sig, 4:user?, 6:total?}.
// Returns total response length (status byte + CBOR payload).
static uint16_t ga_build_response(uint8_t* resp, const ResidentKey* rk,
                                  const uint8_t* authData37, const uint8_t* cdh32,
                                  uint32_t total) {
    __attribute__((aligned(4))) uint8_t sigHash[32];
    SHA256_CTX sha;
    sha256_init(&sha);
    sha256_update(&sha, authData37, 37);
    sha256_update(&sha, cdh32, 32);
    sha256_final(&sha, sigHash);

    __attribute__((aligned(4))) uint8_t privk[32];
    memcpy(privk, rk->private_key, 32);
    __attribute__((aligned(4))) uint8_t sig[64];
    uECC_set_rng(rng);
    fido2_send_keepalive(g_current_cid, 1);
    uECC_sign(privk, sigHash, 32, sig, uECC_secp256r1());
    fido2_send_keepalive(g_current_cid, 1);

    uint8_t der[72];
    int der_len = ecdsa_sig_to_der(sig, der);

    bool have_user = rk->user_id_len > 0;
    uint8_t map_n = (uint8_t)(3 + (have_user ? 1 : 0) + (total > 1 ? 1 : 0));
    resp[0] = 0x00;
    CborEncoder enc;
    cbor_init(&enc, resp + 1, 1024);
    cbor_encode_map(&enc, map_n);
    cbor_encode_uint(&enc, 1);
    cbor_encode_map(&enc, 2);
    cbor_encode_text_string(&enc, "id");
    cbor_encode_byte_string(&enc, rk->credential_id, 32);
    cbor_encode_text_string(&enc, "type");
    cbor_encode_text_string(&enc, "public-key");
    cbor_encode_uint(&enc, 2);
    cbor_encode_byte_string(&enc, authData37, 37);
    cbor_encode_uint(&enc, 3);
    cbor_encode_byte_string(&enc, der, der_len);
    if (have_user) {
        cbor_encode_uint(&enc, 4);
        cbor_encode_map(&enc, (rk->user_name_len > 0) ? 2 : 1);
        cbor_encode_text_string(&enc, "id");
        cbor_encode_byte_string(&enc, rk->user_id, rk->user_id_len);
        if (rk->user_name_len > 0) {
            cbor_encode_text_string(&enc, "name");
            cbor_encode_text_string_len(&enc, (const char*)rk->user_name, rk->user_name_len);
        }
    }
    if (total > 1) {
        cbor_encode_uint(&enc, 6);
        cbor_encode_uint(&enc, total);
    }
    return (uint16_t)(1 + enc.length);
}

void fido2_process_cbor(uint8_t *req, uint16_t req_len, uint8_t *resp, uint16_t *resp_len, uint32_t cid) {
    if (req_len == 0) {
        resp[0] = 0x01; *resp_len = 1; return;
    }
    
    g_current_cid = cid;

    uint8_t cmd = req[0];
    
    // Reset global state if this is not a clientPin command
    if (cmd != 0x06) {
        // g_pin_session_active = false;
    }
    
    CborEncoder encoder;
    cbor_init(&encoder, resp + 1, 1024); 

    if (cmd == 0x04) { // authenticatorGetInfo
        const PINState* p = pin_load();
        bool pin_set = (p != NULL);
        
        resp[0] = 0x00; 
        cbor_encode_map(&encoder, 10);
        
        cbor_encode_uint(&encoder, 1); // versions
        cbor_encode_array(&encoder, 2);
        cbor_encode_text_string(&encoder, "FIDO_2_0");
        cbor_encode_text_string(&encoder, "FIDO_2_1");
        
        cbor_encode_uint(&encoder, 3); // aaguid
        uint8_t aaguid[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00};
        cbor_encode_byte_string(&encoder, aaguid, 16);
        
        cbor_encode_uint(&encoder, 4); // options
        cbor_encode_map(&encoder, 6);
        cbor_encode_text_string(&encoder, "rk"); cbor_encode_bool(&encoder, 1);
        cbor_encode_text_string(&encoder, "up"); cbor_encode_bool(&encoder, 1);
        cbor_encode_text_string(&encoder, "clientPin"); cbor_encode_bool(&encoder, pin_set);
        cbor_encode_text_string(&encoder, "pinUvAuthToken"); cbor_encode_bool(&encoder, 1);
        // credMgmt MUST be advertised for platforms to use CredentialManagement
        cbor_encode_text_string(&encoder, "credMgmt"); cbor_encode_bool(&encoder, 1);
        cbor_encode_text_string(&encoder, "makeCredUvNotRqd"); cbor_encode_bool(&encoder, 1);
        
        cbor_encode_uint(&encoder, 5); // maxMsgSize
        cbor_encode_uint(&encoder, 1024);
        
        cbor_encode_uint(&encoder, 6); // pinUvAuthProtocols
        cbor_encode_array(&encoder, 2);
        cbor_encode_uint(&encoder, 1);
        cbor_encode_uint(&encoder, 2);
        
        cbor_encode_uint(&encoder, 7); // maxCredentialCountInList
        cbor_encode_uint(&encoder, PASSKEY_NUM_SLOTS);
        
        cbor_encode_uint(&encoder, 8); // maxCredentialIdLength
        cbor_encode_uint(&encoder, 32);
        
        cbor_encode_uint(&encoder, 9); // transports
        cbor_encode_array(&encoder, 1);
        cbor_encode_text_string(&encoder, "usb");
        
        cbor_encode_uint(&encoder, 10); // algorithms
        cbor_encode_array(&encoder, 1);
        cbor_encode_map(&encoder, 2);
        cbor_encode_text_string(&encoder, "type");
        cbor_encode_text_string(&encoder, "public-key");
        cbor_encode_text_string(&encoder, "alg");
        cbor_encode_int(&encoder, -7);
        
        cbor_encode_uint(&encoder, 15); // minPINLength
        cbor_encode_uint(&encoder, 4);
        
        *resp_len = 1 + encoder.length;

    } 
    else if (cmd == 0x01) { // MakeCredential
        // 1. Extract clientDataHash (key 0x01)
        extern uint8_t pin_token[32];
        extern uint16_t pin_token_len;
        extern bool has_pin_token;
        uint16_t cdh_len = 0;
        const uint8_t* cdh = get_cbor_map_string(req + 1, req_len - 1, 0x01, &cdh_len);
        
        // 1b. Check pinUvAuthParam (key 0x08) per CTAP2 spec
        uint8_t flags = 0x41; // UP=1, AT=1 (Attested Credential Data included)
        uint16_t pin_auth_len = 0;
        const uint8_t* pin_auth = get_cbor_map_string(req + 1, req_len - 1, 0x08, &pin_auth_len);

        
        // CTAP2 spec §6.1.1: Empty pinAuth is a probe from the platform.
        // Must respond IMMEDIATELY (no user presence!) so Windows can proceed with PIN flow.
        const PINState* pin_state = pin_load();
        
        if (pin_auth != NULL && pin_auth_len == 0) {
            resp[0] = (pin_state == NULL) ? 0x35 : 0x33;
            *resp_len = 1;
            return;
        }

        // CTAP2 spec: If UV or RK is requested and PIN is set but not provided, fail IMMEDIATELY!
        uint16_t options_map_len = 0;
        const uint8_t* options_map = get_cbor_map_value(req + 1, req_len - 1, 0x07, &options_map_len, NULL);
        if (options_map && !pin_auth) {
            uint16_t search_len = req_len - (options_map - req);
            
            uint16_t uv_val_len = 0;
            const uint8_t* uv_val = find_cbor_string((uint8_t*)options_map, search_len, "uv", &uv_val_len);
            bool uv_req = (uv_val && uv_val_len == 1 && uv_val[0] == 0xF5);
            
            uint16_t rk_val_len = 0;
            const uint8_t* rk_val = find_cbor_string((uint8_t*)options_map, search_len, "rk", &rk_val_len);
            bool rk_req = (rk_val && rk_val_len == 1 && rk_val[0] == 0xF5);
            
            // CTAP2.1 §6.1.2 step 7 semantics:
            // - explicit "uv":true -> platform must do the PIN dance:
            //     PIN set   -> PUAT_REQUIRED (0x36)
            //     no PIN    -> PIN_NOT_SET (0x35) so the platform offers PIN setup
            // - "rk":true alone ONLY requires UV if the device is PROTECTED
            //   by some form of user verification (PIN set). Without a PIN,
            //   registration must proceed (CTAP2.0 behavior).
            if (uv_req) {
                resp[0] = (pin_state == NULL) ? 0x35 : 0x36;
                *resp_len = 1;
                return;
            }
            if (rk_req && pin_state != NULL) {
                resp[0] = 0x36;
                *resp_len = 1;
                return;
            }
        }
        
        extern uint32_t active_pin_protocol;
        
        if (pin_auth) {
            if (has_pin_token && cdh && cdh_len >= 32) {
                uint8_t mac[32];
                hmac_sha256(pin_token, pin_token_len > 0 ? pin_token_len : (active_pin_protocol == 2 ? 32 : 16), cdh, 32, mac);
                
                bool valid = false;
                if (active_pin_protocol == 2 && pin_auth_len == 32) {
                    if (memcmp(mac, pin_auth, 32) == 0) valid = true;
                } else if (active_pin_protocol == 1 && pin_auth_len == 16) {
                    if (memcmp(mac, pin_auth, 16) == 0) valid = true;
                }
                
                if (valid) {
                    flags |= 0x04; // UV=1 - verified!
                } else {
                    resp[0] = 0x33;
                    *resp_len = 1;
                    return;
                }
            } else {
                resp[0] = 0x33;
                *resp_len = 1;
                return;
            }
        }
        
        uint8_t up_status = fido2_wait_for_user_presence(cid);
        if (up_status != 0x00) {
            resp[0] = up_status; // 0x2D KEEPALIVE_CANCEL or 0x2F USER_ACTION_TIMEOUT
            *resp_len = 1;
            return;
        }
        

        // If pin_auth absent and uv not required: proceed without UV
        
        // 2. Extract rp.id (safely from within the rp map)
        uint16_t rp_item_len = 0;
        const uint8_t* rp_item = get_cbor_map_item(req + 1, req_len - 1, 0x02, &rp_item_len);
        uint16_t rp_id_len = 0;
        const uint8_t* rp_id = NULL;
        if (rp_item) {
            rp_id = cbor_map_get_string(rp_item, rp_item_len, "id", &rp_id_len);
        }
        
        // 3. Hash rp.id to get rpIdHash
        uint8_t rpIdHash[32] = {0};
        if (rp_id && rp_id_len > 0) {
            SHA256_CTX sha;
            sha256_init(&sha);
            sha256_update(&sha, rp_id, rp_id_len);
            sha256_final(&sha, rpIdHash);
        }

        // 3b. Check excludeList (key 0x05): if a listed credential already exists
        // on this authenticator for this RP, return CREDENTIAL_EXCLUDED (UP was already collected).
        uint16_t ex_len = 0;
        const uint8_t* ex_item = get_cbor_map_item(req + 1, req_len - 1, 0x05, &ex_len);
        if (ex_item && ex_len > 32) {
            // ex_item points at the array start; ex_len covers the whole array
            for (int j = 0; j + 32 <= ex_len; j++) {
                const ResidentKey* ex = passkey_find_by_cred_id(&ex_item[j]);
                if (ex && memcmp(ex->rp_id_hash, rpIdHash, 32) == 0) {
                    resp[0] = 0x2C; // CTAP2_ERR_CREDENTIAL_EXCLUDED
                    *resp_len = 1;
                    return;
                }
            }
        }

        // 4. Generate Key Pair
        __attribute__((aligned(4))) uint8_t private_key[32];
        __attribute__((aligned(4))) uint8_t public_key[64];
        uECC_set_rng(rng);
        fido2_send_keepalive(cid, 1);
        uECC_make_key(public_key, private_key, uECC_secp256r1());
        fido2_send_keepalive(cid, 1);

        // 4b. Extract user.id & user.name (key 0x03)
        uint16_t user_item_len = 0;
        const uint8_t* user_item = get_cbor_map_item(req + 1, req_len - 1, 0x03, &user_item_len);
        uint16_t user_id_len = 0;
        const uint8_t* user_id = NULL;
        uint16_t user_name_len = 0;
        const uint8_t* user_name = NULL;
        if (user_item) {
            user_id = cbor_map_get_string(user_item, user_item_len, "id", &user_id_len);
            user_name = cbor_map_get_string(user_item, user_item_len, "name", &user_name_len);
            if (!user_name) {
                user_name = cbor_map_get_string(user_item, user_item_len, "displayName", &user_name_len);
            }
        }

        // 4c. Generate random credential_id
        uint8_t credential_id[32];
        rng(credential_id, 32);

        // 4d. Save Passkey to Flash
        if (passkey_save(rpIdHash, rp_id, rp_id_len, user_id, user_id_len, user_name, user_name_len, credential_id, private_key) != 0) {            resp[0] = 0x28; // CTAP2_ERR_KEY_STORE_FULL
            *resp_len = 1;
            return;
        }

        flags |= 0x40; // AT (Attested Credential Data included)

        uint8_t authData[37 + 16 + 2 + 32 + 77];
        memset(authData, 0, sizeof(authData));
        memcpy(authData, rpIdHash, 32);
        authData[32] = flags; 
        // signCount is 0
        
        // Attested Credential Data
        // AAGUID (16 bytes) MUST match GetInfo!
        uint8_t aaguid[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00};
        memcpy(&authData[37], aaguid, 16);
        
        authData[53] = 0;
        authData[54] = 32;
        memcpy(&authData[55], credential_id, 32);
        
        // Encode COSE Key in CBOR directly into authData
        CborEncoder cose;
        cbor_init(&cose, &authData[87], 77);
        cbor_encode_map(&cose, 5);
        cbor_encode_uint(&cose, 1); cbor_encode_uint(&cose, 2); // kty = EC2
        cbor_encode_uint(&cose, 3); cbor_encode_head(&cose, 1, 6); // alg = ES256 (-7)
        cbor_encode_head(&cose, 1, 0); cbor_encode_uint(&cose, 1); // crv = P-256 (-1)
        cbor_encode_head(&cose, 1, 1); cbor_encode_byte_string(&cose, public_key, 32); // x (-2)
        cbor_encode_head(&cose, 1, 2); cbor_encode_byte_string(&cose, public_key + 32, 32); // y (-3)
        
        uint16_t authData_len = 87 + cose.length;


        // 6. Sign authData || clientDataHash
        __attribute__((aligned(4))) uint8_t sigHash[32];
        SHA256_CTX sha;
        sha256_init(&sha);
        sha256_update(&sha, authData, authData_len);
        if (cdh) sha256_update(&sha, cdh, 32);
        sha256_final(&sha, sigHash);

        __attribute__((aligned(4))) uint8_t signature[64];
        fido2_send_keepalive(cid, 1); // 1 = PROCESSING (We finished waiting for UP)
        uECC_sign(private_key, sigHash, sizeof(sigHash), signature, uECC_secp256r1());
        
        uint8_t der_sig[72];
        int der_sig_len = ecdsa_sig_to_der(signature, der_sig);
        
        // 7. Construct CBOR response
        resp[0] = 0x00; 
        cbor_encode_map(&encoder, 3);
        
        cbor_encode_uint(&encoder, 1); // fmt
        cbor_encode_text_string(&encoder, "packed");
        
        cbor_encode_uint(&encoder, 2); // authData
        cbor_encode_byte_string(&encoder, authData, authData_len);
        
        cbor_encode_uint(&encoder, 3); // attStmt
        cbor_encode_map(&encoder, 2);
        
        cbor_encode_text_string(&encoder, "alg");
        cbor_encode_int(&encoder, -7); // ES256
        
        cbor_encode_text_string(&encoder, "sig");
        cbor_encode_byte_string(&encoder, der_sig, der_sig_len);
        
        *resp_len = 1 + encoder.length;

    } else if (cmd == 0x02) { // GetAssertion
        // 1. Extract rp.id (key 0x01)
        uint16_t rp_id_len = 0;
        const uint8_t* rp_id = get_cbor_map_value(req + 1, req_len - 1, 0x01, &rp_id_len, NULL);
        
        // 2. Extract clientDataHash (key 0x02)
        uint16_t cdh_len = 0;
        const uint8_t* cdh = get_cbor_map_string(req + 1, req_len - 1, 0x02, &cdh_len);

        // 3. Extract allowList (key 0x03)
        uint16_t allow_len = 0;
        uint8_t allow_type = 0;
        const uint8_t* allowList = get_cbor_map_value(req + 1, req_len - 1, 0x03, &allow_len, &allow_type);
        
        uint8_t rpIdHash[32] = {0};
        if (rp_id && rp_id_len > 0) {
            SHA256_CTX sha;
            sha256_init(&sha);
            sha256_update(&sha, rp_id, rp_id_len);
            sha256_final(&sha, rpIdHash);
        }

        const ResidentKey* rk = NULL;
        const uint8_t* credential_id = NULL;
        uint32_t ga_total = 1; // credentials available for this RP (for key 6)

        // NOTE: an EMPTY allowList must be treated exactly like an absent one
        // (CTAP2.1 §6.2.2 step 7): locate discoverable credentials for the RP.
        // Windows Hello and Chrome send empty arrays during passkey login!
        if (!allowList || (allow_type == 0x80 && allow_len == 0)) {
            // Passkey Auth! Search by RP ID Hash (index 0; 0x08 walks the rest)
            uint32_t n_creds = passkey_count_for_rp(rpIdHash);
            rk = passkey_get_by_rp_index(rpIdHash, 0);
            if (!rk || n_creds == 0) {
                resp[0] = 0x2E; *resp_len = 1; return; // CTAP2_ERR_NO_CREDENTIALS
            }
            memcpy(g_ga_rp_hash, rpIdHash, 32);
            g_ga_count = n_creds;
            g_ga_idx = 0;
            ga_total = n_creds;
            extern uint8_t g_ga_cdh[32];
            if (cdh && cdh_len >= 32) memcpy(g_ga_cdh, cdh, 32);
            else memset(g_ga_cdh, 0, 32);
            credential_id = rk->credential_id;
        } else {
            g_ga_count = 0; // allowList results are not walkable via 0x08
            // 2FA Auth! We have a non-empty allowList.
            // Find a credential in flash that matches rpIdHash AND whose credential_id is present anywhere in the request packet!
            // Since it's 256-bit secure random, collisions are impossible.
            uint32_t addr = PASSKEY_FLASH_START;
            while (addr < PASSKEY_FLASH_END) {
                ResidentKey* curr = (ResidentKey*)addr;
                if (curr->magic == PASSKEY_MAGIC && memcmp(curr->rp_id_hash, rpIdHash, 32) == 0) {
                    // Sliding window search through the entire request buffer for the 32-byte credential_id
                    for (int j = 0; j <= req_len - 32; j++) {
                        if (memcmp(&req[j], curr->credential_id, 32) == 0) {
                            rk = curr;
                            break;
                        }
                    }
                }
                if (rk) break;
                addr += PASSKEY_PAGE_SIZE;
            }
            
            if (!rk) {
                resp[0] = 0x2E; *resp_len = 1; return; // CTAP2_ERR_NO_CREDENTIALS
            }
            credential_id = rk->credential_id;
        }
        
        uint8_t flags = 0x01; // UP=1
        uint16_t pin_auth_len = 0;
        const uint8_t* pin_auth = get_cbor_map_string(req + 1, req_len - 1, 0x06, &pin_auth_len); // pinAuth is 0x06 for GetAssertion

        extern uint32_t active_pin_protocol;
        extern uint16_t pin_token_len;
        
        if (pin_auth) {
            if (has_pin_token && cdh && cdh_len >= 32) {
                uint8_t mac[32];
                hmac_sha256(pin_token, pin_token_len > 0 ? pin_token_len : (active_pin_protocol == 2 ? 32 : 16), cdh, 32, mac); 
                bool valid = false;
                if (active_pin_protocol == 2 && pin_auth_len == 32) {
                    if (memcmp(mac, pin_auth, 32) == 0) valid = true;
                } else if (active_pin_protocol == 1 && pin_auth_len == 16) {
                    if (memcmp(mac, pin_auth, 16) == 0) valid = true;
                }
                
                if (valid) {
                    flags |= 0x04; // UV=1
                } else {
                    resp[0] = 0x33; *resp_len = 1; return;
                }
            } else {
                resp[0] = 0x33; *resp_len = 1; return;
            }
        }
        
        // Check options (key 0x05 for GetAssertion): "up": false means pre-flight
        // probe (platform checks credential existence WITHOUT user presence),
        // and "uv": true without a token requires the PIN flow.
        uint16_t options_map_len = 0;
        const uint8_t* options_map = get_cbor_map_value(req + 1, req_len - 1, 0x05, &options_map_len, NULL);
        bool up_required = true;
        if (options_map) {
            uint16_t search_len = req_len - (uint16_t)(options_map - req);
            
            if (!pin_auth) {
                uint16_t uv_val_len = 0;
                const uint8_t* uv_val = find_cbor_string((uint8_t*)options_map, search_len, "uv", &uv_val_len);
                if (uv_val && uv_val_len == 1 && uv_val[0] == 0xF5) { // 0xF5 is CBOR True
                    const PINState* pin_state = pin_load();
                    resp[0] = (pin_state == NULL) ? 0x35 : 0x36; // PIN_NOT_SET : PUAT_REQUIRED
                    *resp_len = 1; 
                    return;
                }
            }
            
            uint16_t up_val_len = 0;
            const uint8_t* up_val = find_cbor_string((uint8_t*)options_map, search_len, "up", &up_val_len);
            if (up_val && up_val_len == 1 && up_val[0] == 0xF4) { // 0xF4 is CBOR False
                up_required = false;
            }
        }
        
        if (up_required) {
            uint8_t up_status = fido2_wait_for_user_presence(cid);
            if (up_status != 0x00) {
                resp[0] = up_status; // 0x2D KEEPALIVE_CANCEL or 0x2F USER_ACTION_TIMEOUT
                *resp_len = 1;
                return;
            }
        } else {
            flags &= ~0x01; // UP=0: pre-flight response must not claim user presence
        }

        uint8_t authData[37];
        memset(authData, 0, sizeof(authData));
        memcpy(authData, rpIdHash, 32);
        authData[32] = flags; 
        // signCount is 0
        
        uint8_t cdh_buf[32] = {0};
        if (cdh && cdh_len == 32) memcpy(cdh_buf, cdh, 32);

        *resp_len = ga_build_response(resp, rk, authData, cdh_buf, ga_total);

    } else if (cmd == 0x08) { // authenticatorGetNextAssertion (§6.3)
        if (g_ga_count == 0 || g_ga_idx + 1 >= g_ga_count) {
            resp[0] = 0x2E; *resp_len = 1; return; // list exhausted / no prior getAssertion
        }
        g_ga_idx++;
        const ResidentKey* nrk = passkey_get_by_rp_index(g_ga_rp_hash, g_ga_idx);
        if (!nrk) {
            resp[0] = 0x2E; *resp_len = 1; return;
        }

        uint8_t up_status = fido2_wait_for_user_presence(cid);
        if (up_status != 0x00) {
            resp[0] = up_status; *resp_len = 1; return;
        }

        uint8_t nauthData[37];
        memset(nauthData, 0, sizeof(nauthData));
        memcpy(nauthData, g_ga_rp_hash, 32);
        nauthData[32] = 0x01; // UP=1

        *resp_len = ga_build_response(resp, nrk, nauthData, g_ga_cdh, g_ga_count);

    } else if (cmd == 0x06) { // authenticatorClientPIN
        process_client_pin(req + 1, req_len - 1, resp, resp_len, cid);
    } else if (cmd == 0x0A) { // authenticatorCredentialManagement
        // subCommand is an INTEGER: must be parsed with get_cbor_map_int.
        // get_cbor_map_value returns a pointer PAST small int values (bstr-style
        // pointer arithmetic) -> reading *ptr there gives garbage.
        uint32_t sub_cmd_u = 0;
        bool has_sub_cmd = get_cbor_map_int(req + 1, req_len - 1, 0x01, &sub_cmd_u);
        uint8_t sub_cmd = has_sub_cmd ? (uint8_t)sub_cmd_u : 0;

        extern bool has_pin_token;
        extern uint8_t pin_token[32];
        extern uint16_t pin_token_len;
        const PINState* p_state = pin_load();

        // CTAP2.1 §6.8: when the authenticator is protected by a PIN, EVERY
        // CredentialManagement subcommand (including getCredsMetadata) must
        // carry a valid pinUvAuthParam computed as:
        //   authenticate(pinUvAuthToken, subCommandByte [|| subCommandParams raw])
        // (params appended only for subCommands 0x04/0x05/0x06).
        if (p_state != NULL) {
            extern uint32_t active_pin_protocol;
            uint32_t cm_proto = active_pin_protocol;
            get_cbor_map_int(req + 1, req_len - 1, 0x03, &cm_proto); // pinUvAuthProtocol is key 0x03 in CM

            uint8_t prf[1 + 1024];
            prf[0] = sub_cmd;
            uint16_t prf_len = 1;
            if (sub_cmd == 0x04 || sub_cmd == 0x05 || sub_cmd == 0x06) {
                uint16_t item_len = 0;
                const uint8_t* item = get_cbor_map_item(req + 1, req_len - 1, 0x02, &item_len);
                if (item && item_len > 0 && item_len <= 1024) {
                    memcpy(prf + 1, item, item_len);
                    prf_len = (uint16_t)(1 + item_len);
                }
            }

            uint16_t cm_pin_auth_len = 0;
            const uint8_t* cm_pin_auth = get_cbor_map_string(req + 1, req_len - 1, 0x04, &cm_pin_auth_len);
            uint16_t expected = (cm_proto == 2) ? 32 : 16;

            if (!has_pin_token || !cm_pin_auth || cm_pin_auth_len != expected) {
                resp[0] = 0x33; // CTAP2_ERR_PIN_AUTH_INVALID
                *resp_len = 1;
                return;
            }
            uint8_t mac[32];
            hmac_sha256(pin_token, pin_token_len > 0 ? pin_token_len : 32, prf, prf_len, mac);
            if (memcmp(mac, cm_pin_auth, expected) != 0) {
                resp[0] = 0x33;
                *resp_len = 1;
                return;
            }
        }

        uint16_t params_map_len = 0;
        const uint8_t* params_map = get_cbor_map_value(req + 1, req_len - 1, 0x02, &params_map_len, NULL);

        resp[0] = 0x00; // CTAP2_OK

        if (sub_cmd == 0x01) { // getCredsMetadata
            cbor_encode_map(&encoder, 2);
            cbor_encode_uint(&encoder, 1); // existingResidentCredentialsCount
            cbor_encode_uint(&encoder, passkey_count_all());
            cbor_encode_uint(&encoder, 2); // maxPossibleResidentCredentialsCount
            cbor_encode_uint(&encoder, PASSKEY_NUM_SLOTS);
            *resp_len = 1 + encoder.length;
        }
        else if (sub_cmd == 0x02 || sub_cmd == 0x03) { // enumerateRPs Begin / GetNext
            if (sub_cmd == 0x02) {
                g_enum_rp_idx = 0;
            } else {
                g_enum_rp_idx++;
            }
            uint32_t total_rps = passkey_count_unique_rps();
            if (total_rps == 0 || g_enum_rp_idx >= total_rps) {
                resp[0] = 0x2E; *resp_len = 1; return;
            }
            passkey_get_unique_rp_hash(g_enum_rp_idx, g_enum_rp_hash);

            // Use the REAL stored rp.id (first credential of this RP)
            const ResidentKey* rpk0 = passkey_get_by_rp_index(g_enum_rp_hash, 0);
            const char* rp_display = (rpk0 && rpk0->rp_id_len > 0)
                                     ? (const char*)rpk0->rp_id : "Passkey RP";
            uint8_t rp_display_len = (rpk0 && rpk0->rp_id_len > 0)
                                     ? rpk0->rp_id_len : (uint8_t)strlen(rp_display);

            cbor_encode_map(&encoder, (sub_cmd == 0x02) ? 3 : 2);
            cbor_encode_uint(&encoder, 1); // rp
            cbor_encode_map(&encoder, 2);
            cbor_encode_text_string(&encoder, "id");
            cbor_encode_text_string_len(&encoder, rp_display, rp_display_len);
            cbor_encode_text_string(&encoder, "name");
            cbor_encode_text_string_len(&encoder, rp_display, rp_display_len);
            
            cbor_encode_uint(&encoder, 2); // rpIDHash
            cbor_encode_byte_string(&encoder, g_enum_rp_hash, 32);

            if (sub_cmd == 0x02) {
                cbor_encode_uint(&encoder, 3); // totalRPs
                cbor_encode_uint(&encoder, total_rps);
            }
            *resp_len = 1 + encoder.length;
        }
        else if (sub_cmd == 0x04 || sub_cmd == 0x05) { // enumerateCredentials Begin / GetNext
            if (sub_cmd == 0x04) {
                uint16_t rph_len = 0;
                const uint8_t* rph = NULL;
                // get_cbor_map_item returns the item START (correct for nested maps;
                // get_cbor_map_value skips the container header -> broken nesting)
                uint16_t pm_len = 0;
                const uint8_t* pm = get_cbor_map_item(req + 1, req_len - 1, 0x02, &pm_len);
                if (pm) {
                    rph = get_cbor_map_string(pm, pm_len, 0x01, &rph_len);
                }
                if (rph && rph_len >= 32) {
                    memcpy(g_enum_rp_hash, rph, 32);
                }
                g_enum_cred_idx = 0;
            } else {
                g_enum_cred_idx++;
            }

            uint32_t total_creds = passkey_count_for_rp(g_enum_rp_hash);
            const ResidentKey* k = passkey_get_by_rp_index(g_enum_rp_hash, g_enum_cred_idx);
            if (!k || total_creds == 0 || g_enum_cred_idx >= total_creds) {
                resp[0] = 0x2E; *resp_len = 1; return;
            }

            cbor_encode_map(&encoder, (sub_cmd == 0x04) ? 3 : 2);
            cbor_encode_uint(&encoder, 1); // user
            cbor_encode_map(&encoder, 2);
            cbor_encode_text_string(&encoder, "id");
            cbor_encode_byte_string(&encoder, k->user_id, k->user_id_len);
            cbor_encode_text_string(&encoder, "name");
            if (k->user_name_len > 0) {
                cbor_encode_text_string_len(&encoder, (const char*)k->user_name, k->user_name_len);
            } else {
                cbor_encode_text_string(&encoder, "Passkey Account");
            }

            cbor_encode_uint(&encoder, 2); // credentialId
            cbor_encode_map(&encoder, 2);
            cbor_encode_text_string(&encoder, "id");
            cbor_encode_byte_string(&encoder, k->credential_id, 32);
            cbor_encode_text_string(&encoder, "type");
            cbor_encode_text_string(&encoder, "public-key");

            if (sub_cmd == 0x04) {
                cbor_encode_uint(&encoder, 3); // totalCredentials
                cbor_encode_uint(&encoder, total_creds);
            }
            *resp_len = 1 + encoder.length;
        }
        else if (sub_cmd == 0x06) { // deleteCredential
            const uint8_t* target_cred_id = NULL;
            uint16_t target_cred_len = 0;

            uint16_t pm_len = 0;
            const uint8_t* pm = get_cbor_map_item(req + 1, req_len - 1, 0x02, &pm_len);
            if (pm) {
                uint16_t cm_len = 0;
                const uint8_t* cm = get_cbor_map_item(pm, pm_len, 0x02, &cm_len);
                if (cm) {
                    target_cred_id = get_cbor_map_string(cm, cm_len, 0x01, &target_cred_len);
                }
            }

            if (target_cred_id && target_cred_len >= 32) {
                if (passkey_delete_by_cred_id(target_cred_id) != 0) {
                    resp[0] = 0x2E; // CTAP2_ERR_NO_CREDENTIALS (credential not found)
                    *resp_len = 1;
                    return;
                }
            } else {
                resp[0] = 0x2E;
                *resp_len = 1;
                return;
            }
            resp[0] = 0x00;
            *resp_len = 1;
        }
        else {
            resp[0] = 0x01; *resp_len = 1;
        }
    } else if (cmd == 0x07) { // authenticatorReset
        // Must be received within 10 seconds of power up
        if (SysTick->CNT > (uint64_t)48000000 * 10) {
            resp[0] = 0x30; // CTAP2_ERR_NOT_ALLOWED
            *resp_len = 1;
            return;
        }

        uint8_t up_status = fido2_wait_for_user_presence(cid);
        if (up_status != 0x00) {
            resp[0] = up_status; // 0x2D KEEPALIVE_CANCEL or 0x2F USER_ACTION_TIMEOUT
            *resp_len = 1;
            return;
        }
        
        flash_factory_reset();
        resp[0] = 0x00; // CTAP2_OK
        *resp_len = 1;
    } else if (cmd == 0x55) { // touch ADC debug (val + boot baseline)
        init_touch_adc(); // Ensure ADC is initialized
        uint32_t val = read_touch_pa2();
        resp[0] = 0x00;
        resp[1] = (val >> 24) & 0xFF;
        resp[2] = (val >> 16) & 0xFF;
        resp[3] = (val >> 8) & 0xFF;
        resp[4] = val & 0xFF;
        resp[5] = (touch_baseline >> 24) & 0xFF;
        resp[6] = (touch_baseline >> 16) & 0xFF;
        resp[7] = (touch_baseline >> 8) & 0xFF;
        resp[8] = touch_baseline & 0xFF;
        *resp_len = 9;
    } else {
        resp[0] = 0x01; // CTAP2_ERR_INVALID_COMMAND
        *resp_len = 1;
    }
}
