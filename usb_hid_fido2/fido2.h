#ifndef FIDO2_H
#define FIDO2_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Handle CTAP2 commands
const uint8_t* get_cbor_map_value(const uint8_t* data, uint16_t len, uint8_t key, uint16_t* out_len, uint8_t* out_type);
bool get_cbor_map_int(const uint8_t* data, uint16_t len, uint8_t key, uint32_t* out_val);
const uint8_t* get_cbor_map_item(const uint8_t* data, uint16_t len, uint8_t key, uint16_t* out_len);
const uint8_t* get_cbor_map_string(const uint8_t* data, uint16_t len, uint8_t key, uint16_t* out_len);
const uint8_t* get_cbor_map_neg_value(const uint8_t* data, uint16_t len, uint8_t neg_val, uint16_t* out_len, uint8_t* out_type);
void fido2_process_cbor(uint8_t *req, uint16_t req_len, uint8_t *resp, uint16_t *resp_len, uint32_t cid);

// User presence check (touch). Returns 0x00 on success, 0x2D on cancel, 0x2F on timeout.
uint8_t fido2_wait_for_user_presence(uint32_t cid);

// Implemented in main.c to send USB keepalive
void fido2_send_keepalive(uint32_t cid, uint8_t status);

#endif
