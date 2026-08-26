#ifndef PIN_H
#define PIN_H

#include <stdint.h>
#include <stdbool.h>

extern uint8_t pin_shared_secret[32];
extern uint8_t pin_token[32];
extern bool has_pin_token;

extern int rng(uint8_t *dest, unsigned size);
const uint8_t* get_cbor_map_value(const uint8_t* data, uint16_t len, uint8_t key, uint16_t* out_len, uint8_t* out_type);
uint16_t skip_cbor_item(const uint8_t* data, uint16_t len);

void process_client_pin(const uint8_t* req, uint16_t req_len, uint8_t* resp, uint16_t* resp_len, uint32_t cid);

#endif
