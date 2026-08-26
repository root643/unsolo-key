#ifndef CBOR_H
#define CBOR_H

#include <stdint.h>
#include <stddef.h>

// Minimal CBOR encoder for FIDO2
// Supports Map, Array, Text String, Byte String, Unsigned Integer, Boolean

typedef struct {
    uint8_t *buffer;
    size_t length;
    size_t capacity;
} CborEncoder;

void cbor_init(CborEncoder *encoder, uint8_t *buffer, size_t capacity);
void cbor_encode_head(CborEncoder *encoder, uint8_t major_type, uint32_t val);
void cbor_encode_uint(CborEncoder *encoder, uint32_t value);
void cbor_encode_int(CborEncoder *encoder, int32_t value);
void cbor_encode_bool(CborEncoder *encoder, uint8_t value);
void cbor_encode_text_string(CborEncoder *encoder, const char *str);
void cbor_encode_text_string_len(CborEncoder *encoder, const char *str, size_t len);
void cbor_encode_byte_string(CborEncoder *encoder, const uint8_t *data, size_t len);
void cbor_encode_map(CborEncoder *encoder, size_t num_pairs);
void cbor_encode_array(CborEncoder *encoder, size_t num_elements);

#endif
