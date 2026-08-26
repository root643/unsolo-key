#include "cbor.h"
#include <string.h>

void cbor_init(CborEncoder *encoder, uint8_t *buffer, size_t capacity) {
    encoder->buffer = buffer;
    encoder->length = 0;
    encoder->capacity = capacity;
}

void cbor_encode_head(CborEncoder *encoder, uint8_t major_type, uint32_t val) {
    if (encoder->length >= encoder->capacity) return;
    
    if (val < 24) {
        encoder->buffer[encoder->length++] = (major_type << 5) | val;
    } else if (val <= 0xFF) {
        if (encoder->length + 2 > encoder->capacity) return;
        encoder->buffer[encoder->length++] = (major_type << 5) | 24;
        encoder->buffer[encoder->length++] = val;
    } else if (val <= 0xFFFF) {
        if (encoder->length + 3 > encoder->capacity) return;
        encoder->buffer[encoder->length++] = (major_type << 5) | 25;
        encoder->buffer[encoder->length++] = (val >> 8) & 0xFF;
        encoder->buffer[encoder->length++] = val & 0xFF;
    } else {
        if (encoder->length + 5 > encoder->capacity) return;
        encoder->buffer[encoder->length++] = (major_type << 5) | 26;
        encoder->buffer[encoder->length++] = (val >> 24) & 0xFF;
        encoder->buffer[encoder->length++] = (val >> 16) & 0xFF;
        encoder->buffer[encoder->length++] = (val >> 8) & 0xFF;
        encoder->buffer[encoder->length++] = val & 0xFF;
    }
}

void cbor_encode_uint(CborEncoder *encoder, uint32_t value) {
    cbor_encode_head(encoder, 0, value);
}

void cbor_encode_int(CborEncoder *encoder, int32_t value) {
    if (value >= 0) {
        cbor_encode_head(encoder, 0, value);
    } else {
        cbor_encode_head(encoder, 1, -1 - value);
    }
}

void cbor_encode_bool(CborEncoder *encoder, uint8_t value) {
    if (encoder->length >= encoder->capacity) return;
    encoder->buffer[encoder->length++] = value ? 0xF5 : 0xF4;
}

void cbor_encode_text_string(CborEncoder *encoder, const char *str) {
    size_t len = strlen(str);
    cbor_encode_text_string_len(encoder, str, len);
}

void cbor_encode_text_string_len(CborEncoder *encoder, const char *str, size_t len) {
    cbor_encode_head(encoder, 3, (uint32_t)len);
    if (encoder->length + len > encoder->capacity) return;
    memcpy(&encoder->buffer[encoder->length], str, len);
    encoder->length += len;
}

void cbor_encode_byte_string(CborEncoder *encoder, const uint8_t *data, size_t len) {
    cbor_encode_head(encoder, 2, (uint32_t)len);
    if (encoder->length + len > encoder->capacity) return;
    memcpy(&encoder->buffer[encoder->length], data, len);
    encoder->length += len;
}

void cbor_encode_map(CborEncoder *encoder, size_t num_pairs) {
    cbor_encode_head(encoder, 5, (uint32_t)num_pairs);
}

void cbor_encode_array(CborEncoder *encoder, size_t num_elements) {
    cbor_encode_head(encoder, 4, (uint32_t)num_elements);
}
