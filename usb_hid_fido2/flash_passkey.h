#ifndef FLASH_PASSKEY_H
#define FLASH_PASSKEY_H

#include "ch32fun.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define PIN_FLASH_ADDR      0x0800F700  // Last 256-byte page
// Firmware ends ~0xF19C; storage at 0xF200 (5 slots)
#define PASSKEY_FLASH_START 0x0800F200
#define PASSKEY_FLASH_END   0x0800F700  // 5 pages = 5 credential slots
#define PASSKEY_MAGIC       0xF1D0F1D0
#define PASSKEY_PAGE_SIZE   256
#define PASSKEY_NUM_SLOTS   ((PASSKEY_FLASH_END - PASSKEY_FLASH_START) / PASSKEY_PAGE_SIZE)

typedef struct {
    uint32_t magic; // 0x50494E50 (PINP)
    uint8_t pin_hash[16];
    uint8_t retries;
    uint8_t padding[235]; // Align to 256 bytes
} PINState;

typedef struct {
    uint32_t magic;
    uint8_t rp_id_hash[32];
    uint8_t user_id_len;
    uint8_t user_id[64];
    uint8_t credential_id[32];
    uint8_t private_key[32];
    uint8_t user_name_len;
    uint8_t user_name[32];
    uint8_t rp_id_len;
    uint8_t rp_id[32];
    uint8_t padding[25]; // Align to 256 bytes
} ResidentKey;

void flash_unlock();
void flash_lock();
void flash_erase_page(uint32_t addr);
void flash_program_halfword(uint32_t addr, uint16_t data);
void flash_factory_reset();

int passkey_save(const uint8_t* rp_id_hash, const uint8_t* rp_id, uint8_t rp_id_len, const uint8_t* user_id, uint8_t user_id_len, const uint8_t* user_name, uint8_t user_name_len, const uint8_t* credential_id, const uint8_t* private_key);
const ResidentKey* passkey_find_by_rp(const uint8_t* rp_id_hash);
const ResidentKey* passkey_find_by_cred_id(const uint8_t* credential_id);
int passkey_delete_by_cred_id(const uint8_t* credential_id);

uint32_t passkey_count_all();
uint32_t passkey_count_unique_rps();
int passkey_get_unique_rp_hash(uint32_t target_index, uint8_t* out_rp_id_hash);
uint32_t passkey_count_for_rp(const uint8_t* rp_id_hash);
const ResidentKey* passkey_get_by_rp_index(const uint8_t* rp_id_hash, uint32_t target_index);

void pin_save(const uint8_t* pin_hash);
const PINState* pin_load();
void pin_decrement_retries();
void pin_reset_retries();

#endif
