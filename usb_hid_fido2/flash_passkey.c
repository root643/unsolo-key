#include "flash_passkey.h"

#define CR_PAGE_PG                 ((uint32_t)0x00010000)
#define CR_PAGE_ER                 ((uint32_t)0x00020000)
#define CR_STRT_Set                ((uint32_t)0x00000040)
#define CR_BUF_RST                 ((uint32_t)0x00080000)
#define FLASH_CTLR_BUF_LOAD        ((uint32_t)0x00040000)

void flash_unlock() {
    __disable_irq();
    FLASH->KEYR = FLASH_KEY1;
    FLASH->KEYR = FLASH_KEY2;
    FLASH->MODEKEYR = FLASH_KEY1;
    FLASH->MODEKEYR = FLASH_KEY2;
}

void flash_lock() {
    FLASH->CTLR |= FLASH_CTLR_LOCK;
    __enable_irq();
}

void flash_erase_page(uint32_t addr) {
    while(FLASH->STATR & FLASH_FLAG_BSY);
    FLASH->CTLR = CR_PAGE_ER;
    FLASH->ADDR = addr;
    FLASH->CTLR = CR_STRT_Set | CR_PAGE_ER;
    while(FLASH->STATR & FLASH_FLAG_BSY);
}

void flash_program_64bytes(uint32_t addr, uint32_t* data) {
    while(FLASH->STATR & FLASH_FLAG_BSY);
    
    // Clear buffer and prep for flashing
    FLASH->CTLR = CR_PAGE_PG;
    FLASH->CTLR = CR_BUF_RST | CR_PAGE_PG;
    FLASH->ADDR = addr;
    while(FLASH->STATR & FLASH_FLAG_BSY);
    
    uint32_t* dst = (uint32_t*)addr;
    for(int i = 0; i < 16; i++) {
        dst[i] = data[i];
        FLASH->CTLR = CR_PAGE_PG | FLASH_CTLR_BUF_LOAD;
        while(FLASH->STATR & FLASH_FLAG_BSY);
    }
    
    // Actually write the flash out
    FLASH->CTLR = CR_PAGE_PG | CR_STRT_Set;
    while(FLASH->STATR & FLASH_FLAG_BSY);
}

void flash_factory_reset() {
    flash_unlock();
    uint32_t addr = PASSKEY_FLASH_START;
    while (addr <= PIN_FLASH_ADDR) { // Include PIN page
        flash_erase_page(addr);
        addr += PASSKEY_PAGE_SIZE;
    }
}

int passkey_save(const uint8_t* rp_id_hash, const uint8_t* rp_id, uint8_t rp_id_len, const uint8_t* user_id, uint8_t user_id_len, const uint8_t* user_name, uint8_t user_name_len, const uint8_t* credential_id, const uint8_t* private_key) {
    // 1. Find empty slot; prefer replacing an existing entry of the SAME RP+user
    // (re-registration of the same account must not consume extra slots)
    uint32_t addr = PASSKEY_FLASH_START;
    ResidentKey* slot = NULL;
    while (addr < PASSKEY_FLASH_END) {
        ResidentKey* key = (ResidentKey*)addr;
        if (key->magic == 0xFFFFFFFF) { // Empty Flash
            if (!slot) slot = key;
        } else if (key->magic == PASSKEY_MAGIC &&
                   memcmp(key->rp_id_hash, rp_id_hash, 32) == 0 &&
                   key->user_id_len == user_id_len &&
                   memcmp(key->user_id, user_id, user_id_len) == 0) {
            slot = key; // same account: replace in place
            break;
        }
        addr += PASSKEY_PAGE_SIZE;
    }
    
    if (!slot) return -1; // No space left!
    
    // 2. Prepare struct in RAM
    ResidentKey new_key;
    memset(&new_key, 0xFF, sizeof(ResidentKey));
    new_key.magic = PASSKEY_MAGIC;
    memcpy(new_key.rp_id_hash, rp_id_hash, 32);
    if (rp_id_len > 32) rp_id_len = 32;
    new_key.rp_id_len = rp_id_len;
    if (rp_id_len > 0) memcpy(new_key.rp_id, rp_id, rp_id_len);
    if (user_id_len > 64) user_id_len = 64;
    new_key.user_id_len = user_id_len;
    if (user_id_len > 0) memcpy(new_key.user_id, user_id, user_id_len);
    if (user_name_len > 32) user_name_len = 32;
    new_key.user_name_len = user_name_len;
    if (user_name_len > 0) memcpy(new_key.user_name, user_name, user_name_len);
    memcpy(new_key.credential_id, credential_id, 32);
    memcpy(new_key.private_key, private_key, 32);
    
    // 3. Write to Flash
    flash_unlock();
    
    // Erase page just in case
    flash_erase_page((uint32_t)slot);
    
    // Write struct in 64-byte chunks
    uint32_t* src = (uint32_t*)&new_key;
    uint32_t dst = (uint32_t)slot;
    for (int i = 0; i < sizeof(ResidentKey)/64; i++) {
        flash_program_64bytes(dst, src);
        dst += 64;
        src += 16;
    }
    
    flash_lock();
    return 0; // Success
}

const ResidentKey* passkey_find_by_rp(const uint8_t* rp_id_hash) {
    uint32_t addr = PASSKEY_FLASH_START;
    while (addr < PASSKEY_FLASH_END) {
        ResidentKey* key = (ResidentKey*)addr;
        if (key->magic == PASSKEY_MAGIC) {
            if (memcmp(key->rp_id_hash, rp_id_hash, 32) == 0) {
                return key;
            }
        }
        addr += PASSKEY_PAGE_SIZE;
    }
    return NULL;
}

const ResidentKey* passkey_find_by_cred_id(const uint8_t* credential_id) {
    uint32_t addr = PASSKEY_FLASH_START;
    while (addr < PASSKEY_FLASH_END) {
        ResidentKey* key = (ResidentKey*)addr;
        if (key->magic == PASSKEY_MAGIC) {
            if (memcmp(key->credential_id, credential_id, 32) == 0) {
                return key;
            }
        }
        addr += PASSKEY_PAGE_SIZE;
    }
    return NULL;
}

void pin_save(const uint8_t* pin_hash) {
    flash_unlock();
    flash_erase_page(PIN_FLASH_ADDR);
    
    PINState p;
    memset(&p, 0, sizeof(p));
    p.magic = 0x50494E50;
    memcpy(p.pin_hash, pin_hash, 16);
    p.retries = 8;
    
    uint32_t* src = (uint32_t*)&p;
    uint32_t dst = PIN_FLASH_ADDR;
    for (int i = 0; i < sizeof(PINState)/64; i++) {
        flash_program_64bytes(dst, src);
        dst += 64;
        src += 16;
    }
    flash_lock();
}

const PINState* pin_load() {
    PINState* p = (PINState*)PIN_FLASH_ADDR;
    if (p->magic == 0x50494E50) return p;
    return NULL;
}

void pin_decrement_retries() {
    const PINState* p = pin_load();
    if (!p) return;
    uint8_t current_retries = p->retries;
    if (current_retries > 0) current_retries--;
    
    PINState copy;
    memcpy(&copy, p, sizeof(PINState));
    copy.retries = current_retries;
    
    flash_unlock();
    flash_erase_page(PIN_FLASH_ADDR);
    uint32_t* src = (uint32_t*)&copy;
    uint32_t dst = PIN_FLASH_ADDR;
    for (int i = 0; i < sizeof(PINState)/64; i++) {
        flash_program_64bytes(dst, src);
        dst += 64;
        src += 16;
    }
    flash_lock();
}

void pin_reset_retries() {
    const PINState* p = pin_load();
    if (!p) return;
    
    PINState copy;
    memcpy(&copy, p, sizeof(PINState));
    copy.retries = 8;
    
    flash_unlock();
    flash_erase_page(PIN_FLASH_ADDR);
    uint32_t* src = (uint32_t*)&copy;
    uint32_t dst = PIN_FLASH_ADDR;
    for (int i = 0; i < sizeof(PINState)/64; i++) {
        flash_program_64bytes(dst, src);
        dst += 64;
        src += 16;
    }
    flash_lock();
}

uint32_t passkey_count_all() {
    uint32_t count = 0;
    uint32_t addr = PASSKEY_FLASH_START;
    while (addr < PASSKEY_FLASH_END) {
        ResidentKey* key = (ResidentKey*)addr;
        if (key->magic == PASSKEY_MAGIC) count++;
        addr += PASSKEY_PAGE_SIZE;
    }
    return count;
}

uint32_t passkey_count_unique_rps() {
    uint32_t count = 0;
    uint32_t addr = PASSKEY_FLASH_START;
    while (addr < PASSKEY_FLASH_END) {
        ResidentKey* key = (ResidentKey*)addr;
        if (key->magic == PASSKEY_MAGIC) {
            bool unique = true;
            uint32_t check_addr = PASSKEY_FLASH_START;
            while (check_addr < addr) {
                ResidentKey* check_key = (ResidentKey*)check_addr;
                if (check_key->magic == PASSKEY_MAGIC && memcmp(check_key->rp_id_hash, key->rp_id_hash, 32) == 0) {
                    unique = false;
                    break;
                }
                check_addr += PASSKEY_PAGE_SIZE;
            }
            if (unique) count++;
        }
        addr += PASSKEY_PAGE_SIZE;
    }
    return count;
}

int passkey_get_unique_rp_hash(uint32_t target_index, uint8_t* out_rp_id_hash) {
    uint32_t count = 0;
    uint32_t addr = PASSKEY_FLASH_START;
    while (addr < PASSKEY_FLASH_END) {
        ResidentKey* key = (ResidentKey*)addr;
        if (key->magic == PASSKEY_MAGIC) {
            bool unique = true;
            uint32_t check_addr = PASSKEY_FLASH_START;
            while (check_addr < addr) {
                ResidentKey* check_key = (ResidentKey*)check_addr;
                if (check_key->magic == PASSKEY_MAGIC && memcmp(check_key->rp_id_hash, key->rp_id_hash, 32) == 0) {
                    unique = false;
                    break;
                }
                check_addr += PASSKEY_PAGE_SIZE;
            }
            if (unique) {
                if (count == target_index) {
                    memcpy(out_rp_id_hash, key->rp_id_hash, 32);
                    return 0;
                }
                count++;
            }
        }
        addr += PASSKEY_PAGE_SIZE;
    }
    return -1;
}

uint32_t passkey_count_for_rp(const uint8_t* rp_id_hash) {
    uint32_t count = 0;
    uint32_t addr = PASSKEY_FLASH_START;
    while (addr < PASSKEY_FLASH_END) {
        ResidentKey* key = (ResidentKey*)addr;
        if (key->magic == PASSKEY_MAGIC && memcmp(key->rp_id_hash, rp_id_hash, 32) == 0) {
            count++;
        }
        addr += PASSKEY_PAGE_SIZE;
    }
    return count;
}

const ResidentKey* passkey_get_by_rp_index(const uint8_t* rp_id_hash, uint32_t target_index) {
    uint32_t match_idx = 0;
    uint32_t addr = PASSKEY_FLASH_START;
    while (addr < PASSKEY_FLASH_END) {
        ResidentKey* key = (ResidentKey*)addr;
        if (key->magic == PASSKEY_MAGIC && memcmp(key->rp_id_hash, rp_id_hash, 32) == 0) {
            if (match_idx == target_index) return key;
            match_idx++;
        }
        addr += PASSKEY_PAGE_SIZE;
    }
    return NULL;
}

int passkey_delete_by_cred_id(const uint8_t* credential_id) {
    uint32_t addr = PASSKEY_FLASH_START;
    while (addr < PASSKEY_FLASH_END) {
        ResidentKey* key = (ResidentKey*)addr;
        if (key->magic == PASSKEY_MAGIC) {
            if (memcmp(key->credential_id, credential_id, 32) == 0) {
                flash_unlock();
                flash_erase_page(addr);
                flash_lock();
                return 0;
            }
        }
        addr += PASSKEY_PAGE_SIZE;
    }
    return -1;
}
