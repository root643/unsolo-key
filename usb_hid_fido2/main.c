#include "ch32fun.h"
#include "ch32x035_usbfs_device.h"
#include <stdio.h>
#include <stdbool.h>

#define SET_REPORT_WAIT_DEAL 1
#define SET_REPORT_DEAL_OVER 0

__attribute__ ((aligned(4))) uint8_t  HID_Report_Buffer[64];
volatile uint8_t HID_Set_Report_Flag = SET_REPORT_DEAL_OVER;

// Set by CTAPHID_CANCEL; the pending operation must abort with CTAP2_ERR_KEEPALIVE_CANCEL.
// Per CTAPHID spec the authenticator MUST NOT reply to the CANCEL message itself.
volatile bool cancel_requested = false;

// Dummy _write to satisfy linker
int _write(int fd, const char *buf, int size) {
    (void)fd;
    (void)buf;
    return size;
}

#include "cbor.h"
#include "fido2.h"
#include "flash_passkey.h"

void fido2_send_keepalive(uint32_t cid, uint8_t status) {
    // Stop any pending transmission immediately
    USBFS->UEP2_CTRL_H = (USBFS->UEP2_CTRL_H & ~USBFS_UEP_T_RES_MASK) | USBFS_UEP_T_RES_NAK;
    
    for(int i=0; i<64; i++) USBFS_EP2_Buf[i] = 0;
    USBFS_EP2_Buf[0] = (cid >> 24) & 0xFF;
    USBFS_EP2_Buf[1] = (cid >> 16) & 0xFF;
    USBFS_EP2_Buf[2] = (cid >> 8) & 0xFF;
    USBFS_EP2_Buf[3] = cid & 0xFF;
    USBFS_EP2_Buf[4] = 0xBB; // CTAPHID_KEEPALIVE (0x3B | 0x80 = 0xBB)
    USBFS_EP2_Buf[5] = 0;
    USBFS_EP2_Buf[6] = 1;
    USBFS_EP2_Buf[7] = status; // Keepalive status

    USBFS->UEP2_TX_LEN = 64; // FIDO2 HID reports MUST be 64 bytes
    USBFS->UEP2_CTRL_H = (USBFS->UEP2_CTRL_H & ~USBFS_UEP_T_RES_MASK) | USBFS_UEP_T_RES_ACK;
    
    // Non-blocking: DO NOT wait for the host to read it!
}

uint8_t ctap_resp_buf[1024];

void ctap_send_response(uint32_t cid, uint8_t cmd, uint8_t *payload, uint16_t payload_len) {
    uint16_t offset = 0;
    uint8_t seq = 0;

    int wait_timeout = 50000;
    while((USBFS->UEP2_CTRL_H & USBFS_UEP_T_RES_MASK) == USBFS_UEP_T_RES_ACK && wait_timeout > 0) { 
        Delay_Us(10); 
        wait_timeout--; 
    }
    if (wait_timeout == 0) {
        USBFS->UEP2_CTRL_H = (USBFS->UEP2_CTRL_H & ~USBFS_UEP_T_RES_MASK) | USBFS_UEP_T_RES_NAK;
        return;
    }

    // Send first packet
    for(int i=0; i<64; i++) USBFS_EP2_Buf[i] = 0;
    USBFS_EP2_Buf[0] = (cid >> 24) & 0xFF;
    USBFS_EP2_Buf[1] = (cid >> 16) & 0xFF;
    USBFS_EP2_Buf[2] = (cid >> 8) & 0xFF;
    USBFS_EP2_Buf[3] = cid & 0xFF;
    USBFS_EP2_Buf[4] = cmd;
    USBFS_EP2_Buf[5] = (payload_len >> 8) & 0xFF;
    USBFS_EP2_Buf[6] = payload_len & 0xFF;
    
    uint8_t to_copy = (payload_len > 57) ? 57 : payload_len;
    if (payload != NULL) memcpy(&USBFS_EP2_Buf[7], payload, to_copy);
    offset += to_copy;

    USBFS->UEP2_TX_LEN = 64;
    USBFS->UEP2_CTRL_H = (USBFS->UEP2_CTRL_H & ~USBFS_UEP_T_RES_MASK) | USBFS_UEP_T_RES_ACK;
    
    // Wait for transmission
    int timeout = 50000;
    while((USBFS->UEP2_CTRL_H & USBFS_UEP_T_RES_MASK) == USBFS_UEP_T_RES_ACK && timeout > 0) { 
        Delay_Us(10); 
        timeout--; 
    }
    if (timeout == 0) {
        USBFS->UEP2_CTRL_H = (USBFS->UEP2_CTRL_H & ~USBFS_UEP_T_RES_MASK) | USBFS_UEP_T_RES_NAK;
        return; // Drop if host timed out
    }

    // Send continuation packets
    while (offset < payload_len) {
        for(int i=0; i<64; i++) USBFS_EP2_Buf[i] = 0;
        USBFS_EP2_Buf[0] = (cid >> 24) & 0xFF;
        USBFS_EP2_Buf[1] = (cid >> 16) & 0xFF;
        USBFS_EP2_Buf[2] = (cid >> 8) & 0xFF;
        USBFS_EP2_Buf[3] = cid & 0xFF;
        USBFS_EP2_Buf[4] = seq++;

        to_copy = (payload_len - offset > 59) ? 59 : (payload_len - offset);
        if (payload != NULL) memcpy(&USBFS_EP2_Buf[5], payload + offset, to_copy);
        offset += to_copy;

        USBFS->UEP2_TX_LEN = 64;
        USBFS->UEP2_CTRL_H = (USBFS->UEP2_CTRL_H & ~USBFS_UEP_T_RES_MASK) | USBFS_UEP_T_RES_ACK;
        
        timeout = 50000;
        while((USBFS->UEP2_CTRL_H & USBFS_UEP_T_RES_MASK) == USBFS_UEP_T_RES_ACK && timeout > 0) { 
            Delay_Us(10); 
            timeout--; 
        }
        if (timeout == 0) {
            USBFS->UEP2_CTRL_H = (USBFS->UEP2_CTRL_H & ~USBFS_UEP_T_RES_MASK) | USBFS_UEP_T_RES_NAK;
            return; // Drop if host timed out
        }
    }
}

uint8_t ctap_req_buf[1024];
uint16_t ctap_req_len = 0;
uint16_t ctap_expected_len = 0;
uint8_t ctap_seq = 0;
uint32_t ctap_cid = 0;
uint8_t ctap_cmd = 0;

// Allocated CID for this device (assigned once on first INIT)
static uint32_t allocated_cid = 0xCAFEBABE;

extern uint32_t g_current_cid;

// Basic FIDO2 CTAPHID parser with receive fragmentation
void ProcessCTAPHID(uint8_t *buffer, uint16_t len) {
    if (len < 5) return; // Too short
    uint32_t cid = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
    g_current_cid = cid;
    
    // CTAPHID_CANCEL (0x91): MUST NOT be answered directly. Just flag it so the
    // pending operation aborts with CTAP2_ERR_KEEPALIVE_CANCEL. Do NOT touch the
    // transaction state of any in-progress fragmented message.
    if (buffer[4] == 0x91) {
        cancel_requested = true;
        return;
    }
    
    if (buffer[4] & 0x80) { // INIT packet
        if (len < 7) return;
        uint8_t cmd = buffer[4];
        uint16_t payload_len = (buffer[5] << 8) | buffer[6];
        uint16_t chunk_len = len - 7;
        
        if (payload_len > sizeof(ctap_req_buf)) return; // Too large
        
        ctap_cid = cid;
        ctap_cmd = cmd;
        ctap_expected_len = payload_len;
        ctap_req_len = (chunk_len > payload_len) ? payload_len : chunk_len;
        memcpy(ctap_req_buf, &buffer[7], ctap_req_len);
        ctap_seq = 0;
    } else { // Continuation packet
        if (cid != ctap_cid || ctap_expected_len == 0) return; // Unexpected
        uint8_t seq = buffer[4];
        if (seq != ctap_seq) {
            ctap_expected_len = 0; // Out of order, drop
            return;
        }
        ctap_seq++;
        uint16_t chunk_len = len - 5;
        uint16_t remain = ctap_expected_len - ctap_req_len;
        uint16_t copy_len = (chunk_len > remain) ? remain : chunk_len;
        memcpy(&ctap_req_buf[ctap_req_len], &buffer[5], copy_len);
        ctap_req_len += copy_len;
    }

    // If we have received the full message (including zero-length commands like WINK)
    if (ctap_req_len == ctap_expected_len && (ctap_cmd & 0x80)) {
        if (ctap_cmd == 0x90) { // CTAPHID_CBOR
            uint16_t resp_len = 0;
            fido2_process_cbor(ctap_req_buf, ctap_expected_len, ctap_resp_buf, &resp_len, cid);
            ctap_send_response(cid, ctap_cmd, ctap_resp_buf, resp_len);
        } else if (ctap_cmd == 0x86) { // CTAPHID_INIT
            // If the host sends to broadcast CID (0xFFFFFFFF), allocate our CID
            // If it sends to our existing CID, it's a resync - use same CID
            uint32_t resp_cid;
            if (cid == 0xFFFFFFFF) {
                resp_cid = allocated_cid; // Use our fixed allocated CID
            } else {
                resp_cid = cid; // Resync: echo the CID back
                allocated_cid = cid;
            }
            for(int i=0; i<8; i++) ctap_resp_buf[i] = ctap_req_buf[i]; // echo nonce
            ctap_resp_buf[8]  = (resp_cid >> 24) & 0xFF;
            ctap_resp_buf[9]  = (resp_cid >> 16) & 0xFF;
            ctap_resp_buf[10] = (resp_cid >> 8)  & 0xFF;
            ctap_resp_buf[11] = resp_cid & 0xFF;
            ctap_resp_buf[12] = 2; // CTAPHID protocol version
            ctap_resp_buf[13] = 1; // device major version
            ctap_resp_buf[14] = 0; // device minor version
            ctap_resp_buf[15] = 0; // device build version
            ctap_resp_buf[16] = 0x04 | 0x01 | 0x08; // CAPABILITY_CBOR | CAPABILITY_WINK | CAPABILITY_NMSG
            ctap_send_response(cid, ctap_cmd, ctap_resp_buf, 17);
        } else if (ctap_cmd == 0x81) { // PING
            ctap_send_response(cid, ctap_cmd, ctap_req_buf, ctap_expected_len);
        } else if (ctap_cmd == 0x88) { // CTAPHID_WINK - Windows Hello uses this
            ctap_send_response(cid, ctap_cmd, ctap_resp_buf, 0); // Empty response = success
        } else if (ctap_cmd == 0x84) { // CTAPHID_LOCK
            ctap_send_response(cid, ctap_cmd, ctap_resp_buf, 0); // Empty response = success
        } else {
            // Unknown command - MUST respond with error or host hangs forever!
            ctap_resp_buf[0] = 0x01; // ERR_INVALID_CMD
            ctap_send_response(cid, 0xBF, ctap_resp_buf, 1); // 0xBF = CTAPHID_ERROR
        }
        ctap_expected_len = 0; // Reset state for next message
        ctap_cmd = 0; // Clear command so it doesn't re-fire
    }
}

int main()
{
    SystemInit();
    Delay_Us(100);

    // Init USB clocks
    USBFS_RCC_Init();

    // Force USB re-enumeration (crucial after exiting USB Bootloader)
    USBFS_Device_Init(DISABLE, PWR_VDD_3V3);
    Delay_Ms(50);
    
    // Connect USB
    USBFS_Device_Init(ENABLE, PWR_VDD_3V3);

    while(1)
    {
        if(RingBuffer_Comm.RemainPack)
        {
            // We got a packet in EP1 (OUT)
            uint16_t pkg_len = RingBuffer_Comm.PackLen[RingBuffer_Comm.DealPtr];
            uint8_t *pbuf = &Data_Buffer[(RingBuffer_Comm.DealPtr) * DEF_USBD_FS_PACK_SIZE];
            
            ProcessCTAPHID(pbuf, pkg_len);
            
            NVIC_DisableIRQ(USBFS_IRQn);
            RingBuffer_Comm.RemainPack--;
            RingBuffer_Comm.DealPtr++;
            if(RingBuffer_Comm.DealPtr == DEF_Ring_Buffer_Max_Blks)
            {
                RingBuffer_Comm.DealPtr = 0;
            }
            NVIC_EnableIRQ(USBFS_IRQn);
        }
        
        if(HID_Set_Report_Flag == SET_REPORT_WAIT_DEAL)
        {
            // We got a packet via EP0 SET_REPORT
            // STATUS stage was already ACK'd in ISR, so EP0 is free.
            ProcessCTAPHID(HID_Report_Buffer, 64);
            HID_Set_Report_Flag = SET_REPORT_DEAL_OVER;
        }

        if (RingBuffer_Comm.RemainPack < (DEF_Ring_Buffer_Max_Blks - DEF_RING_BUFFER_RESTART))
        {
            if(RingBuffer_Comm.StopFlag)
            {
                RingBuffer_Comm.StopFlag = 0;
                USBFS->UEP1_CTRL_H = (USBFS->UEP1_CTRL_H & ~USBFS_UEP_R_RES_MASK) | USBFS_UEP_R_RES_ACK;
            }
        }
    }
}

// Service Out-Of-Band commands (WINK, CANCEL) while blocked waiting for User Presence
void Process_OOB_Commands(void) {
    if(RingBuffer_Comm.RemainPack)
    {
        uint16_t pkg_len = RingBuffer_Comm.PackLen[RingBuffer_Comm.DealPtr];
        uint8_t *buffer = &Data_Buffer[(RingBuffer_Comm.DealPtr) * DEF_USBD_FS_PACK_SIZE];
        
        // Peek at command
        if (pkg_len >= 5 && (buffer[4] & 0x80)) {
            uint8_t cmd = buffer[4];
            uint32_t cid = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
            
            if (cmd == 0x88 || cmd == 0x84) { // WINK, LOCK
                // Process it immediately and remove from ring buffer WITHOUT touching globals
                ctap_send_response(cid, cmd, NULL, 0); // Empty response = success
                
                NVIC_DisableIRQ(USBFS_IRQn);
                RingBuffer_Comm.RemainPack--;
                RingBuffer_Comm.DealPtr++;
                if(RingBuffer_Comm.DealPtr == DEF_Ring_Buffer_Max_Blks) RingBuffer_Comm.DealPtr = 0;
                NVIC_EnableIRQ(USBFS_IRQn);
            }
            else if (cmd == 0x91) { // CANCEL: flag only, no direct reply (spec 11.2.9.1.5)
                cancel_requested = true;
                
                NVIC_DisableIRQ(USBFS_IRQn);
                RingBuffer_Comm.RemainPack--;
                RingBuffer_Comm.DealPtr++;
                if(RingBuffer_Comm.DealPtr == DEF_Ring_Buffer_Max_Blks) RingBuffer_Comm.DealPtr = 0;
                NVIC_EnableIRQ(USBFS_IRQn);
            }
            else if (cmd == 0x86) { // INIT
                if (pkg_len >= 15) {
                    extern uint32_t g_current_cid;
                    uint32_t resp_cid;
                    if (cid == 0xFFFFFFFF) {
                        resp_cid = allocated_cid;
                    } else {
                        resp_cid = cid;
                        allocated_cid = cid;
                        if (cid == g_current_cid) cancel_requested = true;
                    }
                    uint8_t local_resp[17];
                    for(int i=0; i<8; i++) local_resp[i] = buffer[7+i]; // nonce
                    local_resp[8]  = (resp_cid >> 24) & 0xFF;
                    local_resp[9]  = (resp_cid >> 16) & 0xFF;
                    local_resp[10] = (resp_cid >> 8)  & 0xFF;
                    local_resp[11] = resp_cid & 0xFF;
                    local_resp[12] = 2; // CTAPHID protocol version
                    local_resp[13] = 1; // device major version
                    local_resp[14] = 0; // device minor version
                    local_resp[15] = 0; // device build version
                    local_resp[16] = 0x04 | 0x01 | 0x08; // CAPABILITY_CBOR | CAPABILITY_WINK | CAPABILITY_NMSG
                    
                    ctap_send_response(cid, cmd, local_resp, 17);
                }
                
                NVIC_DisableIRQ(USBFS_IRQn);
                RingBuffer_Comm.RemainPack--;
                RingBuffer_Comm.DealPtr++;
                if(RingBuffer_Comm.DealPtr == DEF_Ring_Buffer_Max_Blks) RingBuffer_Comm.DealPtr = 0;
                NVIC_EnableIRQ(USBFS_IRQn);
            }
        }
    }
}
