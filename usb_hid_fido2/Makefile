all : flash

TARGET:=main

TARGET_MCU?=CH32X035
ADDITIONAL_C_FILES:=ch32x035_usbfs_device.c usb_desc.c sha256.c aes.c cbor.c fido2.c pin.c flash_passkey.c ../micro-ecc/uECC.c

CFLAGS+=-I../micro-ecc -DuECC_OPTIMIZATION_LEVEL=3 -flto
# Only P-256 is needed; disabling other curves saves several KB of flash
CFLAGS+=-DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 -DuECC_SUPPORTS_secp224r1=0 -DuECC_SUPPORTS_secp256k1=0

include ../ch32fun/ch32fun/ch32fun.mk

flash : cv_flash
clean : cv_clean
CFLAGS+=-DFUNCONF_USE_DEBUGPRINTF=0 -DFUNCONF_USE_UARTPRINTF=0
