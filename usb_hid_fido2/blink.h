#ifndef BLINK_H
#define BLINK_H
#include "ch32fun.h"
static inline void blink_error(int count) {
    // Configure PB1 as output
    RCC->APB2PCENR |= RCC_IOPBEN;
    GPIOB->CFGLR = (GPIOB->CFGLR & ~(0xF << 4)) | (0x3 << 4);
    
    // Turn off
    GPIOB->OUTDR |= (1 << 1);
    Delay_Ms(500);
    
    for (int i = 0; i < count; i++) {
        // Turn on
        GPIOB->OUTDR &= ~(1 << 1);
        Delay_Ms(200);
        // Turn off
        GPIOB->OUTDR |= (1 << 1);
        Delay_Ms(200);
    }
}
#endif
