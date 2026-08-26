#ifndef WCH_HAL_STUB_H
#define WCH_HAL_STUB_H

#include "ch32fun.h"
#include <string.h>

#define RCC_AHBPeriph_USBFS    ((uint32_t)0x00001000)
#define RCC_APB2Periph_AFIO    ((uint32_t)0x00000001)
#define RCC_APB2Periph_GPIOC   ((uint32_t)0x00000010)

static inline void RCC_AHBPeriphClockCmd(uint32_t RCC_AHBPeriph, FunctionalState NewState) {
    if (NewState == ENABLE) RCC->AHBPCENR |= RCC_AHBPeriph;
    else RCC->AHBPCENR &= ~RCC_AHBPeriph;
}

static inline void RCC_APB2PeriphClockCmd(uint32_t RCC_APB2Periph, FunctionalState NewState) {
    if (NewState == ENABLE) RCC->APB2PCENR |= RCC_APB2Periph;
    else RCC->APB2PCENR &= ~RCC_APB2Periph;
}

typedef enum {
    GPIO_Mode_AIN = 0x0,
    GPIO_Mode_IN_FLOATING = 0x04,
    GPIO_Mode_IPD = 0x28,
    GPIO_Mode_IPU = 0x48,
    GPIO_Mode_Out_OD = 0x14,
    GPIO_Mode_Out_PP = 0x10,
    GPIO_Mode_AF_OD = 0x1C,
    GPIO_Mode_AF_PP = 0x18
} GPIOMode_TypeDef;

typedef struct {
    uint32_t GPIO_Pin;
    GPIOMode_TypeDef GPIO_Mode;
    uint32_t GPIO_Speed;
} GPIO_InitTypeDef;

#define GPIO_Pin_16 ((uint32_t)0x00010000)
#define GPIO_Pin_17 ((uint32_t)0x00020000)

static inline void GPIO_Init(GPIO_TypeDef* GPIOx, GPIO_InitTypeDef* GPIO_InitStruct) {
    // Basic stub for PC16 and PC17
    // PC16 is CFGXR bits 3:0. IN_FLOATING = 0x04
    // PC17 is CFGXR bits 7:4. IPU = 0x08 (and BSHR bit 17 set)
    uint32_t pinpos;
    for (pinpos = 0; pinpos < 24; pinpos++) {
        uint32_t pos = ((uint32_t)0x01) << pinpos;
        if (GPIO_InitStruct->GPIO_Pin & pos) {
            uint32_t mode = GPIO_InitStruct->GPIO_Mode & 0x0F;
            if (pinpos < 8) {
                GPIOx->CFGLR &= ~(0xF << (pinpos * 4));
                GPIOx->CFGLR |= (mode << (pinpos * 4));
            } else if (pinpos < 16) {
                GPIOx->CFGHR &= ~(0xF << ((pinpos - 8) * 4));
                GPIOx->CFGHR |= (mode << ((pinpos - 8) * 4));
            } else {
                GPIOx->CFGXR &= ~(0xF << ((pinpos - 16) * 4));
                GPIOx->CFGXR |= (mode << ((pinpos - 16) * 4));
            }
            if (GPIO_InitStruct->GPIO_Mode == GPIO_Mode_IPD) {
                GPIOx->BCR = pos;
            } else if (GPIO_InitStruct->GPIO_Mode == GPIO_Mode_IPU) {
                GPIOx->BSHR = pos;
            }
        }
    }
}

#define PWR_VDD_5V  1
#define PWR_VDD_3V3 0
typedef uint8_t PWR_VDD;

#endif
