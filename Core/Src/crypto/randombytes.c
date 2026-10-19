#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "randombytes.h"
#include "rng.h"
#include "stm32g4xx_hal.h"


extern RNG_HandleTypeDef hrng;

void randombytes(uint8_t *out, size_t outlen) {
    while (outlen > 0) {
        uint32_t rnd;
        if (HAL_RNG_GenerateRandomNumber(&hrng, &rnd) != HAL_OK) {
            // Critical error
            while (1);
        }

        // Copy 1 byte at time from rnd (max 4 byte at time)
        size_t copylen = (outlen < 4) ? outlen : 4;
        for (size_t i = 0; i < copylen; i++) {
            *out++ = (rnd >> (8 * i)) & 0xFF;
        }
        outlen -= copylen;
    }
}
