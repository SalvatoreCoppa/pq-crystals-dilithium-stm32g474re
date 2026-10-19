#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sk);
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *ctx, size_t ctxlen,
                     const uint8_t *pk);

#endif
