// Keccak-256 implementation (Ethereum variant)
// Based on the Keccak reference: https://keccak.team/keccak_specs_summary.html
// This is Keccak-256 with 0x01 padding (NOT NIST SHA-3 which uses 0x06).

#include "keccak256.h"
#include <string.h>

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

// Pi: destination index for each step in the rho+pi chain starting from index 1
static const int pi_lane[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

// Rho: rotation amount for each step in the rho+pi chain
// Step i rotates the value coming from the source lane by rho_rot[i]
static const int rho_rot[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static void keccak_f1600(uint64_t state[25]) {
    uint64_t t, bc[5];

    for (int round = 0; round < 24; round++) {
        // Theta
        for (int i = 0; i < 5; i++)
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];

        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                state[j + i] ^= t;
        }

        // Rho + Pi (using precomputed tables)
        t = state[1];
        for (int i = 0; i < 24; i++) {
            int dest = pi_lane[i];
            uint64_t tmp = state[dest];
            state[dest] = ROTL64(t, rho_rot[i]);
            t = tmp;
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            uint64_t tmp[5];
            for (int i = 0; i < 5; i++)
                tmp[i] = state[j + i];
            for (int i = 0; i < 5; i++)
                state[j + i] = tmp[i] ^ ((~tmp[(i + 1) % 5]) & tmp[(i + 2) % 5]);
        }

        // Iota
        state[0] ^= keccak_rc[round];
    }
}

void keccak256(const uint8_t *input, size_t inputLen, uint8_t *output) {
    uint64_t state[25];
    memset(state, 0, sizeof(state));

    const int rate = 136; // (1600 - 2*256) / 8

    // Absorb
    size_t offset = 0;
    while (offset + rate <= inputLen) {
        for (int i = 0; i < rate / 8; i++) {
            uint64_t word = 0;
            for (int j = 0; j < 8; j++)
                word |= (uint64_t)input[offset + i * 8 + j] << (j * 8);
            state[i] ^= word;
        }
        keccak_f1600(state);
        offset += rate;
    }

    // Pad (Keccak padding: 0x01 ... 0x80)
    uint8_t lastBlock[136];
    memset(lastBlock, 0, rate);
    size_t remaining = inputLen - offset;
    if (remaining > 0)
        memcpy(lastBlock, input + offset, remaining);
    lastBlock[remaining] = 0x01;
    lastBlock[rate - 1] |= 0x80;

    for (int i = 0; i < rate / 8; i++) {
        uint64_t word = 0;
        for (int j = 0; j < 8; j++)
            word |= (uint64_t)lastBlock[i * 8 + j] << (j * 8);
        state[i] ^= word;
    }
    keccak_f1600(state);

    // Squeeze: 32 bytes
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++)
            output[i * 8 + j] = (uint8_t)(state[i] >> (j * 8));
    }
}
