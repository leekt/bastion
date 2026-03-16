#ifndef KECCAK256_H
#define KECCAK256_H

#include <stdint.h>
#include <stddef.h>

/// Compute Keccak-256 hash (Ethereum variant, NOT NIST SHA-3).
/// @param input Input data
/// @param inputLen Length of input data in bytes
/// @param output 32-byte output buffer
void keccak256(const uint8_t *input, size_t inputLen, uint8_t *output);

#endif
