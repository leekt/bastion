#ifndef SECP256K1_HELPER_H
#define SECP256K1_HELPER_H

#include <stdint.h>
#include <stddef.h>

/// Derive uncompressed public key (65 bytes: 04 + x[32] + y[32]) from private key (32 bytes).
/// Returns 0 on success, -1 on error.
int secp256k1_derive_pubkey(const uint8_t *privkey, uint8_t *pubkey_out);

/// Compute Ethereum address (20 bytes) from uncompressed public key (65 bytes).
/// Address = keccak256(pubkey[1..65])[12..32]
/// Returns 0 on success, -1 on error.
int secp256k1_eth_address(const uint8_t *pubkey65, uint8_t *address_out);

/// Sign a 32-byte hash with secp256k1 ECDSA.
/// Output: r[32] + s[32] + v[1] = 65 bytes.
/// v is the recovery id (27 or 28).
/// Returns 0 on success, -1 on error.
int secp256k1_sign_hash(const uint8_t *privkey, const uint8_t *hash32, uint8_t *sig_out);

#endif
