// secp256k1 ECDSA signing via OpenSSL (test-only, not used in production app)

#include "secp256k1_helper.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <string.h>

// Forward declaration of keccak256 from the main app's C code
extern void keccak256(const uint8_t *input, size_t inputLen, uint8_t *output);

int secp256k1_derive_pubkey(const uint8_t *privkey, uint8_t *pubkey_out) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) return -1;

    BIGNUM *priv_bn = BN_bin2bn(privkey, 32, NULL);
    if (!priv_bn) { EC_KEY_free(key); return -1; }

    if (!EC_KEY_set_private_key(key, priv_bn)) {
        BN_free(priv_bn);
        EC_KEY_free(key);
        return -1;
    }

    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub = EC_POINT_new(group);
    if (!pub) {
        BN_free(priv_bn);
        EC_KEY_free(key);
        return -1;
    }

    if (!EC_POINT_mul(group, pub, priv_bn, NULL, NULL, NULL)) {
        EC_POINT_free(pub);
        BN_free(priv_bn);
        EC_KEY_free(key);
        return -1;
    }

    EC_KEY_set_public_key(key, pub);

    size_t len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (len != 65) {
        EC_POINT_free(pub);
        BN_free(priv_bn);
        EC_KEY_free(key);
        return -1;
    }

    EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, pubkey_out, 65, NULL);

    EC_POINT_free(pub);
    BN_free(priv_bn);
    EC_KEY_free(key);
    return 0;
}

int secp256k1_eth_address(const uint8_t *pubkey65, uint8_t *address_out) {
    uint8_t hash[32];
    keccak256(pubkey65 + 1, 64, hash);
    memcpy(address_out, hash + 12, 20);
    return 0;
}

// Recover public key from signature + hash + recovery id
static int recover_pubkey(const EC_GROUP *group, const BIGNUM *sig_r,
                          const BIGNUM *sig_s, const uint8_t *hash32,
                          int recid, EC_POINT *result) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 0;

    BIGNUM *order = BN_new();
    EC_GROUP_get_order(group, order, ctx);

    BIGNUM *x = BN_dup(sig_r);

    EC_POINT *R = EC_POINT_new(group);
    if (!EC_POINT_set_compressed_coordinates(group, R, x, recid & 1, ctx)) {
        EC_POINT_free(R);
        BN_free(x);
        BN_free(order);
        BN_CTX_free(ctx);
        return 0;
    }

    BIGNUM *e = BN_bin2bn(hash32, 32, NULL);
    BIGNUM *r_inv = BN_new();
    BN_mod_inverse(r_inv, sig_r, order, ctx);

    // u1 = -e * r_inv mod order
    BIGNUM *u1 = BN_new();
    BN_mod_mul(u1, e, r_inv, order, ctx);
    BN_sub(u1, order, u1);

    // u2 = s * r_inv mod order
    BIGNUM *u2 = BN_new();
    BN_mod_mul(u2, sig_s, r_inv, order, ctx);

    // Q = u1*G + u2*R
    EC_POINT *u1G = EC_POINT_new(group);
    EC_POINT *u2R = EC_POINT_new(group);
    EC_POINT_mul(group, u1G, u1, NULL, NULL, ctx);
    EC_POINT_mul(group, u2R, NULL, R, u2, ctx);
    EC_POINT_add(group, result, u1G, u2R, ctx);

    EC_POINT_free(u1G);
    EC_POINT_free(u2R);
    BN_free(u2);
    BN_free(u1);
    BN_free(r_inv);
    BN_free(e);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(order);
    BN_CTX_free(ctx);
    return 1;
}

int secp256k1_sign_hash(const uint8_t *privkey, const uint8_t *hash32, uint8_t *sig_out) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) return -1;

    BIGNUM *priv_bn = BN_bin2bn(privkey, 32, NULL);
    if (!priv_bn) { EC_KEY_free(key); return -1; }

    if (!EC_KEY_set_private_key(key, priv_bn)) {
        BN_free(priv_bn);
        EC_KEY_free(key);
        return -1;
    }

    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv_bn, NULL, NULL, NULL);
    EC_KEY_set_public_key(key, pub);

    ECDSA_SIG *sig = ECDSA_do_sign(hash32, 32, key);
    if (!sig) {
        EC_POINT_free(pub);
        BN_free(priv_bn);
        EC_KEY_free(key);
        return -1;
    }

    const BIGNUM *r_bn, *s_bn;
    ECDSA_SIG_get0(sig, &r_bn, &s_bn);

    // Normalize s to low-s form (required by Ethereum)
    BIGNUM *half_order = BN_new();
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(group, order, NULL);
    BN_rshift1(half_order, order);

    BIGNUM *s_norm = BN_dup(s_bn);
    int s_is_high = (BN_cmp(s_bn, half_order) > 0);
    if (s_is_high) {
        BN_sub(s_norm, order, s_bn);
    }

    // Extract r and s as 32-byte big-endian
    memset(sig_out, 0, 65);
    int r_len = BN_num_bytes(r_bn);
    int s_len = BN_num_bytes(s_norm);
    BN_bn2bin(r_bn, sig_out + (32 - r_len));
    BN_bn2bin(s_norm, sig_out + 32 + (32 - s_len));

    // Compute recovery id (v = 27 or 28)
    sig_out[64] = 27;
    for (int recid = 0; recid < 2; recid++) {
        EC_POINT *recovered = EC_POINT_new(group);
        if (recover_pubkey(group, r_bn, s_norm, hash32, recid, recovered)) {
            if (EC_POINT_cmp(group, recovered, pub, NULL) == 0) {
                sig_out[64] = (uint8_t)(27 + recid);
                EC_POINT_free(recovered);
                break;
            }
        }
        EC_POINT_free(recovered);
    }

    BN_free(s_norm);
    BN_free(half_order);
    BN_free(order);
    ECDSA_SIG_free(sig);
    EC_POINT_free(pub);
    BN_free(priv_bn);
    EC_KEY_free(key);
    return 0;
}
