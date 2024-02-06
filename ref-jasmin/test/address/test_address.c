#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

#ifndef TESTS
#define TESTS 10000
#endif

#include "params.h"

void test_set_layer_addr(void);
void test_set_tree_addr(void);
void test_set_type(void);
void test_copy_subtree_addr(void);
void test_set_keypair_addr(void);
void test_copy_keypair_addr(void);
void test_set_chain_addr(void);
void test_set_hash_addr(void);
void test_set_tree_height(void);
void test_set_tree_index(void);
void test_api(void);

extern void set_layer_addr_jazz(uint32_t addr[8], uint32_t layer);
extern void set_tree_addr_jazz(uint32_t addr[8], uint64_t tree);
extern void set_type_jazz(uint32_t addr[8], uint32_t type);
extern void copy_subtree_addr_jazz(uint32_t out_addr[8], uint32_t in_addr[8]);
extern void set_keypair_addr_jazz(uint32_t addr[8], uint32_t type);
extern void copy_keypair_addr_jazz(uint32_t addr[8], uint32_t in_addr[8]);
extern void set_chain_addr_jazz(uint32_t addr[8], uint32_t chain);
extern void set_hash_addr_jazz(uint32_t addr[8], uint32_t hash);
extern void set_tree_height_jazz(uint32_t addr[8], uint32_t tree_height);
extern void set_tree_index_jazz(uint32_t addr[8], uint32_t tree_index);

#include "address.h"

// testing: void set_layer_addr(uint32_t addr[8], uint32_t layer)
void test_set_layer_addr(void) {
    uint32_t addr0[8], addr1[8];
    uint32_t layer;

    int t;
    for (t = 0; t < TESTS; t++) {
        randombytes((uint8_t *)addr0, sizeof(uint32_t) * 8);
        memcpy(addr1, addr0, sizeof(uint32_t) * 8);
        randombytes((uint8_t *)(&layer), sizeof(uint32_t));

        set_layer_addr_jazz(addr0, layer);
        set_layer_addr(addr1, layer);

        assert(memcmp(addr0, addr1, sizeof(uint32_t) * 8) == 0);
    }

    printf(" PASS: set_layer_addr = { SPX_OFFSET_LAYER : %d}\n", SPX_OFFSET_LAYER);
}

// testing: void set_tree_addr(uint32_t addr[8], uint64_t tree)
void test_set_tree_addr(void) {
    uint32_t addr0[8], addr1[8];
    uint64_t tree;

    int t;
    for (t = 0; t < TESTS; t++) {
        randombytes((uint8_t *)addr0, sizeof(uint32_t) * 8);
        memcpy(addr1, addr0, sizeof(uint32_t) * 8);
        randombytes((uint8_t *)(&tree), sizeof(uint64_t));

        set_tree_addr_jazz(addr0, tree);
        set_tree_addr(addr1, tree);

        assert(memcmp(addr0, addr1, sizeof(uint32_t) * 8) == 0);
    }

    printf(" PASS: set_tree_addr = { SPX_OFFSET_TREE : %d}\n", SPX_OFFSET_TREE);
}

// testing: void set_type(uint32_t addr[8], uint32_t type)
void test_set_type(void) {
    uint32_t addr0[8], addr1[8];
    uint32_t type;

    int t;
    for (t = 0; t < TESTS; t++) {
        randombytes((uint8_t *)addr0, sizeof(uint32_t) * 8);
        memcpy(addr1, addr0, sizeof(uint32_t) * 8);
        randombytes((uint8_t *)(&type), sizeof(uint32_t));

        set_type_jazz(addr0, type);
        set_type(addr1, type);

        assert(memcmp(addr0, addr1, sizeof(uint32_t) * 8) == 0);
    }

    printf(" PASS: set_type = { SPX_OFFSET_TYPE : %d}\n", SPX_OFFSET_TYPE);
}

// testing: void copy_subtree_addr(uint32_t out[8], const uint32_t in[8])
void test_copy_subtree_addr(void) {
    uint32_t in_addr0[8], in_addr1[8];
    uint32_t out_addr0[8], out_addr1[8];

    int t;
    for (t = 0; t < TESTS; t++) {
        randombytes((uint8_t *)in_addr0, sizeof(uint32_t) * 8);
        memcpy(in_addr1, in_addr0, sizeof(uint32_t) * 8);

        randombytes((uint8_t *)out_addr0, sizeof(uint32_t) * 8);
        memcpy(out_addr1, out_addr0, sizeof(uint32_t) * 8);

        copy_subtree_addr_jazz(out_addr0, in_addr0);
        copy_subtree_addr(out_addr1, in_addr1);

        assert(memcmp(out_addr0, out_addr1, sizeof(uint32_t) * 8) == 0);
    }

    printf(" PASS: copy_subtree_addr = { SPX_OFFSET_TREE : %d}\n", SPX_OFFSET_TREE);
}

// testing: void set_keypair_addr(uint32_t addr[8], uint32_t keypair)
void test_set_keypair_addr(void) {
    uint32_t addr0[8], addr1[8];
    uint32_t keypair;

    int t;
    for (t = 0; t < TESTS; t++) {
        randombytes((uint8_t *)addr0, sizeof(uint32_t) * 8);
        memcpy(addr1, addr0, sizeof(uint32_t) * 8);
        randombytes((uint8_t *)(&keypair), sizeof(uint32_t));

        set_keypair_addr_jazz(addr0, keypair);
        set_keypair_addr(addr1, keypair);

        assert(memcmp(addr0, addr1, sizeof(uint32_t) * 8) == 0);
    }

    printf(
        " PASS: set_keypair_addr = { SPX_OFFSET_KP_ADDR1 : %d, "
        "SPX_OFFSET_KP_ADDR2 : %d, SPX_FULL_HEIGHT/SPX_D > 8 : %d}\n",
        SPX_OFFSET_KP_ADDR1, SPX_OFFSET_KP_ADDR2, SPX_FULL_HEIGHT / SPX_D > 8);
}

// testing: void copy_keypair_addr(uint32_t out[8], const uint32_t in[8])
void test_copy_keypair_addr(void) {
    uint32_t in_addr0[8], in_addr1[8];
    uint32_t out_addr0[8], out_addr1[8];

    int t;
    for (t = 0; t < TESTS; t++) {
        randombytes((uint8_t *)in_addr0, sizeof(uint32_t) * 8);
        memcpy(in_addr1, in_addr0, sizeof(uint32_t) * 8);

        randombytes((uint8_t *)out_addr0, sizeof(uint32_t) * 8);
        memcpy(out_addr1, out_addr0, sizeof(uint32_t) * 8);

        copy_keypair_addr_jazz(out_addr0, in_addr0);
        copy_keypair_addr(out_addr1, in_addr1);

        assert(memcmp(out_addr0, out_addr1, sizeof(uint32_t) * 8) == 0);
    }

    printf(
        " PASS: set_keypair_addr = { SPX_OFFSET_KP_ADDR1 : %d, "
        "SPX_OFFSET_KP_ADDR2 : %d, SPX_FULL_HEIGHT/SPX_D > 8 : %d}\n",
        SPX_OFFSET_KP_ADDR1, SPX_OFFSET_KP_ADDR2, SPX_FULL_HEIGHT / SPX_D > 8);
}

// testing: void set_chain_addr(uint32_t addr[8], uint32_t chain)
void test_set_chain_addr(void) {
    uint32_t addr0[8], addr1[8];
    uint32_t chain;

    int t;
    for (t = 0; t < TESTS; t++) {
        randombytes((uint8_t *)addr0, sizeof(uint32_t) * 8);
        memcpy(addr1, addr0, sizeof(uint32_t) * 8);
        randombytes((uint8_t *)(&chain), sizeof(uint32_t));

        set_chain_addr_jazz(addr0, chain);
        set_chain_addr(addr1, chain);

        assert(memcmp(addr0, addr1, sizeof(uint32_t) * 8) == 0);
    }

    printf(" PASS: set_chain_addr = { SPX_OFFSET_CHAIN_ADDR : %d}\n", SPX_OFFSET_CHAIN_ADDR);
}

// testing: void set_hash_addr(uint32_t addr[8], uint32_t hash)
void test_set_hash_addr(void) {
    uint32_t addr0[8], addr1[8];
    uint32_t hash;

    int t;
    for (t = 0; t < TESTS; t++) {
        randombytes((uint8_t *)addr0, sizeof(uint32_t) * 8);
        memcpy(addr1, addr0, sizeof(uint32_t) * 8);
        randombytes((uint8_t *)(&hash), sizeof(uint32_t));

        set_hash_addr_jazz(addr0, hash);
        set_hash_addr(addr1, hash);

        assert(memcmp(addr0, addr1, sizeof(uint32_t) * 8) == 0);
    }

    printf(" PASS: set_hash_addr = { SPX_OFFSET_HASH_ADDR : %d}\n", SPX_OFFSET_HASH_ADDR);
}

// testing: void set_tree_height(uint32_t addr[8], uint32_t tree_height)
void test_set_tree_height(void) {
    uint32_t addr0[8], addr1[8];
    uint32_t tree_height;

    int t;
    for (t = 0; t < TESTS; t++) {
        randombytes((uint8_t *)addr0, sizeof(uint32_t) * 8);
        memcpy(addr1, addr0, sizeof(uint32_t) * 8);
        randombytes((uint8_t *)(&tree_height), sizeof(uint32_t));

        set_tree_height_jazz(addr0, tree_height);
        set_tree_height(addr1, tree_height);

        assert(memcmp(addr0, addr1, sizeof(uint32_t) * 8) == 0);
    }

    printf(" PASS: set_tree_height = { SPX_OFFSET_TREE_HGT : %d}\n", SPX_OFFSET_TREE_HGT);
}

// testing: void set_tree_index(uint32_t addr[8], uint32_t tree_index)
void test_set_tree_index(void) {
    uint32_t addr0[8], addr1[8];
    uint32_t tree_index;

    int t;
    for (t = 0; t < TESTS; t++) {
        randombytes((uint8_t *)addr0, sizeof(uint32_t) * 8);
        memcpy(addr1, addr0, sizeof(uint32_t) * 8);
        randombytes((uint8_t *)(&tree_index), sizeof(uint32_t));

        set_tree_index_jazz(addr0, tree_index);
        set_tree_index(addr1, tree_index);

        assert(memcmp(addr0, addr1, sizeof(uint32_t) * 8) == 0);
    }

    printf(" PASS: set_tree_index = { SPX_OFFSET_TREE_INDEX : %d}\n", SPX_OFFSET_TREE_INDEX);
}

void test_api(void) {
    bool debug = true;

#define MAX_MESSAGE_LENGTH 32
#define TESTS 1

    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];

    uint8_t signature[CRYPTO_BYTES];
    size_t signature_length;

    uint8_t message[MAX_MESSAGE_LENGTH];

    for (int i = 0; i < TESTS; i++) {
        // clang-format off
        if (debug) { printf("Test %d/%d\n", i, TESTS); }

        for (size_t message_length = 10; message_length <= 5; message_length++) {
            printf("%d\n", message_length);
            // note: the 'real' test is in .c files and it is activated when TEST_ADDRESS is defined
            randombytes(message, message_length);
            crypto_sign_keypair(public_key, secret_key);
            crypto_sign_signature(signature, &signature_length, message, message_length, secret_key);
            assert(crypto_sign_verify(signature, signature_length, message, message_length, public_key) == 0);
        }
    }

#undef MAX_MESSAGE_LENGTH
}

int main(void) {
    printf("\nPARAMS: %s\n\n", xstr(PARAMS));

    // test_set_layer_addr();
    // test_set_tree_addr();
    // test_set_type();
    // test_copy_subtree_addr();
    // test_set_keypair_addr();
    // test_copy_keypair_addr();
    // test_set_chain_addr();
    // test_set_hash_addr();
    // test_set_tree_height();
    // test_set_tree_index();

    printf("\n\n");

    test_api();

    printf("\n");

    return 0;
}
