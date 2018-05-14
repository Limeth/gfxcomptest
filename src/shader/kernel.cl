#define uint32_t uint
#define int32_t int
#define uint64_t ulong
#define bool uint

#define USE_NUM_NONE 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1
#define USE_FIELD_10X26 1
#define USE_SCALAR_8X32 1
#define USE_ENDOMORPHISM 1
#define ENABLE_MODULE_ECDH 1
#define ENABLE_MODULE_SCHNORR 1
#define ENABLE_MODULE_RECOVERY 1

#include "src/shader/std.cl"
#include "src/shader/secp256k1.cl"
#include "src/shader/keccak.cl"
#include "src/shader/atomic.cl"

#define ADDRESS_LENGTH 40
#define ADDRESS_BYTES (ADDRESS_LENGTH / 2)
#define KECCAK_OUTPUT_BYTES 32
#define ADDRESS_BYTE_INDEX (KECCAK_OUTPUT_BYTES - ADDRESS_BYTES)

#ifdef DEBUG_ASSERTIONS
# define DEBUG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
# define DEBUG(fmt, ...)
#endif

typedef struct {
    uint *input;
    secp256k1_context_arg *ctx_arg;
    secp256k1_ecmult_context_chunk *chunk;
} arguments;

enum state {
    STATE_LOADING_CONTEXT,
    STATE_RUNNING,
};

static global bool state = STATE_LOADING_CONTEXT;

static global uint loading_index = 0;
static global secp256k1_ge_storage pre_g[ECMULT_TABLE_SIZE(WINDOW_G)];
#ifdef USE_ENDOMORPHISM
static global secp256k1_ge_storage pre_g_128[ECMULT_TABLE_SIZE(WINDOW_G)];
#endif
static global secp256k1_context context;

// only literal strings may be passed to printf
#define hexdump(label, pointer, bytes) do { \
    DEBUG("[device] %s hexdump:", label); \
    hexdump_impl(pointer, bytes); \
} while(0)

void hexdump_impl(void *pointer, size_t bytes) {
    for (size_t offset = 0; offset < bytes; offset++) {
        if (offset % 16 == 0) {
            printf("\n");
        } else if (offset % 4 == 0) {
            printf(" ");
        }

        uchar byte = *(((uchar*) pointer) + offset);
        printf("%02x ", byte);
    }

    printf("\n");
}

void initialize_context(arguments *args) {
    context = (secp256k1_context) {
        .ecmult_ctx = (secp256k1_ecmult_context) {
            .pre_g = &pre_g,
#ifdef USE_ENDOMORPHISM
            .pre_g_128 = &pre_g_128,
#endif
        },
        .ecmult_gen_ctx = (secp256k1_ecmult_gen_context) {
            .prec = &args->ctx_arg->ecmult_gen_ctx.prec,
            .blind = args->ctx_arg->ecmult_gen_ctx.blind,
            .initial = args->ctx_arg->ecmult_gen_ctx.initial,
        },
        .illegal_callback = (secp256k1_callback) {
            .data = NULL,
        },
        .error_callback = (secp256k1_callback) {
            .data = NULL,
        },
    };
}

void branch_loading_context_atomic(arguments *args) {
    /* printf("loading_context_atomic\n"); */

    if (loading_index == 0) {
        initialize_context(args);
    }

    // Possibly parallelize
    size_t lower_bound = loading_index * ECMULT_TABLE_CHUNK_LEN;
    size_t upper_bound = min((uint) (lower_bound + ECMULT_TABLE_CHUNK_LEN), (uint) (ECMULT_TABLE_SIZE(WINDOW_G)));

    for (size_t item_index_abs = lower_bound; item_index_abs < upper_bound; item_index_abs++) {
        size_t item_index_rel = item_index_abs - lower_bound;
        pre_g[item_index_abs] = args->chunk->pre_g_chunk[item_index_rel];
#ifdef USE_ENDOMORPHISM
        pre_g_128[item_index_abs] = args->chunk->pre_g_128_chunk[item_index_rel];
#endif
    }

    loading_index++;

    if (upper_bound >= ECMULT_TABLE_SIZE(WINDOW_G)) {
        state = STATE_RUNNING;

        hexdump("context", &context, sizeof(secp256k1_context));
        hexdump("first 16 bytes of pre_g", context.ecmult_ctx.pre_g, 16);
        hexdump("first 16 bytes of pre_g_128", context.ecmult_ctx.pre_g_128, 16);
        hexdump("first 16 bytes of prec", context.ecmult_gen_ctx.prec, 16);
        hexdump("last 16 bytes of pre_g", ((uchar*) context.ecmult_ctx.pre_g) + (ECMULT_TABLE_SIZE(WINDOW_G)) * sizeof(secp256k1_ge_storage) - 16, 16);
        hexdump("last 16 bytes of pre_g_128", ((uchar*) context.ecmult_ctx.pre_g_128) + (ECMULT_TABLE_SIZE(WINDOW_G)) * sizeof(secp256k1_ge_storage) - 16, 16);
        hexdump("last 16 bytes of prec", ((uchar*) context.ecmult_gen_ctx.prec) + (16 * 64) * sizeof(secp256k1_ge_storage) - 16, 16);
    }
}

void branch_loading_context(arguments *args) {
    size_t i = get_global_id(0);

    if (i == 0) {
        branch_loading_context_atomic(args);
    }

    work_group_barrier(CLK_GLOBAL_MEM_FENCE | CLK_LOCAL_MEM_FENCE);
}

void run_eckey_edge_case_test(secp256k1_context *ctx) {
    const unsigned char orderc[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    const unsigned char zeros[sizeof(secp256k1_pubkey)] = {0x00};
    unsigned char ctmp[33];
    unsigned char ctmp2[33];
    secp256k1_pubkey pubkey;
    secp256k1_pubkey pubkey2;
    secp256k1_pubkey pubkey_one;
    secp256k1_pubkey pubkey_negone;
    const secp256k1_pubkey *pubkeys[3];
    size_t len;
    int32_t ecount;
    /* Group order is too large, reject. */
    CHECK(secp256k1_ec_seckey_verify(ctx, orderc) == 0);
    VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, orderc) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* Maximum value is too large, reject. */
    memset(ctmp, 255, 32);
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 0);
    memset(&pubkey, 1, sizeof(pubkey));
    VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* Zero is too small, reject. */
    memset(ctmp, 0, 32);
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 0);
    memset(&pubkey, 1, sizeof(pubkey));
    VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* One must be accepted. */
    ctmp[31] = 0x01;
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 1);
    memset(&pubkey, 0, sizeof(pubkey));
    VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == 1);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    pubkey_one = pubkey;
    /* Group order + 1 is too large, reject. */
    memcpy(ctmp, orderc, 32);
    ctmp[31] = 0x42;
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 0);
    memset(&pubkey, 1, sizeof(pubkey));
    VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* -1 must be accepted. */
    ctmp[31] = 0x40;
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 1);
    memset(&pubkey, 0, sizeof(pubkey));
    VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == 1);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    pubkey_negone = pubkey;
    /* /1* Tweak of zero leaves the value changed. *1/ */
    /* memset(ctmp2, 0, 32); */
    /* CHECK(secp256k1_ec_privkey_tweak_add(ctx, ctmp, ctmp2) == 1); */
    /* CHECK(memcmp(orderc, ctmp, 31) == 0 && ctmp[31] == 0x40); */
    /* memcpy(&pubkey2, &pubkey, sizeof(pubkey)); */
    /* CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == 1); */
    /* CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0); */
    /* /1* Multiply tweak of zero zeroizes the output. *1/ */
    /* CHECK(secp256k1_ec_privkey_tweak_mul(ctx, ctmp, ctmp2) == 0); */
    /* CHECK(memcmp(zeros, ctmp, 32) == 0); */
    /* CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, ctmp2) == 0); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(pubkey)) == 0); */
    /* memcpy(&pubkey, &pubkey2, sizeof(pubkey)); */
    /* /1* Overflowing key tweak zeroizes. *1/ */
    /* memcpy(ctmp, orderc, 32); */
    /* ctmp[31] = 0x40; */
    /* CHECK(secp256k1_ec_privkey_tweak_add(ctx, ctmp, orderc) == 0); */
    /* CHECK(memcmp(zeros, ctmp, 32) == 0); */
    /* memcpy(ctmp, orderc, 32); */
    /* ctmp[31] = 0x40; */
    /* CHECK(secp256k1_ec_privkey_tweak_mul(ctx, ctmp, orderc) == 0); */
    /* CHECK(memcmp(zeros, ctmp, 32) == 0); */
    /* memcpy(ctmp, orderc, 32); */
    /* ctmp[31] = 0x40; */
    /* CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, orderc) == 0); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(pubkey)) == 0); */
    /* memcpy(&pubkey, &pubkey2, sizeof(pubkey)); */
    /* CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, orderc) == 0); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(pubkey)) == 0); */
    /* memcpy(&pubkey, &pubkey2, sizeof(pubkey)); */
    /* /1* Private key tweaks results in a key of zero. *1/ */
    /* ctmp2[31] = 1; */
    /* CHECK(secp256k1_ec_privkey_tweak_add(ctx, ctmp2, ctmp) == 0); */
    /* CHECK(memcmp(zeros, ctmp2, 32) == 0); */
    /* ctmp2[31] = 1; */
    /* CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == 0); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(pubkey)) == 0); */
    /* memcpy(&pubkey, &pubkey2, sizeof(pubkey)); */
    /* /1* Tweak computation wraps and results in a key of 1. *1/ */
    /* ctmp2[31] = 2; */
    /* CHECK(secp256k1_ec_privkey_tweak_add(ctx, ctmp2, ctmp) == 1); */
    /* CHECK(memcmp(ctmp2, zeros, 31) == 0 && ctmp2[31] == 1); */
    /* ctmp2[31] = 2; */
    /* CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == 1); */
    /* ctmp2[31] = 1; */
    /* CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, ctmp2) == 1); */
    /* CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0); */
    /* /1* Tweak mul * 2 = 1+1. *1/ */
    /* CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == 1); */
    /* ctmp2[31] = 2; */
    /* CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey2, ctmp2) == 1); */
    /* CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0); */
    /* /1* Test argument errors. *1/ */
    /* ecount = 0; */
    /* /1* secp256k1_context_set_illegal_callback(ctx, counting_illegal_callback_fn, &ecount); *1/ */
    /* CHECK(ecount == 0); */
    /* /1* Zeroize pubkey on parse error. *1/ */
    /* memset(&pubkey, 0, 32); */
    /* CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == 0); */
    /* CHECK(ecount == 1); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(pubkey)) == 0); */
    /* memcpy(&pubkey, &pubkey2, sizeof(pubkey)); */
    /* memset(&pubkey2, 0, 32); */
    /* CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey2, ctmp2) == 0); */
    /* CHECK(ecount == 2); */
    /* CHECK(memcmp(&pubkey2, zeros, sizeof(pubkey2)) == 0); */
    /* /1* Plain argument errors. *1/ */
    /* ecount = 0; */
    /* CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 1); */
    /* CHECK(ecount == 0); */
    /* CHECK(secp256k1_ec_seckey_verify(ctx, NULL) == 0); */
    /* CHECK(ecount == 1); */
    /* ecount = 0; */
    /* memset(ctmp2, 0, 32); */
    /* ctmp2[31] = 4; */
    /* CHECK(secp256k1_ec_pubkey_tweak_add(ctx, NULL, ctmp2) == 0); */
    /* CHECK(ecount == 1); */
    /* CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, NULL) == 0); */
    /* CHECK(ecount == 2); */
    /* ecount = 0; */
    /* memset(ctmp2, 0, 32); */
    /* ctmp2[31] = 4; */
    /* CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, NULL, ctmp2) == 0); */
    /* CHECK(ecount == 1); */
    /* CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, NULL) == 0); */
    /* CHECK(ecount == 2); */
    /* ecount = 0; */
    /* memset(ctmp2, 0, 32); */
    /* CHECK(secp256k1_ec_privkey_tweak_add(ctx, NULL, ctmp2) == 0); */
    /* CHECK(ecount == 1); */
    /* CHECK(secp256k1_ec_privkey_tweak_add(ctx, ctmp, NULL) == 0); */
    /* CHECK(ecount == 2); */
    /* ecount = 0; */
    /* memset(ctmp2, 0, 32); */
    /* ctmp2[31] = 1; */
    /* CHECK(secp256k1_ec_privkey_tweak_mul(ctx, NULL, ctmp2) == 0); */
    /* CHECK(ecount == 1); */
    /* CHECK(secp256k1_ec_privkey_tweak_mul(ctx, ctmp, NULL) == 0); */
    /* CHECK(ecount == 2); */
    /* ecount = 0; */
    /* CHECK(secp256k1_ec_pubkey_create(ctx, NULL, ctmp) == 0); */
    /* CHECK(ecount == 1); */
    /* memset(&pubkey, 1, sizeof(pubkey)); */
    /* CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, NULL) == 0); */
    /* CHECK(ecount == 2); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0); */
    /* /1* secp256k1_ec_pubkey_combine tests. *1/ */
    /* ecount = 0; */
    /* pubkeys[0] = &pubkey_one; */
    /* VG_UNDEF(&pubkeys[0], sizeof(secp256k1_pubkey *)); */
    /* VG_UNDEF(&pubkeys[1], sizeof(secp256k1_pubkey *)); */
    /* VG_UNDEF(&pubkeys[2], sizeof(secp256k1_pubkey *)); */
    /* memset(&pubkey, 255, sizeof(secp256k1_pubkey)); */
    /* VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 0) == 0); */
    /* VG_CHECK(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0); */
    /* CHECK(ecount == 1); */
    /* CHECK(secp256k1_ec_pubkey_combine(ctx, NULL, pubkeys, 1) == 0); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0); */
    /* CHECK(ecount == 2); */
    /* memset(&pubkey, 255, sizeof(secp256k1_pubkey)); */
    /* VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, NULL, 1) == 0); */
    /* VG_CHECK(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0); */
    /* CHECK(ecount == 3); */
    /* pubkeys[0] = &pubkey_negone; */
    /* memset(&pubkey, 255, sizeof(secp256k1_pubkey)); */
    /* VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 1) == 1); */
    /* VG_CHECK(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0); */
    /* CHECK(ecount == 3); */
    /* len = 33; */
    /* /1* CHECK(secp256k1_ec_pubkey_serialize(ctx, ctmp, &len, &pubkey, SECP256K1_EC_COMPRESSED) == 1); *1/ */
    /* /1* CHECK(secp256k1_ec_pubkey_serialize(ctx, ctmp2, &len, &pubkey_negone, SECP256K1_EC_COMPRESSED) == 1); *1/ */
    /* CHECK(memcmp(ctmp, ctmp2, 33) == 0); */
    /* /1* Result is infinity. *1/ */
    /* pubkeys[0] = &pubkey_one; */
    /* pubkeys[1] = &pubkey_negone; */
    /* memset(&pubkey, 255, sizeof(secp256k1_pubkey)); */
    /* VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 2) == 0); */
    /* VG_CHECK(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0); */
    /* CHECK(ecount == 3); */
    /* /1* Passes through infinity but comes out one. *1/ */
    /* pubkeys[2] = &pubkey_one; */
    /* memset(&pubkey, 255, sizeof(secp256k1_pubkey)); */
    /* VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 3) == 1); */
    /* VG_CHECK(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0); */
    /* CHECK(ecount == 3); */
    /* len = 33; */
    /* CHECK(secp256k1_ec_pubkey_serialize(ctx, ctmp, &len, &pubkey, SECP256K1_EC_COMPRESSED) == 1); */
    /* CHECK(secp256k1_ec_pubkey_serialize(ctx, ctmp2, &len, &pubkey_one, SECP256K1_EC_COMPRESSED) == 1); */
    /* CHECK(memcmp(ctmp, ctmp2, 33) == 0); */
    /* /1* Adds to two. *1/ */
    /* pubkeys[1] = &pubkey_one; */
    /* memset(&pubkey, 255, sizeof(secp256k1_pubkey)); */
    /* VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 2) == 1); */
    /* VG_CHECK(&pubkey, sizeof(secp256k1_pubkey)); */
    /* CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0); */
    /* CHECK(ecount == 3); */
    /* /1* secp256k1_context_set_illegal_callback(ctx, NULL, NULL); *1/ */
}

inline char hex_digit_to_char(uchar byte) {
    if (byte <= 9) {
        return '0' + byte;
    } else {
        return 'a' + (byte - 10);
    }
}

void to_hex_string(uchar *slice, size_t slice_len, char *result) {
    for (size_t offset = 0; offset < slice_len; offset++) {
        uchar byte = slice[offset];
        size_t result_index = offset * 2;

        result[result_index + 0] = hex_digit_to_char(byte >>  4);
        result[result_index + 1] = hex_digit_to_char(byte & 0xF);
    }
}

#define PRINT_CHARACTER(literal, variable) do { \
    if (variable == literal[0]) { \
        printf(literal); \
    } \
} while (0)

void print_address(char *address) {
    size_t len = 40;

    if (address[1] == 'x' && address[0] == '0') {
        len += 2;
    }

    for (size_t offset = 0; offset < len; offset++) {
        char character = address[offset];

        CHECK(character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character == 'x');

        PRINT_CHARACTER("0", character);
        PRINT_CHARACTER("1", character);
        PRINT_CHARACTER("2", character);
        PRINT_CHARACTER("3", character);
        PRINT_CHARACTER("4", character);
        PRINT_CHARACTER("5", character);
        PRINT_CHARACTER("6", character);
        PRINT_CHARACTER("7", character);
        PRINT_CHARACTER("8", character);
        PRINT_CHARACTER("9", character);
        PRINT_CHARACTER("a", character);
        PRINT_CHARACTER("b", character);
        PRINT_CHARACTER("c", character);
        PRINT_CHARACTER("d", character);
        PRINT_CHARACTER("e", character);
        PRINT_CHARACTER("f", character);
        PRINT_CHARACTER("x", character);
    }
}

void branch_running(arguments *args) {
    size_t i = get_global_id(0);

    /* if (i == 0) { */
    /*     run_eckey_edge_case_test(&context); */
    /* } */

    if (i != 2) {
        return;
    }

    // needs to be 33 bytes for some reason
    uchar seckey[32] = { 0 };
    seckey[31] = i;

    int result = secp256k1_ec_seckey_verify(&context, (const uchar*) seckey);

    if (result == 0) {
        printf("Core %i result: invalid private key\n", i);
        return;
    }

    secp256k1_pubkey pubkey;

    secp256k1_ec_pubkey_create(&context, &pubkey, (const uchar*) seckey);

    /* hexdump("pubkey raw", (void*) &pubkey.data, 64); */

    // Public key bytes WITH the leading 0x04 byte
    uchar output[65] = { 0 };
    size_t outputlen = 65;

    secp256k1_ec_pubkey_serialize(&context, (uchar*) output, &outputlen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    // Public key bytes WITHOUT the leading 0x04 byte
    uchar *public_key_array = ((uchar*) output) + 1;

    /* hexdump("pubkey ser", public_key_array, 64); */

    keccak_result hash = keccak256(public_key_array, 64);

    /* hexdump("keccak", (void*) hash.array, BITS / 8); */

    char address[42] = { '0', 'x' };

    to_hex_string(&hash.array[ADDRESS_BYTE_INDEX], ADDRESS_BYTES, address + 2);
    printf("Core %i result: ", i);
    print_address(address);
    printf("\n");
}

kernel void entry_point(global uint *input, global secp256k1_context_arg *ctx_arg, global secp256k1_ecmult_context_chunk *chunk) {
    arguments args = (arguments) {
        .input = input,
        .ctx_arg = ctx_arg,
        .chunk = chunk,
    };

    switch (state) {
        case STATE_LOADING_CONTEXT:
            branch_loading_context(&args);
            break;
        case STATE_RUNNING:
            branch_running(&args);
            break;
    }

    input[get_global_id(0)]++;
}
