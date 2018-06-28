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
/* #include "src/shader/mrg32k3a.cl" */

#define MAX_CYCLES_PER_KERNEL_EXECUTION 32
#define SECRET_KEY_BYTES 32
#define ADDRESS_LENGTH 40
#define ADDRESS_BYTES (ADDRESS_LENGTH / 2)
#define KECCAK_OUTPUT_BYTES 32
#define ADDRESS_BYTE_INDEX (KECCAK_OUTPUT_BYTES - ADDRESS_BYTES)
#define PATTERN_CHUNK_BYTES 1000
#define WORK_GROUP_SIZE (WORK_GROUP_SIZE_X * WORK_GROUP_SIZE_Y * WORK_GROUP_SIZE_Z)

#ifdef DEBUG_ASSERTIONS
# define DEBUG(fmt, arg) printf("[DEVICE DEBUG] " fmt, arg)
#else
# define DEBUG(fmt, arg)
#endif

void run_eckey_edge_case_test(secp256k1_context *ctx);

enum state {
    STATE_LOADING_CONTEXT,
    STATE_LOADING_DICTIONARY,
    STATE_LOADING_SECRET_KEYS,
    STATE_RUNNING,
};

typedef struct {
    uchar array[SECRET_KEY_BYTES];
} secret_key_t;

typedef struct {
    uchar array[ADDRESS_BYTES];
} address_t;

typedef struct {
    secret_key_t seckey;
    address_t address;
} result_t;

typedef struct {
    char patterns_of_length_01[PATTERNS_OF_LENGTH_01][ 1];
    char patterns_of_length_02[PATTERNS_OF_LENGTH_02][ 2];
    char patterns_of_length_03[PATTERNS_OF_LENGTH_03][ 3];
    char patterns_of_length_04[PATTERNS_OF_LENGTH_04][ 4];
    char patterns_of_length_05[PATTERNS_OF_LENGTH_05][ 5];
    char patterns_of_length_06[PATTERNS_OF_LENGTH_06][ 6];
    char patterns_of_length_07[PATTERNS_OF_LENGTH_07][ 7];
    char patterns_of_length_08[PATTERNS_OF_LENGTH_08][ 8];
    char patterns_of_length_09[PATTERNS_OF_LENGTH_09][ 9];
    char patterns_of_length_10[PATTERNS_OF_LENGTH_10][10];
    char patterns_of_length_11[PATTERNS_OF_LENGTH_11][11];
    char patterns_of_length_12[PATTERNS_OF_LENGTH_12][12];
    char patterns_of_length_13[PATTERNS_OF_LENGTH_13][13];
    char patterns_of_length_14[PATTERNS_OF_LENGTH_14][14];
    char patterns_of_length_15[PATTERNS_OF_LENGTH_15][15];
    char patterns_of_length_16[PATTERNS_OF_LENGTH_16][16];
    char patterns_of_length_17[PATTERNS_OF_LENGTH_17][17];
    char patterns_of_length_18[PATTERNS_OF_LENGTH_18][18];
    char patterns_of_length_19[PATTERNS_OF_LENGTH_19][19];
    char patterns_of_length_20[PATTERNS_OF_LENGTH_20][20];
    char patterns_of_length_21[PATTERNS_OF_LENGTH_21][21];
    char patterns_of_length_22[PATTERNS_OF_LENGTH_22][22];
    char patterns_of_length_23[PATTERNS_OF_LENGTH_23][23];
    char patterns_of_length_24[PATTERNS_OF_LENGTH_24][24];
    char patterns_of_length_25[PATTERNS_OF_LENGTH_25][25];
    char patterns_of_length_26[PATTERNS_OF_LENGTH_26][26];
    char patterns_of_length_27[PATTERNS_OF_LENGTH_27][27];
    char patterns_of_length_28[PATTERNS_OF_LENGTH_28][28];
    char patterns_of_length_29[PATTERNS_OF_LENGTH_29][29];
    char patterns_of_length_30[PATTERNS_OF_LENGTH_30][30];
    char patterns_of_length_31[PATTERNS_OF_LENGTH_31][31];
    char patterns_of_length_32[PATTERNS_OF_LENGTH_32][32];
    char patterns_of_length_33[PATTERNS_OF_LENGTH_33][33];
    char patterns_of_length_34[PATTERNS_OF_LENGTH_34][34];
    char patterns_of_length_35[PATTERNS_OF_LENGTH_35][35];
    char patterns_of_length_36[PATTERNS_OF_LENGTH_36][36];
    char patterns_of_length_37[PATTERNS_OF_LENGTH_37][37];
    char patterns_of_length_38[PATTERNS_OF_LENGTH_38][38];
    char patterns_of_length_39[PATTERNS_OF_LENGTH_39][39];
    char patterns_of_length_40[PATTERNS_OF_LENGTH_40][40];
    char *patterns_of_length[40];
    size_t patterns_of_length_lengths[40];
} pattern_dictionary;

typedef struct {
    // The length of the patterns in the `patterns` field
    uint pattern_length;
    // The number of patterns in the `patterns` field
    uint pattern_count;
    // The offset in the patterns array
    uint pattern_offset;
    // The patterns, in bytes.
    char patterns[PATTERN_CHUNK_BYTES];
} patterns_chunk;

typedef struct {
    /* uint *input; */
    secp256k1_context_arg *ctx_arg;
    patterns_chunk *patterns_chunk_buffer;
    secp256k1_ecmult_context_chunk *chunk;
    secret_key_t *seckey;
    uint *cycles;
    uint *result_queue_length;
    result_t *result_queue;
} arguments;

global static volatile atomic_uint result_queue_length_atomic = ATOMIC_VAR_INIT(0);
global static bool state = STATE_LOADING_CONTEXT;
global static uint loading_index = 0;
global static secp256k1_ge_storage pre_g[ECMULT_TABLE_SIZE(WINDOW_G)];
#ifdef USE_ENDOMORPHISM
global static secp256k1_ge_storage pre_g_128[ECMULT_TABLE_SIZE(WINDOW_G)];
#endif
global static secp256k1_context context;
global static pattern_dictionary dictionary;
global static secret_key_t current_secret_keys[GLOBAL_WORK_SIZE];
/* static global mrg32k3a_context rngs[GLOBAL_WORK_SIZE]; */

// only literal strings may be passed to printf
#ifdef DEBUG_ASSERTIONS
#   define hexdump(label, pointer, bytes) do { \
        DEBUG("%s hexdump:", label); \
        hexdump_impl(pointer, bytes); \
    } while(0)
#else
#   define hexdump(label, pointer, bytes)
#endif

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

#define PRINT_CHARACTER(literal, variable) do { \
    if (variable == literal[0]) { \
        printf(literal); \
    } \
} while (0)

void print_address_bytes_len(char *address, size_t len) {
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

void print_address_bytes(char *address, bool includeHexPrefix) {
    print_address_bytes_len(address, ADDRESS_LENGTH + (includeHexPrefix ? 2 : 0));
}

inline char hex_digit_to_char(uchar byte) {
#ifdef DEBUG_ASSERTIONS
    if (byte < 10) {
        return '0' + byte;
    } else if (byte < 16) {
        return 'a' + (byte - 10);
    } else {
        printf("Invalid hex digit of value `%u`\n", byte);
        abort();
        return 0;
    }
#else
    if (byte < 10) {
        return '0' + byte;
    } else {
        return 'a' + (byte - 10);
    }
#endif
}

void to_hex_string(uchar *slice, size_t slice_len, char *result) {
    for (size_t offset = 0; offset < slice_len; offset++) {
        uchar byte = slice[offset];
        size_t result_index = offset * 2;

        result[result_index + 0] = hex_digit_to_char(byte >>  4);
        result[result_index + 1] = hex_digit_to_char(byte & 0xF);
    }
}

void serialize_address(char *result, address_t *address, bool includeHexPrefix) {
    if (includeHexPrefix) {
        result[0] = '0';
        result[1] = 'x';
    }

    to_hex_string((uchar*) &address->array, ADDRESS_BYTES, result + (includeHexPrefix ? 2 : 0));
}

void print_address(address_t *address, bool includeHexPrefix) {
    if (includeHexPrefix) {
        char serialized[ADDRESS_LENGTH + 2] = { 0 };
        serialize_address((char*) &serialized, address, true);
        print_address_bytes((char*) &serialized, true);
    } else {
        char serialized[ADDRESS_LENGTH] = { 0 };
        serialize_address((char*) &serialized, address, false);
        print_address_bytes((char*) &serialized, false);
    }
}

void secret_key_increment(secret_key_t *seckey) {
    for (size_t i = 0; i < SECRET_KEY_BYTES; i++) {
        size_t byte_index = SECRET_KEY_BYTES - 1 - i;
        uchar *byte = &seckey->array[byte_index];

        if (*byte == 0xFF) {
            *byte = 0x00;
        } else {
            (*byte)++;
            break;
        }
    }

    work_group_barrier(CLK_GLOBAL_MEM_FENCE | CLK_LOCAL_MEM_FENCE);
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
        state = STATE_LOADING_DICTIONARY;
        loading_index = 0;

        hexdump("context", &context, sizeof(secp256k1_context));
        hexdump("first 16 bytes of pre_g", context.ecmult_ctx.pre_g, 16);
        hexdump("first 16 bytes of pre_g_128", context.ecmult_ctx.pre_g_128, 16);
        hexdump("first 16 bytes of prec", context.ecmult_gen_ctx.prec, 16);
        hexdump("last 16 bytes of pre_g", ((uchar*) context.ecmult_ctx.pre_g) + (ECMULT_TABLE_SIZE(WINDOW_G)) * sizeof(secp256k1_ge_storage) - 16, 16);
        hexdump("last 16 bytes of pre_g_128", ((uchar*) context.ecmult_ctx.pre_g_128) + (ECMULT_TABLE_SIZE(WINDOW_G)) * sizeof(secp256k1_ge_storage) - 16, 16);
        hexdump("last 16 bytes of prec", ((uchar*) context.ecmult_gen_ctx.prec) + (16 * 64) * sizeof(secp256k1_ge_storage) - 16, 16);

#ifdef DEBUG_ASSERTIONS
        // Takes really long to compile, commented out to speed up development
        /* run_eckey_edge_case_test(&context); */
#endif
    }
}

void branch_loading_context(arguments *args) {
    size_t i = get_global_linear_id();

    if (i == 0) {
        branch_loading_context_atomic(args);
    }

    work_group_barrier(CLK_GLOBAL_MEM_FENCE | CLK_LOCAL_MEM_FENCE);
}

void initialize_dictionary() {
    dictionary = (pattern_dictionary) {};

    dictionary.patterns_of_length[ 0] = (char *__global) dictionary.patterns_of_length_01;
    dictionary.patterns_of_length[ 1] = (char *__global) dictionary.patterns_of_length_02;
    dictionary.patterns_of_length[ 2] = (char *__global) dictionary.patterns_of_length_03;
    dictionary.patterns_of_length[ 3] = (char *__global) dictionary.patterns_of_length_04;
    dictionary.patterns_of_length[ 4] = (char *__global) dictionary.patterns_of_length_05;
    dictionary.patterns_of_length[ 5] = (char *__global) dictionary.patterns_of_length_06;
    dictionary.patterns_of_length[ 6] = (char *__global) dictionary.patterns_of_length_07;
    dictionary.patterns_of_length[ 7] = (char *__global) dictionary.patterns_of_length_08;
    dictionary.patterns_of_length[ 8] = (char *__global) dictionary.patterns_of_length_09;
    dictionary.patterns_of_length[ 9] = (char *__global) dictionary.patterns_of_length_10;
    dictionary.patterns_of_length[10] = (char *__global) dictionary.patterns_of_length_11;
    dictionary.patterns_of_length[11] = (char *__global) dictionary.patterns_of_length_12;
    dictionary.patterns_of_length[12] = (char *__global) dictionary.patterns_of_length_13;
    dictionary.patterns_of_length[13] = (char *__global) dictionary.patterns_of_length_14;
    dictionary.patterns_of_length[14] = (char *__global) dictionary.patterns_of_length_15;
    dictionary.patterns_of_length[15] = (char *__global) dictionary.patterns_of_length_16;
    dictionary.patterns_of_length[16] = (char *__global) dictionary.patterns_of_length_17;
    dictionary.patterns_of_length[17] = (char *__global) dictionary.patterns_of_length_18;
    dictionary.patterns_of_length[18] = (char *__global) dictionary.patterns_of_length_19;
    dictionary.patterns_of_length[19] = (char *__global) dictionary.patterns_of_length_20;
    dictionary.patterns_of_length[20] = (char *__global) dictionary.patterns_of_length_21;
    dictionary.patterns_of_length[21] = (char *__global) dictionary.patterns_of_length_22;
    dictionary.patterns_of_length[22] = (char *__global) dictionary.patterns_of_length_23;
    dictionary.patterns_of_length[23] = (char *__global) dictionary.patterns_of_length_24;
    dictionary.patterns_of_length[24] = (char *__global) dictionary.patterns_of_length_25;
    dictionary.patterns_of_length[25] = (char *__global) dictionary.patterns_of_length_26;
    dictionary.patterns_of_length[26] = (char *__global) dictionary.patterns_of_length_27;
    dictionary.patterns_of_length[27] = (char *__global) dictionary.patterns_of_length_28;
    dictionary.patterns_of_length[28] = (char *__global) dictionary.patterns_of_length_29;
    dictionary.patterns_of_length[29] = (char *__global) dictionary.patterns_of_length_30;
    dictionary.patterns_of_length[30] = (char *__global) dictionary.patterns_of_length_31;
    dictionary.patterns_of_length[31] = (char *__global) dictionary.patterns_of_length_32;
    dictionary.patterns_of_length[32] = (char *__global) dictionary.patterns_of_length_33;
    dictionary.patterns_of_length[33] = (char *__global) dictionary.patterns_of_length_34;
    dictionary.patterns_of_length[34] = (char *__global) dictionary.patterns_of_length_35;
    dictionary.patterns_of_length[35] = (char *__global) dictionary.patterns_of_length_36;
    dictionary.patterns_of_length[36] = (char *__global) dictionary.patterns_of_length_37;
    dictionary.patterns_of_length[37] = (char *__global) dictionary.patterns_of_length_38;
    dictionary.patterns_of_length[38] = (char *__global) dictionary.patterns_of_length_39;
    dictionary.patterns_of_length[39] = (char *__global) dictionary.patterns_of_length_40;
    dictionary.patterns_of_length_lengths[ 0] = PATTERNS_OF_LENGTH_01;
    dictionary.patterns_of_length_lengths[ 1] = PATTERNS_OF_LENGTH_02;
    dictionary.patterns_of_length_lengths[ 2] = PATTERNS_OF_LENGTH_03;
    dictionary.patterns_of_length_lengths[ 3] = PATTERNS_OF_LENGTH_04;
    dictionary.patterns_of_length_lengths[ 4] = PATTERNS_OF_LENGTH_05;
    dictionary.patterns_of_length_lengths[ 5] = PATTERNS_OF_LENGTH_06;
    dictionary.patterns_of_length_lengths[ 6] = PATTERNS_OF_LENGTH_07;
    dictionary.patterns_of_length_lengths[ 7] = PATTERNS_OF_LENGTH_08;
    dictionary.patterns_of_length_lengths[ 8] = PATTERNS_OF_LENGTH_09;
    dictionary.patterns_of_length_lengths[ 9] = PATTERNS_OF_LENGTH_10;
    dictionary.patterns_of_length_lengths[10] = PATTERNS_OF_LENGTH_11;
    dictionary.patterns_of_length_lengths[11] = PATTERNS_OF_LENGTH_12;
    dictionary.patterns_of_length_lengths[12] = PATTERNS_OF_LENGTH_13;
    dictionary.patterns_of_length_lengths[13] = PATTERNS_OF_LENGTH_14;
    dictionary.patterns_of_length_lengths[14] = PATTERNS_OF_LENGTH_15;
    dictionary.patterns_of_length_lengths[15] = PATTERNS_OF_LENGTH_16;
    dictionary.patterns_of_length_lengths[16] = PATTERNS_OF_LENGTH_17;
    dictionary.patterns_of_length_lengths[17] = PATTERNS_OF_LENGTH_18;
    dictionary.patterns_of_length_lengths[18] = PATTERNS_OF_LENGTH_19;
    dictionary.patterns_of_length_lengths[19] = PATTERNS_OF_LENGTH_20;
    dictionary.patterns_of_length_lengths[20] = PATTERNS_OF_LENGTH_21;
    dictionary.patterns_of_length_lengths[21] = PATTERNS_OF_LENGTH_22;
    dictionary.patterns_of_length_lengths[22] = PATTERNS_OF_LENGTH_23;
    dictionary.patterns_of_length_lengths[23] = PATTERNS_OF_LENGTH_24;
    dictionary.patterns_of_length_lengths[24] = PATTERNS_OF_LENGTH_25;
    dictionary.patterns_of_length_lengths[25] = PATTERNS_OF_LENGTH_26;
    dictionary.patterns_of_length_lengths[26] = PATTERNS_OF_LENGTH_27;
    dictionary.patterns_of_length_lengths[27] = PATTERNS_OF_LENGTH_28;
    dictionary.patterns_of_length_lengths[28] = PATTERNS_OF_LENGTH_29;
    dictionary.patterns_of_length_lengths[29] = PATTERNS_OF_LENGTH_30;
    dictionary.patterns_of_length_lengths[30] = PATTERNS_OF_LENGTH_31;
    dictionary.patterns_of_length_lengths[31] = PATTERNS_OF_LENGTH_32;
    dictionary.patterns_of_length_lengths[32] = PATTERNS_OF_LENGTH_33;
    dictionary.patterns_of_length_lengths[33] = PATTERNS_OF_LENGTH_34;
    dictionary.patterns_of_length_lengths[34] = PATTERNS_OF_LENGTH_35;
    dictionary.patterns_of_length_lengths[35] = PATTERNS_OF_LENGTH_36;
    dictionary.patterns_of_length_lengths[36] = PATTERNS_OF_LENGTH_37;
    dictionary.patterns_of_length_lengths[37] = PATTERNS_OF_LENGTH_38;
    dictionary.patterns_of_length_lengths[38] = PATTERNS_OF_LENGTH_39;
    dictionary.patterns_of_length_lengths[39] = PATTERNS_OF_LENGTH_40;
}

bool dictionary_loading_finished(arguments *args) {
    patterns_chunk *arg = args->patterns_chunk_buffer;

    return arg->pattern_length == 0 && arg->pattern_count == 0 && arg->pattern_offset == 0;
}

void branch_loading_dictionary_atomic(arguments *args) {
    if (loading_index == 0) {
        initialize_dictionary();
    }

    loading_index++;

    if (dictionary_loading_finished(args)) {
        state = STATE_LOADING_SECRET_KEYS;
        loading_index = 0;
        return;
    }

    patterns_chunk *arg = args->patterns_chunk_buffer;

    /* printf("_\n"); */
    /* printf("pattern_length: %u\n", arg->pattern_length); */
    /* printf("pattern_offset: %u\n", arg->pattern_offset); */
    /* printf("pattern_count: %u\n", arg->pattern_count); */

    memcpy(&dictionary.patterns_of_length[arg->pattern_length - 1][arg->pattern_offset],
           arg->patterns,
           arg->pattern_length * arg->pattern_count);

#ifdef DEBUG_ASSERTIONS
    DEBUG("Loaded pattern: ", NULL);
    print_address_bytes_len(&dictionary.patterns_of_length[arg->pattern_length - 1][arg->pattern_offset], arg->pattern_length);
    printf("\n");
#endif
}

void branch_loading_dictionary(arguments *args) {
    size_t i = get_global_linear_id();

    if (i == 0) {
        branch_loading_dictionary_atomic(args);
    }

    work_group_barrier(CLK_GLOBAL_MEM_FENCE | CLK_LOCAL_MEM_FENCE);
}

void branch_loading_secret_keys_atomic(arguments *args) {
    current_secret_keys[loading_index] = args->seckey[0];

    /* printf("seckey #%u loaded, first byte: %u\n", loading_index, current_secret_keys[loading_index].array[0]); */

    if (loading_index >= GLOBAL_WORK_SIZE - 1) {
        state = STATE_RUNNING;
        loading_index = 0;
        return;
    }

    loading_index++;
}

void branch_loading_secret_keys(arguments *args) {
    size_t i = get_global_linear_id();

    if (i == 0) {
        branch_loading_secret_keys_atomic(args);
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

bool is_secret_key_valid(secret_key_t *seckey) {
    return secp256k1_ec_seckey_verify(&context, (const uchar*) &seckey->array) != 0;
}

address_t derive_address(secret_key_t *seckey) {
    secp256k1_pubkey pubkey;

    secp256k1_ec_pubkey_create(&context, &pubkey, (const uchar*) &seckey->array);

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

    address_t address;

    memcpy(&address.array, &hash.array[ADDRESS_BYTE_INDEX], ADDRESS_BYTES);

    return address;
}

bool binary_search(void *item, void *array, size_t item_bytes, size_t array_len) {
    if (array_len == 0) {
        return false;
    }

    size_t middle_index = array_len / 2;
    void *middle_item = array + middle_index * item_bytes;
    int cmp = memcmp(item, middle_item, item_bytes);

    /* printf("cmp: %d\n", cmp); */

    size_t sub_array_len;
    size_t sub_array_offset;

    if (cmp == 0) {
        return true;
    } else if (cmp < 0) {
        sub_array_len = middle_index;
        sub_array_offset = 0;
    } else { // cmp > 0
        sub_array_len = array_len - middle_index - 1;
        sub_array_offset = middle_index + 1;
    }

    void *sub_array = array + sub_array_offset * item_bytes;

    return binary_search(item, sub_array, item_bytes, sub_array_len);
}

bool is_address_desirable(address_t *address) {
    char address_string[ADDRESS_LENGTH];
    bool match_found = false;

    serialize_address(&address_string, address, false);

    for (size_t pattern_len = 1; pattern_len <= ADDRESS_LENGTH; pattern_len++) {
        char *patterns = dictionary.patterns_of_length[pattern_len - 1];
        size_t patterns_len = dictionary.patterns_of_length_lengths[pattern_len - 1];
        match_found = binary_search(&address_string, patterns, pattern_len, patterns_len);

        /* printf("address: "); */
        /* print_address_bytes(&address_string, false); */
        /* printf("\tpattern_len: %li\tpatterns_len: %li\tpatterns[0]: ", pattern_len, patterns_len); */
        /* print_address_bytes_len(&patterns[0], pattern_len); */
        /* printf("\tmatch_found: %u\n", match_found); */

        if (match_found) {
            break;
        }
    }

    work_group_barrier(CLK_GLOBAL_MEM_FENCE | CLK_LOCAL_MEM_FENCE);

    return match_found;
}

bool attempt_next_match(result_t *result) {
    size_t i = get_global_linear_id();
    bool match_found = false;

    // might need to be 33 bytes for some reason
    secret_key_t *seckey = &current_secret_keys[i];

    if (is_secret_key_valid(seckey)) {
        address_t address = derive_address(seckey);

        if (is_address_desirable(&address)) {
            match_found = true;
            *result = (result_t) {
                .seckey = *seckey,
                .address = address,
            };
            /* printf("Work item %i result:\t", i); */
            /* print_address(&address, true); */
            /* printf("\tsecret key: "); */
            /* char seckey_string[SECRET_KEY_BYTES * 2]; */
            /* to_hex_string(&seckey->array, SECRET_KEY_BYTES, &seckey_string); */
            /* print_address_bytes_len(&seckey_string, SECRET_KEY_BYTES * 2); */
            /* printf("\n"); */
        }
    }

    secret_key_increment(seckey);

    return match_found;
}

void branch_running(arguments *args) {
    atomic_store(&result_queue_length_atomic, 0);
    args->result_queue_length[0] = 0;
    uint i;

    for (i = 0; i < MAX_CYCLES_PER_KERNEL_EXECUTION && args->result_queue_length[0] < RESULT_QUEUE_CAPACITY; i++) {
        result_t result;

        if (attempt_next_match(&result)) {
            uint queue_index = atomic_fetch_add_explicit(
                    &result_queue_length_atomic, 1, memory_order_relaxed, memory_scope_device);

            if (queue_index < RESULT_QUEUE_CAPACITY) {
                args->result_queue[queue_index] = result;
            }
        }

        work_group_barrier(CLK_GLOBAL_MEM_FENCE | CLK_LOCAL_MEM_FENCE);

        args->result_queue_length[0] = atomic_load(&result_queue_length_atomic);
    }

    work_group_barrier(CLK_GLOBAL_MEM_FENCE | CLK_LOCAL_MEM_FENCE);

    args->cycles[0] = i;

    if (args->result_queue_length[0] > RESULT_QUEUE_CAPACITY) {
        args->result_queue_length[0] = RESULT_QUEUE_CAPACITY;
    }
}

__attribute__((reqd_work_group_size(WORK_GROUP_SIZE_X, WORK_GROUP_SIZE_Y, WORK_GROUP_SIZE_Z)))
kernel void entry_point(
    /*global uint *input, */
    global secp256k1_context_arg *ctx_arg,
    global patterns_chunk *patterns_chunk_buffer,
    global secp256k1_ecmult_context_chunk *chunk,
    global secret_key_t *seckey,
    global uint *cycles,
    global uint *result_queue_length,
    global result_t *result_queue
    /* global mrg32k3a_context *mrg32k3a_ctx */
) {
    arguments args = (arguments) {
        /* .input = input, */
        .ctx_arg = ctx_arg,
        .patterns_chunk_buffer = patterns_chunk_buffer,
        .chunk = chunk,
        .seckey = seckey,
        .cycles = cycles,
        .result_queue_length = result_queue_length,
        .result_queue = result_queue,
    };

    switch (state) {
        case STATE_LOADING_CONTEXT:
            branch_loading_context(&args);
            break;
        case STATE_LOADING_DICTIONARY:
            branch_loading_dictionary(&args);
            break;
        case STATE_LOADING_SECRET_KEYS:
            branch_loading_secret_keys(&args);
            break;
        case STATE_RUNNING:
            branch_running(&args);
            break;
    }

    /* size_t lli = get_local_linear_id(); */
    /* local int loc[WORK_GROUP_SIZE]; */
    /* private int priv[WORK_GROUP_SIZE]; */

    /* if (loading_index == 1 && state == STATE_LOADING_CONTEXT) { */
    /*     loc[lli] = 0; */
    /*     priv[lli] = 0; */
    /*     printf("incrementing %li\n", lli); */
    /* } else { */
    /*     loc[lli]++; */
    /*     priv[lli]++; */
    /*     printf("incrementing %li\n", lli); */
    /* } */

    /* printf("global_id: %lu\tlocal_id: %lu\tloc: %i\tpriv: %i\n", get_global_id(0), get_local_id(0), loc[lli], priv[lli]); */
    /* printf("global_id: %lu\tlocal_id: %lu\n", get_global_id(0), get_local_id(0)); */

    /* if (get_global_id(0) == 0) { */
    /*     printf("global_size: %lu\tlocal_size: %lu\n", get_global_size(0), get_local_size(0)); */
    /* } */

    /* input[get_global_id(0)]++; */
}
