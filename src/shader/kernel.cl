#include "src/shader/secp256k1.cl"

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

void memcpy(void *dst, void *src, size_t len) {
    for (size_t offset = 0; offset < len; offset++) {
        ((uchar*) dst)[offset] = ((uchar*) src)[offset];
    }
}

// only literal strings may be passed to printf
#define hexdump(label, pointer, bytes) do { \
    printf("[device] %s hexdump:", label); \
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
    printf("loading_context_atomic\n");

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

    work_group_barrier(CLK_GLOBAL_MEM_FENCE);
}

void branch_running(arguments *args) {
    size_t i = get_global_id(0);
    printf("running in parallel\n");
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
