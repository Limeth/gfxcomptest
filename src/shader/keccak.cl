#define PLEN 25
#define BITS 256
#define DELIM 0x01

constant const uint RHO[24] = {
     1,  3,  6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44
};

constant const size_t PI[24] = {
    10,  7, 11, 17, 18, 3,
     5, 16,  8, 21, 24, 4,
    15, 23, 19, 13, 12, 2,
    20, 14, 22,  9,  6, 1
};

constant const ulong RC[24] = {
    1UL, 0x8082UL, 0x800000000000808aUL, 0x8000000080008000UL,
    0x808bUL, 0x80000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x8aUL, 0x88UL, 0x80008009UL, 0x8000000aUL,
    0x8000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x80000001UL, 0x8000000080008008UL
};

typedef struct {
    uchar array[BITS / 8];
} keccak_result;

typedef struct {
    ulong a[PLEN];
    size_t offset;
    size_t rate;
    uchar delim;
} Keccak;

inline ulong u64_rotate_left(ulong self, uint n_pre) {
    // Protect against undefined behaviour for over-long bit shifts
    uint n = n_pre % 64;
    return (self << n) | (self >> ((64 - n) % 64));
}

void keccakf(ulong a[PLEN]) {
    ulong arrays[24][5] = { { 0 } };

    /* __attribute__((opencl_unroll_hint)) */
    for (size_t i = 0; i < 24; i++) {
        // Theta
        /* __attribute__((opencl_unroll_hint)) */
        for (size_t x = 0; x < 5; x++) {
            arrays[i][x] = 0;

            /* __attribute__((opencl_unroll_hint)) */
            for (size_t y_count = 0; y_count < 5; y_count++) {
                size_t y = y_count * 5;
                arrays[i][x] ^= a[x + y];
            }
        }

        /* __attribute__((opencl_unroll_hint)) */
        for (size_t x = 0; x < 5; x++) {
            /* __attribute__((opencl_unroll_hint)) */
            for (size_t y_count = 0; y_count < 5; y_count++) {
                size_t y = y_count * 5;
                a[y + x] ^= arrays[i][(x + 4) % 5] ^ u64_rotate_left(arrays[i][(x + 1) % 5], 1);
            }
        }

        // Rho and pi
        ulong last = a[1];

        /* __attribute__((opencl_unroll_hint)) */
        for (size_t x = 0; x < 24; x++) {
            arrays[i][0] = a[PI[x]];
            a[PI[x]] = u64_rotate_left(last, RHO[x]);
            last = arrays[i][0];
        }

        // Chi
        /* __attribute__((opencl_unroll_hint)) */
        for (size_t y_step = 0; y_step < 5; y_step++) {
            size_t y = y_step * 5;

            /* __attribute__((opencl_unroll_hint)) */
            for (size_t x = 0; x < 5; x++) {
                arrays[i][x] = a[y + x];
            }

            /* __attribute__((opencl_unroll_hint)) */
            for (size_t x = 0; x < 5; x++) {
                a[y + x] = arrays[i][x] ^ ((~arrays[i][(x + 1) % 5]) & (arrays[i][(x + 2) % 5]));
            }
        }

        // Iota
        a[0] ^= RC[i];
    }
}

Keccak Keccak_new(size_t rate, uchar delim) {
    return (Keccak) {
        .a = { 0 },
        .offset = 0,
        .rate = rate,
        .delim = delim,
    };
}

Keccak Keccak_new_keccak256() {
    return Keccak_new(200 - BITS/4, DELIM);
}

void xorin(uchar *dst, size_t dst_len, const uchar *src, size_t src_len) {
    CHECK(dst_len <= src_len);

    for (int i = 0; i < dst_len; i++) {
        *dst ^= *src;
        src++;
        dst++;
    }
}

void Keccak_absorb(Keccak *self, const uchar *input, const size_t input_len) {
    //first foldp
    size_t ip = 0;
    size_t l = input_len;
    size_t rate = self->rate - self->offset;
    size_t offset = self->offset;

    while (l >= rate) {
        xorin(((uchar*) self->a) + offset, rate, input + ip, input_len - ip);
        keccakf((ulong*) self->a);
        ip += rate;
        l -= rate;
        rate = self->rate;
        offset = 0;
    }

    // Xor in the last block
    xorin(((uchar*) self->a) + offset, l, input + ip, input_len - ip);
    self->offset = offset + l;
}

void Keccak_pad(Keccak *self) {
    size_t offset = self->offset;
    size_t rate = self->rate;
    uchar delim = self->delim;
    uchar *aa = (uchar*) self->a;
    aa[offset] ^= delim;
    aa[rate - 1] ^= 0x80;
}

void setout(const uchar *src, uchar *dst, const size_t len) {
    memcpy(dst, src, len);
}

void Keccak_squeeze(Keccak *self, uchar *output, const size_t output_len) {
    // second foldp
    size_t op = 0;
    size_t l = output_len;
    while (l >= self->rate) {
        setout((const uchar*) self->a, output + op, self->rate);
        keccakf((ulong*) &self->a);
        op += self->rate;
        l -= self->rate;
    }

    setout((const uchar*) self->a, output + op, l);
}

void Keccak_finalize(Keccak *self, uchar *output, const size_t output_len) {
    Keccak_pad(self);

    // apply keccakf
    keccakf((ulong*) self->a);

    // squeeze output
    Keccak_squeeze(self, output, output_len);
}

void Keccak_update(Keccak *self, const uchar *input, const size_t input_len) {
    Keccak_absorb(self, input, input_len);
}

void Keccak_keccak256(const uchar *data, const size_t data_len, uchar *result, const size_t result_len) {
    Keccak keccak = Keccak_new_keccak256();
    Keccak_update(&keccak, data, data_len);
    Keccak_finalize(&keccak, result, result_len);
}

keccak_result keccak256(const uchar *data, const size_t data_len) {
    keccak_result result = (keccak_result) {
        .array = { 0 },
    };

    Keccak_keccak256(data, data_len, result.array, BITS / 8);

    return result;
}
