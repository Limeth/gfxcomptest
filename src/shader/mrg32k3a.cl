/*
   32-bits Random number generator U(0,1): MRG32k3a
   Author of the original C implementation: Pierre L'Ecuyer,
   Source: Good Parameter Sets for Combined Multiple Recursive Random
           Number Generators,
           Shorter version in Operations Research,
           47, 1 (1999), 159--164.
   ---------------------------------------------------------
*/

#define norm 2.328306549295728e-10
#define m1   4294967087
#define m2   4294944443
#define a12     1403580
#define a13n     810728
#define a21      527612
#define a23n    1370589
#define MRG32K3A_SEEDS_LEN 6
#define MRG32K3A_SEEDS_BYTES (MRG32K3A_SEEDS_LEN * 8)

typedef struct {
    ulong s1[3];
    ulong s2[3];
} mrg32k3a_context;

/***
The seeds for s1[0], s1[1], s1[2] must be integers in <0; m1 - 1> and not all 0. 
The seeds for s2[0], s2[1], s2[2] must be integers in <0; m2 - 1> and not all 0. 
***/
bool mrg32k3a_context_create(ulong[MRG32K3A_SEEDS_LEN] seeds, mrg32k3a_context *uninitialized) {
    for (int i = 0; i < 3; i++) {
        if (seeds[i] > m1 - 1) {
            return false;
        }
    }

    for (int i = 3; i < 6; i++) {
        if (seeds[i] > m2 - 1) {
            return false;
        }
    }

    uint zero = 0;

    for (int i = 0; i < 6; i++) {
        zero |= seeds[i];
    }

    if (zero == 0) {
        return false;
    }

    *uninitialized = (mrg32k3a_context) {
        .s1 = { seeds[0], seeds[1], seeds[2] },
        .s2 = { seeds[3], seeds[4], seeds[5] },
    };

    return true;
}

/*
 * The `seed_buffer` must contain `MRG32K3A_SEEDS_BYTES * get_global_size`
 * random bytes, where `get_global_size` is the total number of work items.
 */
bool mrg32k3a_context_create_work_item(constant uchar *seed_buffer, mrg32k3a_context *uninitialized) {
    size_t id = get_global_linear_id();
    size_t offset = id * MRG32K3A_SEEDS_BYTES;
    ulong *seeds_pointer = (ulong*) (seed_buffer + offset);
    ulong[MRG32K3A_SEEDS_LEN] seeds = { 0 };

    for (size_t i = 0; i < MRG32K3A_SEEDS_LEN; i++) {
        seeds[i] = seeds_pointer[i];
    }

    return mrg32k3a_context_create(seeds, context);
}

/*
 * Returns an unsigned long in the range <1; m1>
 */
ulong mrg32k3a_next_state(mrg32k3a_context *context) {
    ulong* s1 = context->s1;
    ulong* s2 = context->s2;
    long p1, p2;

    /* Component 1 */
    p1 = a12 * s1[1] - a13n * s1[0];
    p1 %= m1;

    if (p1 < 0)
        p1 += m1;

    s1[0] = s1[1];
    s1[1] = s1[2];
    s1[2] = p1;

    /* Component 2 */
    p2 = a21 * s1[2] - a23n * s1[0];
    p2 %= m2;

    if (p2 < 0)
        p2 += m2;

    s1[0] = s1[1];
    s1[1] = s1[2];
    s1[2] = p2;

    /* Combinations */
    if (p1 <= p2) {
        return p1 - p2 + m1;
    } else {
        return p1 - p2;
    }
}

uint mrg32k3a_next_int(mrg32k3a_context *context) {
    return (uint) (mrg32k3a_next_state(context) * norm);
}
