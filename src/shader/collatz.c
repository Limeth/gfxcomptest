#define i32 int
#define u32 uint
#define isize size_t

u32 collatz_iterations(u32 n) {
    u32 sum = 0;

    for (u32 i = 0; i < n; i++) {
        sum += n;
    }

    return sum;
}

kernel void collatz_entry_point(global u32 *input) {
    isize i = get_global_id(0);

    input[i] = collatz_iterations(input[i]);
}
