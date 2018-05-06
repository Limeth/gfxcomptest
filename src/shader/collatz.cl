uint collatz_iterations(uint n) {
    uint sum = 0;

    for (uint i = 0; i < n; i++) {
        sum += n;
    }

    return sum;
}

kernel void collatz_entry_point(global uint *input) {
    size_t i = get_global_id(0);

    input[i] = collatz_iterations(input[i]);
}
