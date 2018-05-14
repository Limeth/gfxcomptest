//! Note: Sequential execution doesn't fix `printf` interleaving
//! Actually, this doesn't seem to work at all.

void begin_sequential_execution(atomic_flag *flag) {
    work_group_barrier(CLK_GLOBAL_MEM_FENCE | CLK_LOCAL_MEM_FENCE);
    bool wait;

    do {
        wait = atomic_flag_test_and_set_explicit(flag, memory_order_seq_cst, memory_scope_device);
    } while (wait);
}

void end_sequential_execution(atomic_flag *flag) {
    atomic_flag_clear_explicit(flag, memory_order_seq_cst, memory_scope_device);
    work_group_barrier(CLK_GLOBAL_MEM_FENCE | CLK_LOCAL_MEM_FENCE);
}
