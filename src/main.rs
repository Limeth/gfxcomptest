extern crate ocl;
extern crate secp256k1;

#[macro_use]
mod context;

use context::secp256k1_context_struct_arg;
use context::secp256k1_ecmult_context_chunk;
use context::Secp256k1Context;
use context::ECMULT_TABLE_CHUNKS;
use ocl::traits::OclPrm;
use ocl::ProQue;
use ocl::builders::ProgramBuilder;
use ocl::flags::MemFlags;
use secp256k1::ffi::Context;
use std::fmt;

fn main() -> ocl::Result<()> {
    let mut secp256k1 = Secp256k1Context::new();
    let (ctx_arg, chunks) = secp256k1.copied_without_pointers();

    // debug!("host", "ctx_arg.ecmult_gen_ctx.blind.d[0]", ctx_arg.ecmult_gen_ctx.blind.d[0]);
    // debug!("host", "ctx_arg.ecmult_gen_ctx.initial.infinity", ctx_arg.ecmult_gen_ctx.initial.infinity);
    // debug!("host", "ctx_arg.ecmult_gen_ctx.initial.x.n[0]", ctx_arg.ecmult_gen_ctx.initial.x.n[0]);

    let mut program_builder = ProgramBuilder::new();

    // nVidia has source caching, but it isn't reliable when using #include
    #[cfg(debug_assertions)]
    std::env::set_var("CUDA_CACHE_DISABLE", "1");
    program_builder.cmplr_opt("-cl-std=CL2.0");
    #[cfg(debug_assertions)]
    program_builder.cmplr_def("DEBUG_ASSERTIONS", 1);
    program_builder.src(include_str!("shader/kernel.cl"));

    println!("Compiling shader, this may take a while...");
    let pro_que: ProQue = ProQue::builder()
        .prog_bldr(program_builder)
        .dims(3)
        .build()?;
    let buffer = pro_que.create_buffer::<u32>()?;
    // let ctx_buffer = pro_que.create_buffer::<secp256k1_context_struct_arg>()?;
    let ctx_buffer = pro_que.buffer_builder::<secp256k1_context_struct_arg>()
        .flags(MemFlags::READ_ONLY)
        .build()?;
    let chunk_buffer = pro_que.buffer_builder::<secp256k1_ecmult_context_chunk>()
        .flags(MemFlags::READ_ONLY)
        .build()?;
    // let ctx_buffer = pro_que.buffer_builder::<u64>()
    //     .flags(MemFlags::READ_ONLY)
    //     .build()?;
    let kernel = pro_que.kernel_builder("entry_point")
        .arg(&buffer)
        .arg(&ctx_buffer)
        .arg(&chunk_buffer)
        .build()?;

    let data = [0, 1, 2];

    buffer.write(&data[..]).enq()?;

    let tmp = [ctx_arg];
    ctx_buffer.write(&tmp[..]).enq()?;

    for chunk_index in 0..ECMULT_TABLE_CHUNKS {
        chunk_buffer.write(&chunks[chunk_index..(chunk_index + 1)]).enq()?;
        unsafe { kernel.enq()?; }
    }

    let mut vec = vec![0; buffer.len()];

    buffer.read(&mut vec).enq()?;
    println!("{:?}", vec);

    unsafe { kernel.enq()?; }

    buffer.read(&mut vec).enq()?;
    println!("{:?}", vec);

    Ok(())
}
