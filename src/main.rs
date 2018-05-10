extern crate ocl;
extern crate secp256k1;

#[macro_use]
mod context;

use context::secp256k1_context_struct_arg;
use context::ecmult_table_chunk;
use context::Secp256k1Context;
use ocl::traits::OclPrm;
use ocl::ProQue;
use ocl::flags::MemFlags;
use secp256k1::ffi::Context;
use std::fmt;

fn main() -> ocl::Result<()> {
    let mut secp256k1 = Secp256k1Context::new();
    let (ctx_arg, chunks) = secp256k1.copied_without_pointers();

    debug!("host", "ctx_arg.ecmult_gen_ctx.blind.d[0]", ctx_arg.ecmult_gen_ctx.blind.d[0]);
    debug!("host", "ctx_arg.ecmult_gen_ctx.initial.infinity", ctx_arg.ecmult_gen_ctx.initial.infinity);
    debug!("host", "ctx_arg.ecmult_gen_ctx.initial.x.n[0]", ctx_arg.ecmult_gen_ctx.initial.x.n[0]);

    let src = include_str!("shader/collatz.cl");
    let pro_que: ProQue = ProQue::builder()
        .src(src)
        .dims(1)
        .build()?;
    let buffer = pro_que.create_buffer::<u32>()?;
    // let ctx_buffer = pro_que.create_buffer::<secp256k1_context_struct_arg>()?;
    let ctx_buffer = pro_que.buffer_builder::<secp256k1_context_struct_arg>()
        .flags(MemFlags::READ_ONLY)
        .build()?;
    let chunk_buffer = pro_que.buffer_builder::<ecmult_table_chunk>()
        .flags(MemFlags::READ_ONLY)
        .build()?;
    // let ctx_buffer = pro_que.buffer_builder::<u64>()
    //     .flags(MemFlags::READ_ONLY)
    //     .build()?;
    let kernel = pro_que.kernel_builder("entry_point")
        .arg(&buffer)
        .arg(10)
        .arg(&ctx_buffer)
        .arg(&chunk_buffer)
        .build()?;

    let data = [0];

    buffer.write(&data[..]).enq()?;
    let tmp = [ctx_arg];
    ctx_buffer.write(&tmp[..]).enq()?;
    let tmp = [ecmult_table_chunk::default()];
    chunk_buffer.write(&tmp[..]).enq()?;

    unsafe { kernel.enq()?; }

    let mut vec = vec![0; buffer.len()];

    buffer.read(&mut vec).enq()?;
    println!("{:?}", vec);

    Ok(())
}
