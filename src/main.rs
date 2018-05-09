extern crate ocl;
extern crate secp256k1;

#[macro_use]
mod context;

use context::secp256k1_context_struct_arg;
use ocl::traits::OclPrm;
use ocl::ProQue;
use ocl::flags::MemFlags;
use secp256k1::ffi::Context;
use std::fmt;

const SIZE: usize = 335_000;

#[derive(Clone, Copy)]
struct SomeType([u8; SIZE]);

impl_array!(SomeType([u8; SIZE]));

unsafe impl OclPrm for SomeType {}

type TypeAlias = secp256k1_context_struct_arg;

fn main() -> ocl::Result<()> {
    println!("[u8; 1] size: {}", std::mem::size_of::<[u8; 1]>());
    let src = include_str!("shader/collatz.cl");
    let pro_que: ProQue = ProQue::builder()
        .src(src)
        .dims(3)
        .build()?;
    let buffer = pro_que.create_buffer::<u32>()?;
    println!("size: {}", std::mem::size_of::<TypeAlias>());
    println!("ge_storage size: {}", std::mem::size_of::<context::secp256k1_ge_storage>());
    println!("ECMULT_TABLE_CHUNK_LEN: {}", context::ECMULT_TABLE_CHUNK_LEN);
    let ctx_buffer = pro_que.create_buffer::<TypeAlias>()?;
    let ctx_buffer = pro_que.buffer_builder::<TypeAlias>()
        .flags(MemFlags::READ_ONLY)
        .build()?;
    println!("RIP");
    let kernel = pro_que.kernel_builder("entry_point")
        .arg(&buffer)
        .arg(10)
        .build()?;

    let data = [0, 1, 2];

    buffer.write(&data[..]).enq()?;

    unsafe { kernel.enq()?; }

    let mut vec = vec![0; buffer.len()];

    buffer.read(&mut vec).enq()?;
    println!("{:?}", vec);

    Ok(())
}
