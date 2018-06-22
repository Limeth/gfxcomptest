extern crate ocl;
extern crate secp256k1;

#[macro_use]
mod context;

use context::secp256k1_context_struct_arg;
use context::secp256k1_ecmult_context_chunk;
use context::Secp256k1Context;
use context::ECMULT_TABLE_CHUNKS;
use ocl::ProQue;
use ocl::builders::ProgramBuilder;
use ocl::flags::MemFlags;
use ocl::traits::OclPrm;
use secp256k1::ffi::Context;
use std::fmt;

const ADDRESS_LENGTH: usize = 40;
const PATTERN_CHUNK_BYTES: usize = 1000;

#[derive(Clone, Copy)]
struct patterns_alias([u8; PATTERN_CHUNK_BYTES]);

impl_array!(patterns_alias([u8; PATTERN_CHUNK_BYTES]));

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct patterns_chunk {
    pattern_length: u32,
    pattern_count: u32,
    pattern_offset: u32,
    patterns: patterns_alias,
}

unsafe impl OclPrm for patterns_chunk {}

fn main() -> ocl::Result<()> {
    let mut secp256k1 = Secp256k1Context::new();
    let (ctx_arg, chunks) = secp256k1.copied_without_pointers();

    let patterns = vec!["coffee", "cocoa", "abcd", "deadbeef"];
    let mut patterns_by_length: [Vec<String>; ADDRESS_LENGTH] = [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];

    for pattern in patterns {
        if pattern.is_empty() {
            continue;
        }

        patterns_by_length[pattern.len() - 1].push(pattern.to_string());
    }

    for patterns in &mut patterns_by_length[..] {
        patterns.sort();
    }

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

    for (pattern_length, patterns) in (&mut patterns_by_length[..]).into_iter().enumerate().map(|(i, patterns)| (i + 1, patterns)) {
        program_builder.cmplr_def(format!("PATTERNS_OF_LENGTH_{:02}", pattern_length), patterns.len() as i32);
    }

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
    let patterns_buffer = pro_que.buffer_builder::<patterns_chunk>()
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
        .arg(&patterns_buffer)
        .arg(&chunk_buffer)
        .build()?;

    let data = [0, 1, 2];

    buffer.write(&data[..]).enq()?;

    // Loading context
    println!("Transferring the secp256k1 context...");

    let tmp = [ctx_arg];
    ctx_buffer.write(&tmp[..]).enq()?;

    for chunk_index in 0..ECMULT_TABLE_CHUNKS {
        chunk_buffer.write(&chunks[chunk_index..(chunk_index + 1)]).enq()?;
        unsafe { kernel.enq()?; }
    }

    // Loading dictionary
    println!("Transferring the pattern dictionary...");

    let allowed_characters = "0123456789abcdef";
    let patterns = vec!["c0ffee", "c0c0a", "abcd", "deadbeef", "invalid"];
    let mut patterns_by_length: [Vec<String>; ADDRESS_LENGTH] = [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];

    'pattern_loop:
    for pattern in patterns {
        if pattern.is_empty() {
            continue;
        }

        'character_loop:
        for character in pattern.bytes() {
            for allowed_character in allowed_characters.bytes() {
                if character == allowed_character {
                    continue 'character_loop;
                }
            }

            println!("Skipping invalid pattern: {}", pattern);
            continue 'pattern_loop;
        }

        patterns_by_length[pattern.len() - 1].push(pattern.to_string());
    }

    for (pattern_length, patterns) in (&mut patterns_by_length[..]).into_iter().enumerate().map(|(i, patterns)| (i + 1, patterns)) {
        patterns.sort();

        let patterns_per_chunk = PATTERN_CHUNK_BYTES / pattern_length;

        for (chunk, patterns_in_chunk) in patterns.chunks(patterns_per_chunk).enumerate() {
            let mut chunk = [patterns_chunk {
                pattern_length: pattern_length as u32,
                pattern_count: patterns_in_chunk.len() as u32,
                pattern_offset: (chunk * patterns_per_chunk) as u32,
                patterns: patterns_alias::default(),
            }];

            for (i, pattern) in patterns_in_chunk.iter().enumerate() {
                let dest_slice = &mut chunk[0].patterns.0[i * pattern_length..];

                for (byte_index, byte) in pattern.as_bytes().iter().enumerate() {
                    dest_slice[byte_index] = *byte;
                }
            }

            patterns_buffer.write(&chunk[..]).enq()?;
            unsafe { kernel.enq()?; }
        }
    }

    // Signalize state change
    let mut chunk = [patterns_chunk::default()];

    patterns_buffer.write(&chunk[..]).enq()?;
    unsafe { kernel.enq()?; }

    // Running
    println!("Launching computation.");

    let mut vec = vec![0; buffer.len()];

    buffer.read(&mut vec).enq()?;
    println!("{:?}", vec);

    unsafe { kernel.enq()?; }

    buffer.read(&mut vec).enq()?;
    println!("{:?}", vec);

    Ok(())
}
