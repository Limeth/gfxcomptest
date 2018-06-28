extern crate ocl;
extern crate secp256k1;
extern crate rand;

#[macro_use]
mod context;

use context::secp256k1_context_struct_arg;
use context::secp256k1_ecmult_context_chunk;
use context::Secp256k1Context;
use context::ECMULT_TABLE_CHUNKS;
use ocl::SpatialDims;
use ocl::core::types::abs::DeviceId;
use ocl::enums::{ContextInfo, ContextInfoResult, DeviceInfo, DeviceInfoResult};
use ocl::Context;
use ocl::ProQue;
use ocl::builders::ProgramBuilder;
use ocl::flags::MemFlags;
use ocl::traits::OclPrm;
use rand::Rng;
use rand::OsRng;
use std::fmt;
use std::fmt::Write;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const ADDRESS_LENGTH: usize = 40;
const PRIVATE_KEY_LENGTH: usize = 64;
const ADDRESS_BYTES: usize = ADDRESS_LENGTH / 2;
const PATTERN_CHUNK_BYTES: usize = 1000;
const MRG32K3A_SEEDS_LEN: usize = 6;
const SECRET_KEY_BYTES: usize = 32;
const M1: u64 = 4294967087;
const M2: u64 = 4294944443;
const RESULT_QUEUE_CAPACITY: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct secret_key_bytes_array_alias([u8; SECRET_KEY_BYTES]);

impl_array!(secret_key_bytes_array_alias([u8; SECRET_KEY_BYTES]));

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct secret_key_t {
    array: secret_key_bytes_array_alias,
}

unsafe impl OclPrm for secret_key_t {}

impl secret_key_t {
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        secret_key_t {
            array: secret_key_bytes_array_alias(rng.gen())
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct address_bytes_array_alias([u8; ADDRESS_BYTES]);

impl_array!(address_bytes_array_alias([u8; ADDRESS_BYTES]));

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct address_t {
    array: address_bytes_array_alias,
}

unsafe impl OclPrm for address_t {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct result_t {
    seckey: secret_key_t,
    address: address_t,
}

unsafe impl OclPrm for result_t {}

#[repr(C)]
#[derive(Clone, Copy)]
struct s_alias([u64; 3]);

impl_array!(s_alias([u64; 3]));

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct mrg32k3a_context {
    s1: s_alias,
    s2: s_alias,
}

unsafe impl OclPrm for mrg32k3a_context {}

#[repr(C)]
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

impl mrg32k3a_context {
    /*
     * The seeds for s1[0], s1[1], s1[2] must be integers in <0; m1 - 1> and not all 0.
     * The seeds for s2[0], s2[1], s2[2] must be integers in <0; m2 - 1> and not all 0.
     */
    fn from(seeds: &[u64; MRG32K3A_SEEDS_LEN]) -> Result<Self, ()> {
        for i in 0..3 {
            if seeds[i] > M1 - 1 {
                return Err(());
            }
        }

        for i in 3..6 {
            if seeds[i] > M2 - 1 {
                return Err(());
            }
        }

        let mut zero = 0;

        for item in seeds {
            zero |= item;
        }

        if zero == 0 {
            return Err(());
        }

        Ok(mrg32k3a_context {
            s1: s_alias([seeds[0], seeds[1], seeds[2]]),
            s2: s_alias([seeds[3], seeds[4], seeds[5]]),
        })
    }

    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        loop {
            let seeds = rng.gen();
            let result = Self::from(&seeds);

            if let Ok(ctx) = result {
                return ctx;
            }
        }
    }
}

fn main() -> ocl::Result<()> {
    let mut secp256k1 = Secp256k1Context::new();
    let (ctx_arg, chunks) = secp256k1.copied_without_pointers();

    let allowed_characters = "0123456789abcdef";
    let patterns = vec![
        "abcde",
        "000000000",
        "111111111",
        "222222222",
        "333333333",
        "444444444",
        "555555555",
        "666666666",
        "777777777",
        "888888888",
        "999999999",
        "aaaaaaaaa",
        "bbbbbbbbb",
        "ccccccccc",
        "ddddddddd",
        "eeeeeeeee",
        "fffffffff",
        "012345678",
        "123456789",
    ];
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

    for patterns in &mut patterns_by_length[..] {
        patterns.sort();
    }

    // debug!("host", "ctx_arg.ecmult_gen_ctx.blind.d[0]", ctx_arg.ecmult_gen_ctx.blind.d[0]);
    // debug!("host", "ctx_arg.ecmult_gen_ctx.initial.infinity", ctx_arg.ecmult_gen_ctx.initial.infinity);
    // debug!("host", "ctx_arg.ecmult_gen_ctx.initial.x.n[0]", ctx_arg.ecmult_gen_ctx.initial.x.n[0]);

    let context = Context::builder().build().unwrap();

    let devices = match context.info(ContextInfo::Devices).expect("Could not access OpenCL devices.") {
        ContextInfoResult::Devices(devices) => devices,
        _ => panic!("Unexpected OpenCL devices query result."),
    };

    println!("devices: {:?}", devices);

    let chunks = Arc::new(chunks);

    for (device_index, device_id) in devices.iter().enumerate() {
        exec_device(ctx_arg, chunks.clone(), context.clone(), device_index, *device_id, &patterns_by_length);
    }

    Ok(())
}

fn to_hex_string(slice: &[u8], expected_string_size: usize) -> Result<String, fmt::Error> {
    let mut result = String::with_capacity(expected_string_size);

    for &byte in slice {
        write!(&mut result, "{:02x}", byte)?;
    }

    Ok(result)
}

macro_rules! device_info {
    ($context:expr, $device_index:expr, $($device_info:tt)+) => {
        match $context.device_info($device_index, DeviceInfo::$($device_info)+).unwrap() {
            DeviceInfoResult::$($device_info)+(inner) => inner,
            _ => panic!("Invalid device info result while requesting `{}`.", stringify!($($device_info)+)),
        }
    }
}

fn slice_to_spatial_dims(slice: &[usize]) -> SpatialDims {
    match slice.len() {
        1 => SpatialDims::One(slice[0]),
        2 => SpatialDims::Two(slice[0], slice[1]),
        3 => SpatialDims::Three(slice[0], slice[1], slice[2]),
        _ => SpatialDims::Unspecified,
    }
}

fn exec_device(
    ctx_arg: secp256k1_context_struct_arg,
    chunks: Arc<Box<[secp256k1_ecmult_context_chunk; ECMULT_TABLE_CHUNKS]>>,
    context: Context,
    device_index: usize,
    device_id: DeviceId,
    patterns_by_length: &[Vec<String>; ADDRESS_LENGTH],
) -> ocl::Result<()>{
    println!("MaxComputeUnits: {:?}", context.device_info(device_index, DeviceInfo::MaxComputeUnits).unwrap());
    println!("MaxWorkItemDimensions: {:?}", context.device_info(device_index, DeviceInfo::MaxWorkItemDimensions).unwrap());
    println!("MaxWorkGroupSize: {:?}", context.device_info(device_index, DeviceInfo::MaxWorkGroupSize).unwrap());
    println!("MaxWorkItemSizes: {:?}", context.device_info(device_index, DeviceInfo::MaxWorkItemSizes).unwrap());

    let max_compute_units = device_info!(context, device_index, MaxComputeUnits);
    let max_work_item_dimensions = device_info!(context, device_index, MaxWorkItemDimensions);
    let max_work_group_size = device_info!(context, device_index, MaxWorkGroupSize);
    let max_work_item_sizes = device_info!(context, device_index, MaxWorkItemSizes);

    let work_group_size = [max_work_group_size, 1, 1];
    let global_work_size = [max_work_group_size * max_compute_units as usize, 1, 1];
    let global_work_size_linear = (global_work_size[0] * global_work_size[1] * global_work_size[2]);

    let mut program_builder = ProgramBuilder::new();

    // nVidia has source caching, but it isn't reliable when using #include
    // #[cfg(debug_assertions)]
    std::env::set_var("CUDA_CACHE_DISABLE", "1");
    program_builder.cmplr_opt("-cl-std=CL2.0");
    program_builder.cmplr_def("WORK_GROUP_SIZE_X", work_group_size[0] as i32);
    program_builder.cmplr_def("WORK_GROUP_SIZE_Y", work_group_size[1] as i32);
    program_builder.cmplr_def("WORK_GROUP_SIZE_Z", work_group_size[2] as i32);
    program_builder.cmplr_def("GLOBAL_WORK_SIZE", global_work_size_linear as i32);
    program_builder.cmplr_def("RESULT_QUEUE_CAPACITY", RESULT_QUEUE_CAPACITY as i32);
    #[cfg(debug_assertions)]
    program_builder.cmplr_def("DEBUG_ASSERTIONS", 1);

    for (pattern_length, patterns) in (&patterns_by_length[..]).into_iter().enumerate().map(|(i, patterns)| (i + 1, patterns)) {
        program_builder.cmplr_def(format!("PATTERNS_OF_LENGTH_{:02}", pattern_length), patterns.len() as i32);
    }

    program_builder.src(include_str!("shader/kernel.cl"));

    // TODO: Friendlier output
    println!("Compiling shader for device `{:?}`, this may take a while...", device_index);

    let pro_que: ProQue = ProQue::builder()
        .context(context.clone())
        .device(device_id)
        .prog_bldr(program_builder)
        // .dims(max_work_item_dimensions)
        .dims((max_work_group_size * max_compute_units as usize, 1, 1))
        .build()?;
    let secp256k1_buffer = pro_que.buffer_builder::<secp256k1_context_struct_arg>()
        .flags(MemFlags::READ_ONLY)
        .len(1)
        .build()?;
    let patterns_buffer = pro_que.buffer_builder::<patterns_chunk>()
        .flags(MemFlags::READ_ONLY)
        .len(1)
        .build()?;
    let chunk_buffer = pro_que.buffer_builder::<secp256k1_ecmult_context_chunk>()
        .flags(MemFlags::READ_ONLY)
        .len(1)
        .build()?;
    let seckey_buffer = pro_que.buffer_builder::<secret_key_t>()
        .flags(MemFlags::READ_ONLY)
        .len(1)
        .build()?;
    let cycles_buffer = pro_que.buffer_builder::<u32>()
        .flags(MemFlags::READ_WRITE)
        .len(1)
        .build()?;
    let result_queue_length_buffer = pro_que.buffer_builder::<u32>()
        .flags(MemFlags::READ_WRITE)
        .len(1)
        .build()?;
    let result_queue_buffer = pro_que.buffer_builder::<result_t>()
        .flags(MemFlags::READ_WRITE)
        .len(RESULT_QUEUE_CAPACITY)
        .build()?;
    // let mrg32k3a_buffer = pro_que.buffer_builder::<mrg32k3a_context>()
    //     .flags(MemFlags::READ_ONLY)
    //     .len(1)
    //     .build()?;
    let kernel = pro_que.kernel_builder("entry_point")
        // Must be divisible by `local_work_size`:
        .global_work_size(global_work_size)
        // should conform to MaxWorkItemSizes limits
        .local_work_size(work_group_size)
        .arg(&secp256k1_buffer)
        .arg(&patterns_buffer)
        .arg(&chunk_buffer)
        .arg(&seckey_buffer)
        .arg(&cycles_buffer)
        .arg(&result_queue_length_buffer)
        .arg(&result_queue_buffer)
        // .arg(&mrg32k3a_buffer)
        .build()?;

    // {{{ Loading context
    println!("Transferring the secp256k1 context...");

    let tmp = [ctx_arg];
    secp256k1_buffer.write(&tmp[..]).enq()?;

    for chunk_index in 0..ECMULT_TABLE_CHUNKS {
        chunk_buffer.write(&chunks[chunk_index..(chunk_index + 1)]).enq()?;
        unsafe { kernel.enq()?; }
    }
    // }}}

    // {{{ Loading dictionary
    println!("Transferring the pattern dictionary...");

    for (pattern_length, patterns) in (&patterns_by_length[..]).into_iter().enumerate().map(|(i, patterns)| (i + 1, patterns)) {
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
    let chunk = [patterns_chunk::default()];

    patterns_buffer.write(&chunk[..]).enq()?;
    unsafe { kernel.enq()?; }
    // }}}

    // {{{ Loading initial secret keys
    println!("Generating and transferring initial secret keys...");

    let mut rng = OsRng::new().expect("Could not create an OS RNG.");

    for work_item in 0..global_work_size_linear {
        let seckey_array = [secret_key_t::random(&mut rng)];
        seckey_buffer.write(&seckey_array[..]).enq()?;
        unsafe { kernel.enq()?; }
    }
    // }}}

    // {{{ Setting up the device-local pseudo RNG
    // let mut rng = OsRng::new().expect("Could not create an OS RNG.");

    // for work_item in 0..global_work_size_linear {
    //     let mrg32k3a_context_array = [mrg32k3a_context::random(&mut rng)];
    //     mrg32k3a_buffer.write(&mrg32k3a_context_array[..]).enq()?;
    //     unsafe { kernel.enq()?; }
    // }
    // }}}

    // {{{ Running

    println!("Launching computation.");

    loop {
        unsafe { kernel.enq()?; }
        // thread::sleep(Duration::new(0, 1000000));

        let mut cycles_array = [0];
        let mut result_queue_length_array = [0];
        let mut result_queue_array = [result_t::default(); RESULT_QUEUE_CAPACITY];

        cycles_buffer.read(&mut cycles_array[..]).enq()?;
        result_queue_length_buffer.read(&mut result_queue_length_array[..]).enq()?;
        result_queue_buffer.read(&mut result_queue_array[..]).enq()?;

        for result in &result_queue_array[..result_queue_length_array[0] as usize] {
            let seckey_string = to_hex_string(&result.seckey.array.0[..], PRIVATE_KEY_LENGTH)
                .expect("Could not format the secret key.");
            let address_string = to_hex_string(&result.address.array.0[..], ADDRESS_LENGTH)
                .expect("Could not format the address.");

            println!("Found address: 0x{}\tSecret key: 0x{}", address_string, seckey_string);
        }
    }
}
