use ocl::traits::OclPrm;
use secp256k1::ContextFlag;
use secp256k1::ffi;
use secp256k1::ffi::Context;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::convert::From;
use std::default::Default;
use std::fmt;
use std::mem;

macro_rules! debug {
    ($platform:expr, $name:expr, $expr:expr) => {
        println!("[{}]\t{}:\t{:x}\t{}", $platform, $name, $expr, $expr);
    }
}

// rust-secp256k1 compiles secp256k1 with endomorphism
const USE_ENDOMORPHISM: bool = true;
pub const WINDOW_G: usize = 15; // When USE_ENDOMORPHISM is true
// const WINDOW_G: usize = 16; // When USE_ENDOMORPHISM is false
pub const ECMULT_TABLE_SIZE: usize = 1 << (WINDOW_G - 2);

// So that each chunk is 65536 bytes (roughly as large as the rest of the context)
pub const ECMULT_TABLE_CHUNK_LEN: usize = 65536 / mem::size_of::<secp256k1_ge_storage>();
// Integer division with ceiling
pub const ECMULT_TABLE_CHUNKS: usize = (ECMULT_TABLE_SIZE + ECMULT_TABLE_CHUNK_LEN - 1) / ECMULT_TABLE_CHUNK_LEN;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C)]
pub struct secp256k1_scalar {
    pub d: [u32; 8],
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C)]
pub struct secp256k1_fe {
    pub n: [u32; 10],
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C)]
pub struct secp256k1_gej {
    pub x: secp256k1_fe,
    pub y: secp256k1_fe,
    pub z: secp256k1_fe,
    pub infinity: ::std::os::raw::c_int,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C)]
pub struct secp256k1_ge {
    pub x: secp256k1_fe,
    pub y: secp256k1_fe,
    pub infinity: ::std::os::raw::c_int,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C)]
pub struct secp256k1_fe_storage {
    pub n: [u32; 8],
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C)]
pub struct secp256k1_ge_storage {
    pub x: secp256k1_fe_storage,
    pub y: secp256k1_fe_storage,
}

#[repr(C)]
pub struct secp256k1_ecmult_context {
    pub pre_g: *mut [secp256k1_ge_storage; ECMULT_TABLE_SIZE],
}

#[repr(C)]
pub struct secp256k1_ecmult_gen_context {
    pub prec: *mut [[secp256k1_ge_storage; 16]; 64],
    pub blind: secp256k1_scalar,
    pub initial: secp256k1_gej,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct secp256k1_callback {
    pub fn_: ::std::option::Option<
        unsafe extern "C" fn(
            text: *const ::std::os::raw::c_char,
            data: *mut ::std::os::raw::c_void,
        ),
    >,
    pub data: *const ::std::os::raw::c_void,
}

#[repr(C)]
pub struct secp256k1_context_struct {
    pub ecmult_ctx: secp256k1_ecmult_context,
    pub ecmult_gen_ctx: secp256k1_ecmult_gen_context,
    pub illegal_callback: secp256k1_callback,
    pub error_callback: secp256k1_callback,
}

// We need to introduce newtypes for the arrays, because it is not possible to impl traits for
// arrays
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ecmult_table_chunk([secp256k1_ge_storage; ECMULT_TABLE_CHUNK_LEN]);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct prec_alias_inner([secp256k1_ge_storage; 16]);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct prec_alias([prec_alias_inner; 64]);

#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C)]
pub struct secp256k1_ecmult_gen_context_arg {
    pub prec: prec_alias,
    pub blind: secp256k1_scalar,
    pub initial: secp256k1_gej,
}

macro_rules! impl_array {
    ($alias:ident([$T:ty; $len:expr])) => {
        impl PartialEq for $alias {
            fn eq(&self, other: &$alias) -> bool {
                for (a, b) in self.0.iter().zip(other.0.iter()) {
                    if a.ne(b) {
                        return false;
                    }
                }

                true
            }
        }

        impl Default for $alias {
            fn default() -> Self {
                $alias([<$T as Default>::default(); $len])
            }
        }

        impl fmt::Debug for $alias {
            fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
                (&self.0[..]).fmt(f)
            }
        }
    }
}

impl_array!(ecmult_table_chunk([secp256k1_ge_storage; ECMULT_TABLE_CHUNK_LEN]));
impl_array!(prec_alias_inner([secp256k1_ge_storage; 16]));
impl_array!(prec_alias([prec_alias_inner; 64]));

#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C)]
pub struct secp256k1_context_struct_arg {
    /*
     * Sent in chunks (ecmult_table_chunk):
     * pub ecmult_ctx: secp256k1_ecmult_context_arg,
     */
    pub ecmult_gen_ctx: secp256k1_ecmult_gen_context_arg,
}

pub type secp256k1_context = secp256k1_context_struct;

pub struct Secp256k1Context {
    pub ctx: *mut Context,
    pub caps: ContextFlag,
}

impl Secp256k1Context {
    pub fn new() -> Secp256k1Context {
        Secp256k1Context::with_caps(ContextFlag::Full)
    }

    /// Creates a new Secp256k1 context with the specified capabilities
    pub fn with_caps(caps: ContextFlag) -> Secp256k1Context {
        let flag = match caps {
            ContextFlag::None => ffi::SECP256K1_START_NONE,
            ContextFlag::SignOnly => ffi::SECP256K1_START_SIGN,
            ContextFlag::VerifyOnly => ffi::SECP256K1_START_VERIFY,
            ContextFlag::Full => ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY
        };
        Secp256k1Context { ctx: unsafe { ffi::secp256k1_context_create(flag) }, caps: caps }
    }

    unsafe fn transmute_ctx(&self) -> &secp256k1_context {
        return &*(self.ctx as *mut secp256k1_context)
    }

    pub fn copied_without_pointers(&mut self) -> (secp256k1_context_struct_arg, Box<[ecmult_table_chunk; ECMULT_TABLE_CHUNKS]>) {
        let ctx: &mut secp256k1_context_struct = unsafe { mem::transmute(self.ctx) };

        debug!("const", "WINDOW_G", WINDOW_G);
        debug!("const", "ECMULT_TABLE_SIZE", ECMULT_TABLE_SIZE);
        debug!("const", "ECMULT_TABLE_CHUNK_LEN", ECMULT_TABLE_CHUNK_LEN);
        debug!("const", "ECMULT_TABLE_CHUNKS", ECMULT_TABLE_CHUNKS);
        unsafe { debug!("origin", "(&*ctx.ecmult_ctx.pre_g)[0].x.n[0])", (&*ctx.ecmult_ctx.pre_g)[0].x.n[0]); }
        debug!("origin", "ctx_arg.ecmult_gen_ctx.blind.d[0]", ctx.ecmult_gen_ctx.blind.d[0]);
        debug!("origin", "ctx_arg.ecmult_gen_ctx.initial.infinity", ctx.ecmult_gen_ctx.initial.infinity);
        debug!("origin", "ctx_arg.ecmult_gen_ctx.initial.x.n[0]", ctx.ecmult_gen_ctx.initial.x.n[0]);

        let ecmult_gen_ctx = &mut ctx.ecmult_gen_ctx;
        let prec: &mut [[secp256k1_ge_storage; 16]; 64] = unsafe { &mut *ecmult_gen_ctx.prec };
        let prec: &mut prec_alias = unsafe { mem::transmute(prec) };

        let mut ctx_arg = secp256k1_context_struct_arg {
            ecmult_gen_ctx: secp256k1_ecmult_gen_context_arg {
                prec: prec_alias::default(),
                blind: ecmult_gen_ctx.blind,
                initial: ecmult_gen_ctx.initial,
            },
        };

        (&mut ctx_arg.ecmult_gen_ctx.prec.0).clone_from_slice(&prec.0[..]);

        let ecmult_ctx = &mut ctx.ecmult_ctx;
        let pre_g: &mut [secp256k1_ge_storage; ECMULT_TABLE_SIZE] = unsafe { &mut *ecmult_ctx.pre_g };
        let mut chunks = Box::new([ecmult_table_chunk::default(); ECMULT_TABLE_CHUNKS]);

        for chunk_index in 0..ECMULT_TABLE_CHUNKS {
            let lower_bound = chunk_index * ECMULT_TABLE_CHUNK_LEN;
            let upper_bound = Ord::min(lower_bound + ECMULT_TABLE_CHUNK_LEN, ECMULT_TABLE_SIZE);

            (&mut (*chunks)[chunk_index].0).clone_from_slice(&pre_g[lower_bound..upper_bound]);
        }

        (ctx_arg, chunks)
    }
}

impl Drop for Secp256k1Context {
    fn drop(&mut self) {
        unsafe { ffi::secp256k1_context_destroy(self.ctx); }
    }
}

unsafe impl OclPrm for secp256k1_context_struct_arg {}
unsafe impl OclPrm for ecmult_table_chunk {}
