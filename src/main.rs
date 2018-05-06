extern crate ocl;

use ocl::ProQue;

fn main() -> ocl::Result<()> {
    let src = include_str!("shader/collatz.cl");
    let pro_que = ProQue::builder()
        .src(src)
        .dims(3)
        .build()?;
    let buffer = pro_que.create_buffer::<u32>()?;
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
