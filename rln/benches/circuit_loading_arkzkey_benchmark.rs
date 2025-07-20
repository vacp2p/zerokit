use criterion::{criterion_group, criterion_main, Criterion};
use rln::circuit::{read_arkzkey_from_bytes_uncompressed, ARKZKEY_BYTES};

pub fn uncompressed_bench(c: &mut Criterion) {
    let zkey = ARKZKEY_BYTES.to_vec();
    let size = zkey.len() as f32;
    println!(
        "Size of uncompressed arkzkey: {:.2?} MB",
        size / 1024.0 / 1024.0
    );

    c.bench_function("arkzkey::arkzkey_from_raw_uncompressed", |b| {
        b.iter(|| {
            let r = read_arkzkey_from_bytes_uncompressed(&zkey);
            assert!(r.is_ok());
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = uncompressed_bench
}
criterion_main!(benches);
