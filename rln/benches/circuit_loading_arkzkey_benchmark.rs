use criterion::{criterion_group, criterion_main, Criterion};
use rln::circuit::{read_arkzkey_from_bytes_uncompressed, ARKZKEY_BYTES};

pub fn uncompressed_bench(c: &mut Criterion) {
    let arkzkey = ARKZKEY_BYTES.to_vec();
    let size = arkzkey.len() as f32;
    println!(
        "Size of uncompressed arkzkey: {:.2?} MB",
        size / 1024.0 / 1024.0
    );

    c.bench_function("arkzkey::arkzkey_from_raw_uncompressed", |b| {
        b.iter(|| {
            let r = read_arkzkey_from_bytes_uncompressed(&arkzkey);
            assert_eq!(r.is_ok(), true);
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = uncompressed_bench
}
criterion_main!(benches);
