use criterion::{criterion_group, criterion_main, Criterion};
use rln::circuit::{arkzkey_from_raw_compressed, arkzkey_from_raw_uncompressed, ARKZKEY_BYTES, ARKZKEY_BYTES_UNCOMPR};

pub fn uncompressed_bench(c: &mut Criterion) {
    let arkzkey = ARKZKEY_BYTES_UNCOMPR.to_vec();
    let size = arkzkey.len() as f32;
    println!("Size of uncompressed arkzkey: {:.2?} MB", size / 1024.0 / 1024.0);

    c.bench_function("arkzkey::arkzkey_from_raw_uncompressed", |b| {
        b.iter(|| {
            let r = arkzkey_from_raw_uncompressed(&arkzkey);
            assert_eq!(r.is_ok(), true);
        })
    });
}
pub fn compressed_bench(c: &mut Criterion) {
    let arkzkey = ARKZKEY_BYTES.to_vec();
    let size = arkzkey.len() as f32;
    println!("Size of compressed arkzkey: {:.2?} MB", size / 1024.0 / 1024.0);

    c.bench_function("arkzkey::arkzkey_from_raw_compressed", |b| {
        b.iter(|| {
            let r = arkzkey_from_raw_compressed(&arkzkey);
            assert_eq!(r.is_ok(), true);
        })
    });
}


criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(std::time::Duration::from_secs(250));
    targets = uncompressed_bench, compressed_bench
}
criterion_main!(benches);

