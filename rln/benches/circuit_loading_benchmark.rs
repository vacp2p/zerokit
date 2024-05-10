use criterion::{criterion_group, criterion_main, Criterion};

// Depending on the key type (enabled by the `--features arkzkey` flag)
// the upload speed from the `rln_final.zkey` or `rln_final.arkzkey` file is calculated
pub fn key_load_benchmark(c: &mut Criterion) {
    c.bench_function("zkey::upload_from_folder", |b| {
        b.iter(|| {
            let _ = rln::circuit::zkey_from_folder();
        })
    });
}

criterion_group!(benches, key_load_benchmark);
criterion_main!(benches);
