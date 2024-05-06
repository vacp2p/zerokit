use criterion::{criterion_group, criterion_main, Criterion};
use rln::circuit::TEST_RESOURCES_FOLDER;

// Depending on the key type (enabled by the `--features arkzkey` flag)
// the upload speed from the `rln_final.zkey` or `rln_final.arkzkey` file is calculated
pub fn key_load_benchmark(c: &mut Criterion) {
    c.bench_function("zkey::upload_from_folder", |b| {
        b.iter(|| {
            let _ = rln::circuit::zkey_from_folder(TEST_RESOURCES_FOLDER);
        })
    });
}

criterion_group!(benches, key_load_benchmark);
criterion_main!(benches);
