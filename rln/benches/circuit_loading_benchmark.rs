use criterion::{criterion_group, criterion_main, Criterion};
use rln::circuit::{zkey_from_raw, ZKEY_BYTES};

// Depending on the key type (enabled by the `--features arkzkey` flag)
// the upload speed from the `rln_final.zkey` or `rln_final.arkzkey` file is calculated
pub fn key_load_benchmark(c: &mut Criterion) {
    let zkey = ZKEY_BYTES.to_vec();

    c.bench_function("zkey::upload_from_folder", |b| {
        b.iter(|| {
            let _ = zkey_from_raw(&zkey);
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().without_plots().measurement_time(std::time::Duration::from_secs(10));
    targets = key_load_benchmark
}
criterion_main!(benches);
