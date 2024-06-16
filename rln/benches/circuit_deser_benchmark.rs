use criterion::{criterion_group, criterion_main, Criterion};
use rln::circuit::{vk_from_ark_serialized, VK_BYTES};

// Here we benchmark how long the deserialization of the
// verifying_key takes, only testing the json => verifying_key conversion,
// and skipping conversion from bytes => string => serde_json::Value
pub fn vk_deserialize_benchmark(c: &mut Criterion) {
    let vk = VK_BYTES;

    c.bench_function("circuit::to_verifying_key", |b| {
        b.iter(|| {
            let _ = vk_from_ark_serialized(vk);
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(std::time::Duration::from_secs(10));
    targets = vk_deserialize_benchmark
}
criterion_main!(benches);
