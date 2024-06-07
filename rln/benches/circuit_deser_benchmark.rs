use criterion::{criterion_group, criterion_main, Criterion};
use rln::circuit::{to_verifying_key, RESOURCES_DIR, VK_FILENAME};
use serde_json::Value;
use std::path::Path;

// Here we benchmark how long the deserialization of the
// verifying_key takes, only testing the json => verifying_key conversion,
// and skipping conversion from bytes => string => serde_json::Value
pub fn vk_deserialize_benchmark(c: &mut Criterion) {
    let vk = RESOURCES_DIR.get_file(Path::new(VK_FILENAME)).unwrap();
    let vk = vk.contents_utf8().unwrap();
    let json: Value = serde_json::from_str(vk).unwrap();

    c.bench_function("circuit::to_verifying_key", |b| {
        b.iter(|| {
            let _ = to_verifying_key(&json);
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(std::time::Duration::from_secs(10));
    targets = vk_deserialize_benchmark
}
criterion_main!(benches);
