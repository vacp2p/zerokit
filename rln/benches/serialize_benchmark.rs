use criterion::{criterion_group, criterion_main, Criterion};
use rln::circuit::TEST_TREE_HEIGHT;
use rln::protocol::*;

pub fn rln_witness_benchmark(c: &mut Criterion) {
    let rln_witness = random_rln_witness(TEST_TREE_HEIGHT);

    c.bench_function("rln_witness::full_cycle", |b| {
        b.iter(|| {
            let ser = serialize_witness(&rln_witness).unwrap();
            let (deser, _) = deserialize_witness(&ser).unwrap();
            let rln_witness_json = rln_witness_to_json(&deser).unwrap();
            let _ = rln_witness_from_json(rln_witness_json).unwrap();
        })
    });

    c.bench_function("rln_witness::serialize_cycle", |b| {
        b.iter(|| {
            let ser = serialize_witness(&rln_witness).unwrap();
            let _ = deserialize_witness(&ser).unwrap();
        })
    });

    c.bench_function("rln_witness::json_cycle", |b| {
        b.iter(|| {
            let rln_witness_json = rln_witness_to_json(&rln_witness).unwrap();
            let _ = rln_witness_from_json(rln_witness_json).unwrap();
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(std::time::Duration::from_secs(10));
    targets = rln_witness_benchmark
}
criterion_main!(benches);
