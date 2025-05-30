use std::hint::black_box;

use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use zerokit_utils::Poseidon;

const ROUND_PARAMS: [(usize, usize, usize, usize); 8] = [
    (2, 8, 56, 0),
    (3, 8, 57, 0),
    (4, 8, 56, 0),
    (5, 8, 60, 0),
    (6, 8, 60, 0),
    (7, 8, 63, 0),
    (8, 8, 64, 0),
    (9, 8, 63, 0),
];

pub fn poseidon_benchmark(c: &mut Criterion) {
    let hasher = Poseidon::<Fr>::from(&ROUND_PARAMS);
    let mut group = c.benchmark_group("poseidon Fr");

    for size in [10u32, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*size as u64));

        group.bench_with_input(BenchmarkId::new("Array hash", size), size, |b, &size| {
            b.iter_batched(
                // Setup: create values for each benchmark iteration
                || {
                    let mut values = Vec::with_capacity(size as usize);
                    for i in 0..size {
                        values.push([Fr::from(i)]);
                    }
                    values
                },
                // Actual benchmark
                |values| {
                    for v in values.iter() {
                        let _ = hasher.hash(black_box(&v[..]));
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }

    // Benchmark single hash operation separately
    group.bench_function("Single hash", |b| {
        let input = [Fr::from(u64::MAX)];
        b.iter(|| {
            let _ = hasher.hash(black_box(&input[..]));
        })
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(4))
        .sample_size(20);
    targets = poseidon_benchmark
}
criterion_main!(benches);
