use std::hint::black_box;

use ark_bn254::Fr;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use zerokit_utils::poseidon::{Poseidon, Poseidon2, POSEIDON2_ROUND_PARAMS, POSEIDON_ROUND_PARAMS};

pub fn poseidon_benchmark(c: &mut Criterion) {
    let hasher = Poseidon::from(&POSEIDON_ROUND_PARAMS);
    let mut group = c.benchmark_group("Poseidon::hash");

    for size in [10u32, 100, 1000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
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
    group.bench_function("single", |b| {
        let input = [Fr::from(u64::MAX)];
        b.iter(|| {
            let _ = hasher.hash(black_box(&input[..]));
        })
    });

    group.finish();
}

pub fn poseidon2_benchmark(c: &mut Criterion) {
    let hasher = Poseidon2::from(&POSEIDON2_ROUND_PARAMS);
    let mut group = c.benchmark_group("Poseidon2::hash");

    for size in [10u32, 100, 1000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
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
    group.bench_function("single", |b| {
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
    targets = poseidon_benchmark, poseidon2_benchmark
}
criterion_main!(benches);
