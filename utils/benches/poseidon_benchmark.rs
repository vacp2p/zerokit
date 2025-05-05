use ark_bn254::Fr;
use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use light_poseidon::{
    PoseidonHasher as LPoseidonHasher, PoseidonParameters as LPoseidonParameters,
};
use zerokit_utils::{Poseidon, RoundParameters};

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

fn make_values(size: u32) -> Vec<[Fr; 1]> {
    let mut values = Vec::with_capacity(size as usize);
    for i in 0..size {
        values.push([Fr::from(i)]);
    }
    values
}

pub fn poseidon_benchmark(c: &mut Criterion) {
    let hasher = Poseidon::<Fr>::from(&ROUND_PARAMS);
    let mut group = c.benchmark_group("poseidon Fr");

    for size in [10u32, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*size as u64));

        group.bench_with_input(BenchmarkId::new("Array hash", size), size, |b, &size| {
            b.iter_batched(
                // Setup: create values for each benchmark iteration
                || make_values(size),
                // Actual benchmark
                |values| {
                    for v in values.iter() {
                        let _ = hasher.hash(black_box(&v[..]));
                    }
                },
                BatchSize::SmallInput,
            );
            b.iter_batched(
                // Setup: create values for each benchmark iteration
                || {
                    // first, we need to pull out the parameters that the internal hasher is
                    // using...
                    let RoundParameters {
                        t,
                        n_rounds_full,
                        n_rounds_partial,
                        skip_matrices: _,
                        ark_consts,
                        mds,
                    } = hasher.select_params(&[Fr::from(1)]).unwrap();
                    // then we need to translate it to the light-poseidon paramater
                    let l_params = LPoseidonParameters {
                        ark: ark_consts.clone(),
                        mds: mds.clone(),
                        full_rounds: *n_rounds_full,
                        partial_rounds: *n_rounds_partial,
                        width: *t,
                        alpha: 1,
                    };
                    
                    let vals = make_values(size);
                    let light_hasher = light_poseidon::Poseidon::<Fr>::new(l_params);
                    (vals, light_hasher)
                },
                // Actual benchmark
                |(values, mut light_hasher)| {
                    for v in values.iter() {
                        let _ = light_hasher.hash(black_box(&v[..]));
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
