use ark_bn254::Fr;
use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use light_poseidon::{
    PoseidonHasher as LPoseidonHasher, PoseidonParameters as LPoseidonParameters,
};
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use rln::utils::bytes_le_to_fr;
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

struct U256Stream {
    rng: ChaCha8Rng,
}
impl U256Stream {
    fn seeded_stream(seed: u64) -> Self {
        let rng = ChaCha8Rng::seed_from_u64(seed);
        Self { rng }
    }
}

impl Iterator for U256Stream {
    type Item = [u8; 32];

    fn next(&mut self) -> Option<Self::Item> {
        let mut res = [0; 32];
        self.rng.fill_bytes(&mut res);
        Some(res)
    }
}

pub fn poseidon_benchmark(c: &mut Criterion) {
    let hasher = Poseidon::<Fr>::from(&ROUND_PARAMS);
    let mut group = c.benchmark_group("poseidon Fr");

    // group.measurement_time(std::time::Duration::from_secs(30));
    for size in [1u32, 2].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        let vals = U256Stream::seeded_stream(*size as u64)
            .take(*size as usize)
            .map(|b| bytes_le_to_fr(&b).0)
            .collect::<Vec<_>>();
        let RoundParameters {
            t,
            n_rounds_full,
            n_rounds_partial,
            skip_matrices: _,
            ark_consts,
            mds,
        } = hasher.select_params(&vals).unwrap();

        group.bench_function(BenchmarkId::new("Array hash light", size), |b| {
            b.iter_batched(
                // setup
                || {
                    // this needs to be done here due to move/copy/etc issues.
                    let l_params = LPoseidonParameters {
                        ark: ark_consts.clone(),
                        mds: mds.clone(),
                        full_rounds: *n_rounds_full,
                        partial_rounds: *n_rounds_partial,
                        width: *t,
                        alpha: 5,
                    };

                    light_poseidon::Poseidon::<Fr>::new(l_params)
                },
                // Actual benchmark
                |mut light_hasher| black_box(light_hasher.hash(&vals)),
                BatchSize::SmallInput,
            )
        });
        group.bench_function(BenchmarkId::new("Array hash ift", size), |b| {
            b.iter(|| black_box(hasher.hash(&vals)))
        });
        group.bench_function(BenchmarkId::new("Array hash light_circom", size), |b| {
            b.iter_batched(
                // setup
                || light_poseidon::Poseidon::<Fr>::new_circom(*size as usize).unwrap(),
                // Actual benchmark
                |mut light_hasher_circom| black_box(light_hasher_circom.hash(&vals)),
                BatchSize::SmallInput,
            )
        });
    }

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
