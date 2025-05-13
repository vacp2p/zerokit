use std::str::FromStr;

use ark_ff::{BigInteger, Field, PrimeField};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use light_poseidon::PoseidonBytesHasher;
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use rln::{
    circuit::Fr,
    hashers::{PoseidonHash, ROUND_PARAMS},
};
use zerokit_utils::{
    FullMerkleConfig, FullMerkleTree, Hasher, OptimalMerkleConfig, OptimalMerkleTree, Poseidon,
    ZerokitMerkleTree as _,
};
use zk_kit_lean_imt::{hashed_tree::LeanIMTHasher, lean_imt::LeanIMT};

impl zerokit_utils::Hasher for BenchyLightPosHasher {
    type Fr = Fr;

    fn default_leaf() -> Self::Fr {
        Self::Fr::default()
    }

    fn hash(input: &[Self::Fr]) -> Self::Fr {
        let hasher = Poseidon::from(&ROUND_PARAMS);
        hasher.hash(input).unwrap()
    }
}
// ChaCha8Rng is chosen for its portable determinism
struct HashMockStream {
    rng: ChaCha8Rng,
}

impl HashMockStream {
    fn seeded_stream(seed: u64) -> Self {
        let rng = ChaCha8Rng::seed_from_u64(seed);
        Self { rng }
    }
}

impl Iterator for HashMockStream {
    type Item = [u8; 32];

    fn next(&mut self) -> Option<Self::Item> {
        let mut res = [0; 32];
        self.rng.fill_bytes(&mut res);
        Some(res)
    }
}
// impl LeanIMTHasher<32> for HashMockStream {
//     fn hash(input: &[u8]) -> [u8; 32] {
//         input.try_into().unwrap()
//     }
// }
lazy_static::lazy_static! {
    static ref LEAVES: [[u8; 32]; 400] = HashMockStream::seeded_stream(42)
        .take(400)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
}

#[derive(Debug)]
struct BenchyIFTHasher;
struct BenchyLightPosHasher;
impl Hasher for BenchyIFTHasher {
    type Fr = Fr;

    fn default_leaf() -> Self::Fr {
        Fr::default()
    }

    fn hash(input: &[Self::Fr]) -> Self::Fr {
        *input.first().unwrap_or(&Self::default_leaf())
    }
}

impl<const N: usize> LeanIMTHasher<N> for BenchyIFTHasher {
    fn hash(input: &[u8]) -> [u8; N] {
        let hasher = Poseidon::<Fr>::from(&ROUND_PARAMS);

        let frs = input
            .chunks(N)
            .map(|bytes| Fr::from_random_bytes(bytes).unwrap_or(Fr::default()))
            .collect::<Vec<_>>();
        let frs = frs.as_slice();
        let res_fr: Fr = hasher.hash(frs).unwrap();
        let res_bytes: [u8; N] = res_fr.into_bigint().to_bytes_le().try_into().unwrap();
        res_bytes
    }
}
impl LeanIMTHasher<32> for BenchyLightPosHasher {
    fn hash(input: &[u8]) -> [u8; 32] {
        let mut hasher = light_poseidon::Poseidon::<Fr>::new_circom(1).unwrap();
        // TODO: this should be doable without mucking around with heap-memory
        let chunks: Vec<&[u8]> = input.chunks(32).collect();
        hasher.hash_bytes_le(&chunks).unwrap()
    }
}

fn make_data_table() -> (Vec<[u8; 32]>, Vec<Fr>, [u32; 3]) {
    let size_group = [7u32, 13, 17];
    let data_table: Vec<[u8; 32]> = HashMockStream::seeded_stream(42)
        .take(*size_group.iter().max().unwrap() as usize)
        .collect();

    let fr_table = HashMockStream::seeded_stream(42)
        .take(*size_group.iter().max().unwrap() as usize)
        .map(|bytes: [u8; 32]| {
            Fr::from_str(
                bytes
                    .iter()
                    .map(|b| format!("{}", b % 10))
                    .collect::<String>()
                    .as_str(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    (data_table, fr_table, size_group)
}
fn noop_hash(data: &[u8]) -> [u8; 32] {
    data[0..32].try_into().unwrap()
}
pub fn hashless_setup_iterative(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashless tree iterative setup");
    let (data_table, fr_table, size_group) = make_data_table();

    for size in size_group {
        group.bench_with_input(
            BenchmarkId::new("Lean IMT iterative", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &data_table[0..size as usize];
                        let tree = LeanIMT::<32>::new(&[], noop_hash).unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| {
                        for d in data_source.iter() {
                            tree.insert(d, noop_hash);
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT optimal iterative", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &fr_table[0..size as usize];
                        let tree = OptimalMerkleTree::<BenchyIFTHasher>::new(
                            6,
                            Fr::default(),
                            OptimalMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| {
                        for (i, d) in data_source.iter().enumerate() {
                            tree.set(i, *d).unwrap();
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT full iterative", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &fr_table[0..size as usize];
                        let tree = FullMerkleTree::<BenchyIFTHasher>::new(
                            6,
                            Fr::default(),
                            FullMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| {
                        for (i, d) in data_source.iter().enumerate() {
                            tree.set(i, *d).unwrap();
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}
pub fn hashless_setup_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashless tree batch setup");
    let (data_table, fr_table, size_group) = make_data_table();
    for size in size_group {
        group.bench_with_input(
            BenchmarkId::new("Lean IMT batch", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &data_table[0..size as usize];
                        let tree = LeanIMT::<32>::new(&[], noop_hash).unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| tree.insert_many(data_source, noop_hash),
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT optimal batch", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &fr_table[0..size as usize];
                        let data_source = data_source.iter().copied();
                        let tree = OptimalMerkleTree::<BenchyIFTHasher>::new(
                            6,
                            Fr::default(),
                            OptimalMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| tree.set_range(0, data_source),
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT full batch", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &fr_table[0..size as usize];
                        let data_source = data_source.iter().copied();
                        let tree = FullMerkleTree::<BenchyIFTHasher>::new(
                            6,
                            Fr::default(),
                            FullMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| tree.set_range(0, data_source),
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

fn tree_hash_batch_shootout(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash+tree batch shootout");
    let (data_table, fr_table, size_group) = make_data_table();
    for size in size_group {
        group.bench_with_input(
            BenchmarkId::new("Lean IMT batch poseidon", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &data_table[0..size as usize];
                        let tree =
                            LeanIMT::<32>::new(&[], <BenchyIFTHasher as LeanIMTHasher<32>>::hash)
                                .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| {
                        tree.insert_many(data_source, <BenchyIFTHasher as LeanIMTHasher<32>>::hash)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("Lean IMT batch light-poseidon", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &data_table[0..size as usize];
                        let tree = LeanIMT::<32>::new(
                            &[],
                            <BenchyLightPosHasher as LeanIMTHasher<32>>::hash,
                        )
                        .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| {
                        tree.insert_many(data_source, <BenchyIFTHasher as LeanIMTHasher<32>>::hash)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT optimal batch poseidon", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &fr_table[0..size as usize];
                        let data_source = data_source.iter().copied();
                        let tree = OptimalMerkleTree::<PoseidonHash>::new(
                            6,
                            Fr::default(),
                            OptimalMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| tree.set_range(0, data_source),
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT optimal batch light-poseidon", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &fr_table[0..size as usize];
                        let data_source = data_source.iter().copied();
                        let tree = OptimalMerkleTree::<BenchyLightPosHasher>::new(
                            6,
                            Fr::default(),
                            OptimalMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| tree.set_range(0, data_source),
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT full batch poseidon", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &fr_table[0..size as usize];
                        let data_source = data_source.iter().copied();
                        let tree = FullMerkleTree::<PoseidonHash>::new(
                            6,
                            Fr::default(),
                            FullMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| tree.set_range(0, data_source),
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT full batch light-poseidon", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &fr_table[0..size as usize];
                        let data_source = data_source.iter().copied();
                        let tree = FullMerkleTree::<BenchyLightPosHasher>::new(
                            6,
                            Fr::default(),
                            FullMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| tree.set_range(0, data_source),
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

criterion_group! {
    name = benchies;
    config = Criterion::default()
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(4))
        .sample_size(50);
    targets =  /* hashless_setup_batch, hashless_setup_iterative, */ tree_hash_batch_shootout
}
criterion_main!(benchies);
