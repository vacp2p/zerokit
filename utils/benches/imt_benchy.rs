use std::{hint::black_box, str::FromStr};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use light_poseidon::{
    Poseidon as LtPoseidon, PoseidonBytesHasher as LtPoseidonBytesHasher, PoseidonHasher as _,
};
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use rln::{
    circuit::Fr,
    hashers::PoseidonHash,
    utils::{bytes_le_to_fr, fr_to_bytes_le},
};
use zerokit_utils::{
    FullMerkleConfig, FullMerkleTree, Hasher as ZKitUtilsHasher, OptimalMerkleConfig,
    OptimalMerkleTree, ZerokitMerkleTree,
};
use zk_kit_lean_imt::{hashed_tree::LeanIMTHasher, lean_imt::LeanIMT};

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

#[derive(Debug)]
/// To benchmark the data structure abscent of the hashing overhead
struct BenchyNoOpHasher;
struct BenchyIFTHasher;
struct BenchyLightPosHasher;

// =====
// Ships to IFT Hasher interface
// IFT poseidon hasher doesn't need
// =====

impl ZKitUtilsHasher for BenchyNoOpHasher {
    type Fr = Fr;

    fn default_leaf() -> Self::Fr {
        Fr::default()
    }

    fn hash(input: &[Self::Fr]) -> Self::Fr {
        *input.first().unwrap_or(&Self::default_leaf())
    }
}

impl ZKitUtilsHasher for BenchyLightPosHasher {
    type Fr = Fr;

    fn default_leaf() -> Self::Fr {
        Self::Fr::default()
    }

    fn hash(input: &[Self::Fr]) -> Self::Fr {
        let mut hasher = LtPoseidon::<Fr>::new_circom(input.len()).unwrap();
        hasher.hash(input).unwrap()
    }
}

// =====
// shims for lean imt interface
// =====

impl<const N: usize> LeanIMTHasher<N> for BenchyNoOpHasher {
    fn hash(input: &[u8]) -> [u8; N] {
        input[0..32].try_into().unwrap()
    }
}
impl LeanIMTHasher<32> for BenchyLightPosHasher {
    fn hash(input: &[u8]) -> [u8; 32] {
        let chunks: Vec<&[u8]> = input.chunks(32).collect();
        let mut hasher = LtPoseidon::<Fr>::new_circom(chunks.len()).unwrap();
        hasher.hash_bytes_le(&chunks).unwrap()
    }
}
impl LeanIMTHasher<32> for BenchyIFTHasher {
    fn hash(input: &[u8]) -> [u8; 32] {
        let chunks: Vec<&[u8]> = input.chunks(32).collect();
        let mut lt_hasher = LtPoseidon::<Fr>::new_circom(chunks.len()).unwrap();
        lt_hasher.hash_bytes_le(&chunks).unwrap()
    }
}

/// We start with the data to be hashed, and make the changes needed for them
/// to be valid Fr bytes, just needing raw reinterpretation.
/// Needed for LeanIMT because it processes  &[u8], not &[Fr]
/// and we want to do away with that mapping as a performance variable
fn lean_data_prep(raw_vec: &[[u8; 32]]) -> Vec<[u8; 32]> {
    raw_vec
        .iter()
        .cloned()
        // take raw bytes and Fr-ize it
        .map(|chunk| bytes_le_to_fr(&chunk).0)
        // turn it back into a byte collection
        .map(|bytes| fr_to_bytes_le(&bytes))
        // coorce it into the [u8; 32]s needed for light-imt hash signature
        .map(|bytes| std::convert::TryInto::<[u8; 32]>::try_into(bytes).unwrap())
        .collect()
}

fn spawn_inputs(size_group: &[u32]) -> (Vec<[u8; 32]>, Vec<Fr>) {
    let max = *size_group.iter().max().unwrap() as usize;
    let data_table: Vec<[u8; 32]> = HashMockStream::seeded_stream(42).take(max).collect();

    let fr_table = HashMockStream::seeded_stream(42)
        .take(max)
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
    (data_table, fr_table)
}

pub fn hashless_setup_iterative(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashless tree iterative setup");
    let size_group = [7u32, 13, 17, 40];
    let (data_table, fr_table) = spawn_inputs(&size_group);

    for size in size_group {
        let data_source = &data_table[0..size as usize];
        let fr_source = &fr_table[0..size as usize];
        group.bench_with_input(
            BenchmarkId::new("Lean IMT iterative", size),
            &size,
            |b, &_size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        LeanIMT::<32>::new(&[], <BenchyNoOpHasher as LeanIMTHasher<32>>::hash)
                            .unwrap()
                    },
                    // Actual benchmark
                    |mut tree| {
                        for d in data_source.iter() {
                            #[allow(clippy::unit_arg)]
                            black_box(tree.insert(d, <BenchyNoOpHasher as LeanIMTHasher<32>>::hash))
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
                        OptimalMerkleTree::<BenchyNoOpHasher>::new(
                            (size.ilog2() + 1) as usize,
                            Fr::default(),
                            OptimalMerkleConfig::default(),
                        )
                        .unwrap()
                    },
                    // Actual benchmark
                    |mut tree| {
                        for (i, d) in fr_source.iter().enumerate() {
                            black_box(tree.set(i, *d)).unwrap();
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
                        FullMerkleTree::<BenchyNoOpHasher>::new(
                            (size.ilog2() + 1) as usize,
                            Fr::default(),
                            FullMerkleConfig::default(),
                        )
                        .unwrap()
                    },
                    // Actual benchmark
                    |mut tree| {
                        for (i, d) in fr_source.iter().enumerate() {
                            black_box(tree.set(i, *d)).unwrap();
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
    let size_group = [7u32, 13, 17, 40];
    let (data_table, fr_table) = spawn_inputs(&size_group);
    for size in size_group {
        let data_source = &data_table[0..size as usize];
        group.bench_with_input(
            BenchmarkId::new("Lean IMT batch", size),
            &size,
            |b, &_size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        LeanIMT::<32>::new(&[], <BenchyNoOpHasher as LeanIMTHasher<32>>::hash)
                            .unwrap()
                    },
                    // Actual benchmark
                    |mut tree| {
                        black_box(tree.insert_many(
                            data_source,
                            <BenchyNoOpHasher as LeanIMTHasher<32>>::hash,
                        ))
                    },
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
                        let tree = OptimalMerkleTree::<BenchyNoOpHasher>::new(
                            (size.ilog2() + 1) as usize,
                            Fr::default(),
                            OptimalMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| black_box(tree.set_range(0, data_source)),
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
                        let tree = FullMerkleTree::<BenchyNoOpHasher>::new(
                            (size.ilog2() + 1) as usize,
                            Fr::default(),
                            FullMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| black_box(tree.set_range(0, data_source)),
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

fn tree_hash_batch_setup_shootout(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash+tree batch shootout");
    let size_group = [7u32, 13, 17, 40];
    let (data_table, fr_table) = spawn_inputs(&size_group);
    for size in size_group {
        let data_source = &data_table[0..size as usize];
        group.bench_with_input(
            BenchmarkId::new("Lean IMT batch poseidon", size),
            &size,
            |b, &_size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let byte_form = lean_data_prep(data_source);
                        let tree =
                            LeanIMT::<32>::new(&[], <BenchyIFTHasher as LeanIMTHasher<32>>::hash)
                                .unwrap();
                        (tree, byte_form)
                    },
                    // Actual benchmark
                    |(mut tree, byte_form)| {
                        black_box(
                            tree.insert_many(
                                &byte_form,
                                <BenchyIFTHasher as LeanIMTHasher<32>>::hash,
                            ),
                        )
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("Lean IMT batch light-poseidon", size),
            &size,
            |b, &_size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let byte_form = lean_data_prep(data_source);
                        let tree = LeanIMT::<32>::new(
                            &[],
                            <BenchyLightPosHasher as LeanIMTHasher<32>>::hash,
                        )
                        .unwrap();
                        (tree, byte_form)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| {
                        black_box(tree.insert_many(
                            &data_source,
                            <BenchyLightPosHasher as LeanIMTHasher<32>>::hash,
                        ))
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
                        let fr_slice = &fr_table[0..size as usize];
                        let fr_iter = fr_slice.iter().copied();
                        let tree = OptimalMerkleTree::<PoseidonHash>::new(
                            (size.ilog2() + 1) as usize,
                            Fr::default(),
                            OptimalMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, fr_iter)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| black_box(tree.set_range(0, data_source)),
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
                        let fr_slice = &fr_table[0..size as usize];
                        let fr_iter = fr_slice.iter().copied();
                        let tree = OptimalMerkleTree::<BenchyLightPosHasher>::new(
                            (size.ilog2() + 1) as usize,
                            Fr::default(),
                            OptimalMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, fr_iter)
                    },
                    // Actual benchmark
                    |(mut tree, fr_iter)| black_box(tree.set_range(0, fr_iter)),
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
                        let fr_slice = &fr_table[0..size as usize];
                        let fr_iter = fr_slice.iter().copied();
                        let tree = FullMerkleTree::<PoseidonHash>::new(
                            (size.ilog2() + 1) as usize,
                            Fr::default(),
                            FullMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, fr_iter)
                    },
                    // Actual benchmark
                    |(mut tree, fr_iter)| black_box(tree.set_range(0, fr_iter)),
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
                        let fr_slice = &fr_table[0..size as usize];
                        let fr_iter = fr_slice.iter().copied();
                        let tree = FullMerkleTree::<BenchyLightPosHasher>::new(
                            (size.ilog2() + 1) as usize,
                            Fr::default(),
                            FullMerkleConfig::default(),
                        )
                        .unwrap();
                        (tree, fr_iter)
                    },
                    // Actual benchmark
                    |(mut tree, fr_iter)| black_box(tree.set_range(0, fr_iter)),
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

pub fn proof_gen_shootout(c: &mut Criterion) {
    let mut group = c.benchmark_group("MTree proof-gen shootout");
    let size_group = [7u32, 13, 17, 40];
    let (data_table, fr_table) = spawn_inputs(&size_group);
    for size in size_group {
        let data_source = &data_table[0..size as usize];
        // let data_stream = HashMockStream::seeded_stream(size as u64);
        // let chunk_vec = data_stream.take(size as usize).collect::<Vec<[u8; 32]>>();
        group.bench_with_input(
            BenchmarkId::new("Lean IMT proof generation", size),
            &size,
            |b, &_size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let frd_byte_chunks = lean_data_prep(data_source);
                        LeanIMT::<32>::new(
                            &frd_byte_chunks,
                            <BenchyIFTHasher as LeanIMTHasher<32>>::hash,
                        )
                        .unwrap()
                    },
                    // Actual benchmark
                    |tree| black_box(tree.generate_proof(0)),
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT full proof generation", size),
            &size,
            |b, &_size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let fr_form: Vec<Fr> = data_source
                            .iter()
                            .cloned()
                            // take raw bytes and Fr-ize it
                            .map(|chunk| bytes_le_to_fr(&chunk).0)
                            .collect();
                        let mut tree = FullMerkleTree::<PoseidonHash>::new(
                            7,
                            Fr::default(),
                            FullMerkleConfig::default(),
                        )
                        .unwrap();
                        tree.set_range(0, fr_form.into_iter()).unwrap();
                        tree
                    },
                    // Actual benchmark
                    |tree| black_box(tree.proof(0)),
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT optimal proof generation", size),
            &size,
            |b, &_size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let fr_slice = &fr_table[0..size as usize];
                        let fr_iter = fr_slice.iter().copied();
                        let mut tree = OptimalMerkleTree::<PoseidonHash>::new(
                            7,
                            Fr::default(),
                            OptimalMerkleConfig::default(),
                        )
                        .unwrap();
                        tree.set_range(0, fr_iter).unwrap();
                        tree
                    },
                    // Actual benchmark
                    |tree| black_box(tree.proof(0)),
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

pub fn verification_shootout(c: &mut Criterion) {
    let mut group = c.benchmark_group("MTree verification shootout");
    let size_group = [7u32, 13, 17, 40];
    for size in size_group {
        let data_stream = HashMockStream::seeded_stream(size as u64);
        let data_source = data_stream.take(size as usize).collect::<Vec<[u8; 32]>>();
        group.bench_with_input(
            BenchmarkId::new("Lean IMT verification", size),
            &size,
            |b, &_size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let frd_bytes = lean_data_prep(&data_source);
                        let tree = LeanIMT::<32>::new(
                            &frd_bytes,
                            <BenchyIFTHasher as LeanIMTHasher<32>>::hash,
                        )
                        .unwrap();
                        let proof = tree.generate_proof(0).unwrap();
                        // assert!(LeanIMT::verify_proof(&proof, <BenchyIFTHasher as LeanIMTHasher<32>>::hash));
                        proof
                    },
                    // Actual benchmark
                    |proof| {
                        black_box(LeanIMT::verify_proof(
                            &proof,
                            <BenchyIFTHasher as LeanIMTHasher<32>>::hash,
                        ))
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT full verification", size),
            &size,
            |b, &_size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let fr_form: Vec<Fr> = data_source
                            .iter()
                            .cloned()
                            // take raw bytes and Fr-ize it
                            .map(|chunk| bytes_le_to_fr(&chunk).0)
                            .collect();
                        let mut tree = FullMerkleTree::<PoseidonHash>::new(
                            7,
                            Fr::default(),
                            FullMerkleConfig::default(),
                        )
                        .unwrap();
                        let first_leaf = *fr_form.first().unwrap();
                        tree.set_range(0, fr_form.into_iter()).unwrap();
                        let proof = tree.proof(0).unwrap();
                        // assert!(tree.verify(&first_leaf, &proof).unwrap());
                        (first_leaf, tree, proof)
                    },
                    // Actual benchmark
                    |(first_leaf, tree, proof)| black_box(tree.verify(&first_leaf, &proof)),
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("IFT optimal verification", size),
            &size,
            |b, &_size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let fr_form: Vec<Fr> = data_source
                            .iter()
                            .cloned()
                            // take raw bytes and Fr-ize it
                            .map(|chunk| bytes_le_to_fr(&chunk).0)
                            .collect();
                        let mut tree = OptimalMerkleTree::<PoseidonHash>::new(
                            7,
                            Fr::default(),
                            OptimalMerkleConfig::default(),
                        )
                        .unwrap();
                        let first_leaf = *fr_form.first().unwrap();
                        tree.set_range(0, fr_form.into_iter()).unwrap();
                        let proof = tree.proof(0).unwrap();
                        // assert!(tree.verify(&first_leaf, &proof).unwrap());
                        (first_leaf, tree, proof)
                    },
                    // Actual benchmark
                    |(first_leaf, tree, proof)| black_box(tree.verify(&first_leaf, &proof)),
                    BatchSize::SmallInput,
                )
            },
        );
    }
}
criterion_main!(tree_benchies);
criterion_group! {
    name = tree_benchies;
    config = Criterion::default()
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(4))
        .sample_size(40);
    targets =
        hashless_setup_batch,
        hashless_setup_iterative,
        tree_hash_batch_setup_shootout,
}
criterion_group! {
    name = tree_zk_benchies;
    config = Criterion::default()
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(4))
        .sample_size(10);
    targets =
        proof_gen_shootout,
        verification_shootout
}
