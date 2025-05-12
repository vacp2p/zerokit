use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use light_poseidon::{PoseidonBytesHasher, PoseidonHasher};
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use rln::{circuit::Fr, utils::fr_to_bytes_le};
use zerokit_utils::Poseidon;
use zk_kit_lean_imt::{
    hashed_tree::{HashedLeanIMT, LeanIMTHasher},
    lean_imt::*,
};

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
impl LeanIMTHasher<32> for HashMockStream {
    fn hash(input: &[u8]) -> [u8; 32] {
        input.try_into().unwrap()
    }
}
lazy_static::lazy_static! {
    static ref LEAVES: [[u8; 32]; 40] = HashMockStream::seeded_stream(42)
        .take(40)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
}

struct BenchyIFTHasher;
struct BenchyLightPosHasher;

impl<const N: usize> LeanIMTHasher<N> for BenchyIFTHasher {
    fn hash(input: &[u8]) -> [u8; N] {
        let hasher = Poseidon::<Fr>::from(&ROUND_PARAMS);
        let input_as_frs: Vec<_> = input
            .chunks(N)
            .map(|ch| rln::utils::bytes_le_to_fr(ch).0)
            .collect();
        let res = hasher.hash(&input_as_frs).unwrap();
        let byte_vec: Vec<u8> = fr_to_bytes_le(&res);
        let mut res = [0; N];
        if byte_vec.len() >= N {
            res.copy_from_slice(&byte_vec[..N]);
        } else {
            res.copy_from_slice(&byte_vec);
        };
        res
    }
}
impl LeanIMTHasher<32> for BenchyLightPosHasher {
    fn hash(input: &[u8]) -> [u8; 32] {
        let mut hasher = light_poseidon::Poseidon::<Fr>::new_circom(1).unwrap();
        let chunks: Vec<&[u8]> = input.chunks(32).collect();
        hasher.hash_bytes_le(&chunks).unwrap()
    }
}
fn benchy_prototype_code() {
    let mut tree = HashedLeanIMT::<32, BenchyIFTHasher>::new(&[], BenchyIFTHasher).unwrap();
    let mut genned_hashes = LEAVES.iter();
    tree.insert(genned_hashes.next().unwrap());
    tree.insert(genned_hashes.next().unwrap());
    tree.insert_many(&[
        *genned_hashes.next().unwrap(),
        *genned_hashes.next().unwrap(),
        *genned_hashes.next().unwrap(),
    ])
    .unwrap();

    println!("Tree root: {:?}", tree.root().unwrap());
    println!("Tree depth: {}", tree.depth());

    let proof = tree.generate_proof(3).unwrap();
    assert!(HashedLeanIMT::<32, BenchyIFTHasher>::verify_proof(&proof));
}

pub fn hashless_imt_benchy(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashless merkle tree setup");
    let size_group = [7u32, 13, 17];
    let data_table: Vec<[u8; 32]> = HashMockStream::seeded_stream(42)
        .take(*size_group.iter().max().unwrap() as usize)
        .collect();
    for size in size_group.iter() {
        group.bench_with_input(
            BenchmarkId::new("Lean IMT setup incremental", size),
            size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &data_table[0..size as usize];
                        let tree = HashedLeanIMT::<32, BenchyIFTHasher>::new(&[], BenchyIFTHasher)
                            .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| {
                        for d in data_source.iter() {
                            tree.insert(d);
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("Lean IMT setup batch", size),
            size,
            |b, &size| {
                b.iter_batched(
                    // Setup: create values for each benchmark iteration
                    || {
                        let data_source = &data_table[0..size as usize];
                        let tree = HashedLeanIMT::<32, BenchyIFTHasher>::new(&[], BenchyIFTHasher)
                            .unwrap();
                        (tree, data_source)
                    },
                    // Actual benchmark
                    |(mut tree, data_source)| tree.insert_many(data_source),
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benchies;
    config = Criterion::default()
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(4))
        .sample_size(10);
    targets = hashless_imt_benchy
}
criterion_main!(benchies);
