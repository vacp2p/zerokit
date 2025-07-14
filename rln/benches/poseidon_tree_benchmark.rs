use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rln::{
    circuit::{Fr, TEST_TREE_HEIGHT},
    hashers::PoseidonHash,
};
use utils::{FullMerkleTree, OptimalMerkleTree, ZerokitMerkleTree};

pub fn get_leaves(n: u32) -> Vec<Fr> {
    (0..n).map(Fr::from).collect()
}

pub fn optimal_merkle_tree_poseidon_benchmark(c: &mut Criterion) {
    c.bench_function("OptimalMerkleTree::<Poseidon>::full_height_gen", |b| {
        b.iter(|| {
            OptimalMerkleTree::<PoseidonHash>::default(TEST_TREE_HEIGHT).unwrap();
        })
    });

    let mut group = c.benchmark_group("Set");
    for &n in [1u32, 10, 100].iter() {
        let leaves = get_leaves(n);

        let mut tree = OptimalMerkleTree::<PoseidonHash>::default(TEST_TREE_HEIGHT).unwrap();
        group.bench_function(
            BenchmarkId::new("OptimalMerkleTree::<Poseidon>::set", n),
            |b| {
                b.iter(|| {
                    for (i, l) in leaves.iter().enumerate() {
                        let _ = tree.set(i, *l);
                    }
                })
            },
        );

        group.bench_function(
            BenchmarkId::new("OptimalMerkleTree::<Poseidon>::set_range", n),
            |b| b.iter(|| tree.set_range(0, leaves.iter().cloned())),
        );
    }
    group.finish();
}

pub fn full_merkle_tree_poseidon_benchmark(c: &mut Criterion) {
    c.bench_function("FullMerkleTree::<Poseidon>::full_height_gen", |b| {
        b.iter(|| {
            FullMerkleTree::<PoseidonHash>::default(TEST_TREE_HEIGHT).unwrap();
        })
    });

    let mut group = c.benchmark_group("Set");
    for &n in [1u32, 10, 100].iter() {
        let leaves = get_leaves(n);

        let mut tree = FullMerkleTree::<PoseidonHash>::default(TEST_TREE_HEIGHT).unwrap();
        group.bench_function(
            BenchmarkId::new("FullMerkleTree::<Poseidon>::set", n),
            |b| {
                b.iter(|| {
                    for (i, l) in leaves.iter().enumerate() {
                        let _ = tree.set(i, *l);
                    }
                })
            },
        );

        group.bench_function(
            BenchmarkId::new("FullMerkleTree::<Poseidon>::set_range", n),
            |b| b.iter(|| tree.set_range(0, leaves.iter().cloned())),
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    optimal_merkle_tree_poseidon_benchmark,
    full_merkle_tree_poseidon_benchmark
);
criterion_main!(benches);
