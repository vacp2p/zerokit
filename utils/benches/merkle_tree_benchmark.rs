use criterion::{criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use tiny_keccak::{Hasher as _, Keccak};
use zerokit_utils::{
    FullMerkleConfig, FullMerkleTree, Hasher, OptimalMerkleConfig, OptimalMerkleTree,
    ZerokitMerkleTree,
};

#[derive(Clone, Copy, Eq, PartialEq)]
struct Keccak256;

impl Hasher for Keccak256 {
    type Fr = [u8; 32];

    fn default_leaf() -> Self::Fr {
        [0; 32]
    }

    fn hash(inputs: &[Self::Fr]) -> Self::Fr {
        let mut output = [0; 32];
        let mut hasher = Keccak::v256();
        for element in inputs {
            hasher.update(element);
        }
        hasher.finalize(&mut output);
        output
    }
}

pub fn optimal_merkle_tree_benchmark(c: &mut Criterion) {
    let mut tree =
        OptimalMerkleTree::<Keccak256>::new(2, [0; 32], OptimalMerkleConfig::default()).unwrap();

    let leaves = [
        hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        hex!("0000000000000000000000000000000000000000000000000000000000000004"),
    ];

    c.bench_function("OptimalMerkleTree::set", |b| {
        b.iter(|| {
            tree.set(0, leaves[0]).unwrap();
        })
    });

    c.bench_function("OptimalMerkleTree::delete", |b| {
        b.iter(|| {
            tree.delete(0).unwrap();
        })
    });

    c.bench_function("OptimalMerkleTree::override_range", |b| {
        b.iter(|| {
            tree.override_range(0, leaves, [0, 1, 2, 3]).unwrap();
        })
    });

    c.bench_function("OptimalMerkleTree::compute_root", |b| {
        b.iter(|| {
            tree.compute_root().unwrap();
        })
    });

    c.bench_function("OptimalMerkleTree::get", |b| {
        b.iter(|| {
            tree.get(0).unwrap();
        })
    });
}

pub fn full_merkle_tree_benchmark(c: &mut Criterion) {
    let mut tree =
        FullMerkleTree::<Keccak256>::new(2, [0; 32], FullMerkleConfig::default()).unwrap();

    let leaves = [
        hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        hex!("0000000000000000000000000000000000000000000000000000000000000004"),
    ];

    c.bench_function("FullMerkleTree::set", |b| {
        b.iter(|| {
            tree.set(0, leaves[0]).unwrap();
        })
    });

    c.bench_function("FullMerkleTree::delete", |b| {
        b.iter(|| {
            tree.delete(0).unwrap();
        })
    });

    c.bench_function("FullMerkleTree::override_range", |b| {
        b.iter(|| {
            tree.override_range(0, leaves, [0, 1, 2, 3]).unwrap();
        })
    });

    c.bench_function("FullMerkleTree::compute_root", |b| {
        b.iter(|| {
            tree.compute_root().unwrap();
        })
    });

    c.bench_function("FullMerkleTree::get", |b| {
        b.iter(|| {
            tree.get(0).unwrap();
        })
    });
}

criterion_group!(
    benches,
    optimal_merkle_tree_benchmark,
    full_merkle_tree_benchmark
);
criterion_main!(benches);
