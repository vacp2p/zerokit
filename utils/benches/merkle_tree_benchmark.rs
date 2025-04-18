use criterion::{criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use lazy_static::lazy_static;
use std::{fmt::Display, str::FromStr};
use tiny_keccak::{Hasher as _, Keccak};
use zerokit_utils::{
    FullMerkleConfig, FullMerkleTree, Hasher, OptimalMerkleConfig, OptimalMerkleTree,
    ZerokitMerkleTree,
};

#[derive(Clone, Copy, Eq, PartialEq)]
struct Keccak256;

#[derive(Clone, Copy, Eq, PartialEq, Debug, Default)]
struct TestFr([u8; 32]);

impl Hasher for Keccak256 {
    type Fr = TestFr;

    fn default_leaf() -> Self::Fr {
        TestFr([0; 32])
    }

    fn hash(inputs: &[Self::Fr]) -> Self::Fr {
        let mut output = [0; 32];
        let mut hasher = Keccak::v256();
        for element in inputs {
            hasher.update(element.0.as_slice());
        }
        hasher.finalize(&mut output);
        TestFr(output)
    }
}

impl Display for TestFr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.0.as_slice()))
    }
}

impl FromStr for TestFr {
    type Err = std::string::FromUtf8Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(TestFr(s.as_bytes().try_into().unwrap()))
    }
}

lazy_static! {
    static ref LEAVES: [TestFr; 4] = [
        hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        hex!("0000000000000000000000000000000000000000000000000000000000000004"),
    ]
    .map(TestFr);
}

pub fn optimal_merkle_tree_benchmark(c: &mut Criterion) {
    let mut tree =
        OptimalMerkleTree::<Keccak256>::new(2, TestFr([0; 32]), OptimalMerkleConfig::default())
            .unwrap();

    c.bench_function("OptimalMerkleTree::set", |b| {
        b.iter(|| {
            tree.set(0, LEAVES[0]).unwrap();
        })
    });

    c.bench_function("OptimalMerkleTree::delete", |b| {
        b.iter(|| {
            tree.delete(0).unwrap();
        })
    });

    c.bench_function("OptimalMerkleTree::override_range", |b| {
        b.iter(|| {
            tree.override_range(0, LEAVES.into_iter(), [0, 1, 2, 3].into_iter())
                .unwrap();
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

    // check intermediate node getter which required additional computation of sub root index
    c.bench_function("OptimalMerkleTree::get_subtree_root", |b| {
        b.iter(|| {
            tree.get_subtree_root(1, 0).unwrap();
        })
    });

    c.bench_function("OptimalMerkleTree::get_empty_leaves_indices", |b| {
        b.iter(|| {
            tree.get_empty_leaves_indices();
        })
    });
}

pub fn full_merkle_tree_benchmark(c: &mut Criterion) {
    let mut tree =
        FullMerkleTree::<Keccak256>::new(2, TestFr([0; 32]), FullMerkleConfig::default()).unwrap();

    c.bench_function("FullMerkleTree::set", |b| {
        b.iter(|| {
            tree.set(0, LEAVES[0]).unwrap();
        })
    });

    c.bench_function("FullMerkleTree::delete", |b| {
        b.iter(|| {
            tree.delete(0).unwrap();
        })
    });

    c.bench_function("FullMerkleTree::override_range", |b| {
        b.iter(|| {
            tree.override_range(0, LEAVES.into_iter(), [0, 1, 2, 3].into_iter())
                .unwrap();
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

    // check intermediate node getter which required additional computation of sub root index
    c.bench_function("FullMerkleTree::get_subtree_root", |b| {
        b.iter(|| {
            tree.get_subtree_root(1, 0).unwrap();
        })
    });

    c.bench_function("FullMerkleTree::get_empty_leaves_indices", |b| {
        b.iter(|| {
            tree.get_empty_leaves_indices();
        })
    });
}

criterion_group!(
    benches,
    optimal_merkle_tree_benchmark,
    full_merkle_tree_benchmark
);
criterion_main!(benches);
