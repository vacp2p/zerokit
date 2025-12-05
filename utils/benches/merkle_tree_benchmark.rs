use std::{fmt::Display, str::FromStr, sync::LazyLock};

use criterion::{criterion_group, criterion_main, Criterion};
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

static LEAVES: LazyLock<Vec<TestFr>> = LazyLock::new(|| {
    let mut leaves = Vec::with_capacity(1 << 20);
    for i in 0..(1 << 20) {
        let mut bytes = [0u8; 32];
        bytes[28..].copy_from_slice(&(i as u32).to_be_bytes());
        leaves.push(TestFr(bytes));
    }
    leaves
});

static INDICES: LazyLock<Vec<usize>> = LazyLock::new(|| (0..(1 << 20)).collect());

const NOF_LEAVES: usize = 8192;

pub fn optimal_merkle_tree_benchmark(c: &mut Criterion) {
    let mut tree =
        OptimalMerkleTree::<Keccak256>::new(20, TestFr([0; 32]), OptimalMerkleConfig::default())
            .unwrap();

    for i in 0..NOF_LEAVES {
        tree.set(i, LEAVES[i % LEAVES.len()]).unwrap();
    }

    c.bench_function("OptimalMerkleTree::set", |b| {
        let mut index = NOF_LEAVES;
        b.iter(|| {
            tree.set(index % (1 << 20), LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % (1 << 20);
        })
    });

    c.bench_function("OptimalMerkleTree::delete", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.delete(index % NOF_LEAVES).unwrap();
            tree.set(index % NOF_LEAVES, LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % NOF_LEAVES;
        })
    });

    c.bench_function("OptimalMerkleTree::override_range", |b| {
        let mut offset = 0;
        b.iter(|| {
            let range = offset..offset + NOF_LEAVES;
            tree.override_range(
                offset,
                LEAVES[range.clone()].iter().cloned(),
                INDICES[range.clone()].iter().cloned(),
            )
            .unwrap();
            offset = (offset + NOF_LEAVES) % (1 << 20);
        })
    });

    c.bench_function("OptimalMerkleTree::get", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.get(index % NOF_LEAVES).unwrap();
            index = (index + 1) % NOF_LEAVES;
        })
    });

    c.bench_function("OptimalMerkleTree::get_subtree_root", |b| {
        let mut level = 1;
        let mut index = 0;
        b.iter(|| {
            tree.get_subtree_root(level % 20, index % (1 << (20 - (level % 20))))
                .unwrap();
            index = (index + 1) % (1 << (20 - (level % 20)));
            level = 1 + (level % 20);
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
        FullMerkleTree::<Keccak256>::new(20, TestFr([0; 32]), FullMerkleConfig::default()).unwrap();

    for i in 0..NOF_LEAVES {
        tree.set(i, LEAVES[i % LEAVES.len()]).unwrap();
    }

    c.bench_function("FullMerkleTree::set", |b| {
        let mut index = NOF_LEAVES;
        b.iter(|| {
            tree.set(index % (1 << 20), LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % (1 << 20);
        })
    });

    c.bench_function("FullMerkleTree::delete", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.delete(index % NOF_LEAVES).unwrap();
            tree.set(index % NOF_LEAVES, LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % NOF_LEAVES;
        })
    });

    c.bench_function("FullMerkleTree::override_range", |b| {
        let mut offset = 0;
        b.iter(|| {
            let range = offset..offset + NOF_LEAVES;
            tree.override_range(
                offset,
                LEAVES[range.clone()].iter().cloned(),
                INDICES[range.clone()].iter().cloned(),
            )
            .unwrap();
            offset = (offset + NOF_LEAVES) % (1 << 20);
        })
    });

    c.bench_function("FullMerkleTree::get", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.get(index % NOF_LEAVES).unwrap();
            index = (index + 1) % NOF_LEAVES;
        })
    });

    c.bench_function("FullMerkleTree::get_subtree_root", |b| {
        let mut level = 1;
        let mut index = 0;
        b.iter(|| {
            tree.get_subtree_root(level % 20, index % (1 << (20 - (level % 20))))
                .unwrap();
            index = (index + 1) % (1 << (20 - (level % 20)));
            level = 1 + (level % 20);
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
