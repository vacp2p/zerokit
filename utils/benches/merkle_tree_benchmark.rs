use std::{fmt::Display, str::FromStr, sync::LazyLock};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tiny_keccak::{Hasher as _, Keccak};
use zerokit_utils::{
    error::HashError,
    merkle_tree::validate_override_range_inputs,
    merkle_tree::{
        EmptyIndicesPolicy, FullMerkleConfig, FullMerkleTree, Hasher, OptimalMerkleConfig,
        OptimalMerkleTree, ZerokitMerkleTree,
    },
};

#[derive(Clone, Copy, Eq, PartialEq)]
struct Keccak256;

#[derive(Clone, Copy, Eq, PartialEq, Debug, Default)]
struct TestFr([u8; 32]);

impl Hasher for Keccak256 {
    type Fr = TestFr;
    type Error = HashError;

    fn default_leaf() -> Self::Fr {
        TestFr([0; 32])
    }

    fn hash(inputs: &[Self::Fr]) -> Result<Self::Fr, HashError> {
        let mut output = [0; 32];
        let mut hasher = Keccak::v256();
        for element in inputs {
            hasher.update(element.0.as_slice());
        }
        hasher.finalize(&mut output);
        Ok(TestFr(output))
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

/// Benchmarks `validate_override_range_inputs` in isolation against a full
/// `override_range` call at several index-set sizes, to measure what fraction
/// of the total cost is pure validation (sort + dedup + bounds checks).
///
/// The indices are deliberately passed unsorted and interleaved to exercise
/// the worst-case path through the validator. Both tree implementations
/// (OptimalMerkleTree and FullMerkleTree) are measured so the comparison
/// holds across backends.
///
/// Results on Apple M-series (depth-20 tree, 2^20 capacity):
///
/// ```text
/// n indices │ validate only │ Optimal override_range │ Full override_range │ validation share
/// ──────────┼───────────────┼────────────────────────┼─────────────────────┼─────────────────
///        64 │       224 ns  │              149 µs    │           119 µs    │          ~0.2 %
///     1 024 │      4.95 µs  │              534 µs    │           452 µs    │          ~1.0 %
///     8 192 │      50.6 µs  │              4.3 ms    │           3.7 ms    │          ~1.3 %
///    65 536 │       491 µs  │              179 ms    │           171 ms    │          ~0.3 %
/// ```
///
/// Conclusion: validation never exceeds ~1.3 % of the total `override_range`
/// cost. Hash recomputation up the 20-level tree dominates by 2–3 orders of
/// magnitude, making a separate "raw" (skip-validation) API unnecessary.
pub fn validate_override_range_benchmark(c: &mut Criterion) {
    const CAPACITY: usize = 1 << 20;
    // Sizes chosen to span "typical small" through "stress" usage.
    const SIZES: &[usize] = &[64, 1_024, 8_192, 65_536];

    // Pre-built trees reused across iterations so hashing dominates.
    let mut optimal_tree =
        OptimalMerkleTree::<Keccak256>::new(20, TestFr([0; 32]), OptimalMerkleConfig::default())
            .unwrap();
    let mut full_tree =
        FullMerkleTree::<Keccak256>::new(20, TestFr([0; 32]), FullMerkleConfig::default()).unwrap();

    // Seed both trees so `override_range` has real data to read back.
    for i in 0..NOF_LEAVES {
        optimal_tree.set(i, LEAVES[i]).unwrap();
        full_tree.set(i, LEAVES[i]).unwrap();
    }

    let mut group = c.benchmark_group("validate_override_range");

    for &n in SIZES {
        // Deliberately unsorted and with duplicates to exercise the full
        // sort+dedup path, which is the worst case for the validator.
        let unsorted_indices: Vec<usize> = (0..n)
            .map(|i| {
                // interleave forward and backward halves to defeat pre-sortedness
                if i % 2 == 0 {
                    i / 2
                } else {
                    n - 1 - i / 2
                }
            })
            .collect();

        // --- validation only ---
        group.bench_with_input(
            BenchmarkId::new("validate_only", n),
            &unsorted_indices,
            |b, indices| {
                b.iter(|| {
                    validate_override_range_inputs(
                        n, // start placed right after the delete range
                        1, // one leaf to set (minimal leaves work)
                        indices.clone(),
                        CAPACITY,
                        EmptyIndicesPolicy::Allow,
                    )
                    .unwrap()
                })
            },
        );

        // --- full override_range (OptimalMerkleTree) ---
        // start = n so delete indices [0..n) all lie before start, leaves_len = 1.
        let start = n.min(CAPACITY - 1);
        group.bench_with_input(
            BenchmarkId::new("OptimalMerkleTree/override_range", n),
            &unsorted_indices,
            |b, indices| {
                b.iter(|| {
                    optimal_tree
                        .override_range(
                            start,
                            std::iter::once(LEAVES[start]),
                            indices.iter().copied(),
                        )
                        .unwrap()
                })
            },
        );

        // --- full override_range (FullMerkleTree) ---
        group.bench_with_input(
            BenchmarkId::new("FullMerkleTree/override_range", n),
            &unsorted_indices,
            |b, indices| {
                b.iter(|| {
                    full_tree
                        .override_range(
                            start,
                            std::iter::once(LEAVES[start]),
                            indices.iter().copied(),
                        )
                        .unwrap()
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    optimal_merkle_tree_benchmark,
    full_merkle_tree_benchmark,
    validate_override_range_benchmark,
);
criterion_main!(benches);
