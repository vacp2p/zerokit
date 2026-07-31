use std::{hint::black_box, sync::LazyLock};

use criterion::{criterion_group, criterion_main, Criterion};
use rln::prelude::*;
use zerokit_utils::merkle_tree::{ZerokitMerkleProof, ZerokitMerkleTree};

static LEAVES: LazyLock<Vec<Fr>> = LazyLock::new(|| {
    let mut leaves = Vec::with_capacity(1 << 20);
    for i in 0..(1 << 20) {
        leaves.push(Fr::from(i as u64));
    }
    leaves
});

static INDICES: LazyLock<Vec<usize>> = LazyLock::new(|| (0..(1 << 20)).collect());

const LEAF_COUNT: usize = 8192;

pub fn pm_tree_benchmark(c: &mut Criterion) {
    let mut tree = PmTree::<SledDB, PoseidonHash>::default(20).unwrap();

    for i in 0..LEAF_COUNT {
        tree.set(i, LEAVES[i % LEAVES.len()]).unwrap();
    }

    let mut verify_tree = PmTree::<SledDB, PoseidonHash>::default(20).unwrap();
    for i in 0..LEAF_COUNT {
        verify_tree.set(i, LEAVES[i % LEAVES.len()]).unwrap();
    }

    let cached_leaf_index = 0;
    let cached_leaf = LEAVES[cached_leaf_index];
    let cached_proof = verify_tree.proof(cached_leaf_index).unwrap();

    let mut update_next_tree = PmTree::<SledDB, PoseidonHash>::default(20).unwrap();

    c.bench_function("PmTree::get_subtree_root", |b| {
        let mut level = 1;
        let mut index = 0;
        b.iter(|| {
            tree.get_subtree_root(level % 20, index % (1 << (20 - (level % 20))))
                .unwrap();
            index = (index + 1) % (1 << (20 - (level % 20)));
            level = 1 + (level % 20);
        })
    });

    c.bench_function("PmTree::set", |b| {
        let mut index = LEAF_COUNT;
        b.iter(|| {
            tree.set(index % (1 << 20), LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % (1 << 20);
        })
    });

    c.bench_function("PmTree::set_range", |b| {
        let mut offset = 0;
        b.iter(|| {
            let range = offset..offset + LEAF_COUNT;
            tree.set_range(offset, LEAVES[range].iter().cloned())
                .unwrap();
            offset = (offset + LEAF_COUNT) % (1 << 20);
        })
    });

    c.bench_function("PmTree::get", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.get(index % LEAF_COUNT).unwrap();
            index = (index + 1) % LEAF_COUNT;
        })
    });

    c.bench_function("PmTree::get_empty_leaves_indices", |b| {
        b.iter(|| {
            tree.get_empty_leaves_indices();
        })
    });

    c.bench_function("PmTree::override_range", |b| {
        let mut offset = 0;
        b.iter(|| {
            let range = offset..offset + LEAF_COUNT;
            tree.override_range(
                offset,
                LEAVES[range.clone()].iter().cloned(),
                INDICES[range.clone()].iter().cloned(),
            )
            .unwrap();
            offset = (offset + LEAF_COUNT) % (1 << 20);
        })
    });

    c.bench_function("PmTree::update_next", |b| {
        let mut next_value = 0;
        b.iter(|| {
            if update_next_tree.leaves_set() >= (1 << 20) {
                update_next_tree = PmTree::default(20).unwrap();
            }
            update_next_tree
                .update_next(LEAVES[next_value % LEAVES.len()])
                .unwrap();
            next_value += 1;
        })
    });

    c.bench_function("PmTree::delete", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.delete(index % LEAF_COUNT).unwrap();
            tree.set(index % LEAF_COUNT, LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % LEAF_COUNT;
        })
    });

    c.bench_function("PmTree::proof", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.proof(index % LEAF_COUNT).unwrap();
            index = (index + 1) % LEAF_COUNT;
        })
    });

    c.bench_function("PmTree::verify", |b| {
        b.iter(|| {
            verify_tree.verify(&cached_leaf, &cached_proof).unwrap();
        })
    });

    c.bench_function("PmTreeProof::compute_root_from", |b| {
        b.iter(|| {
            black_box(cached_proof.compute_root_from(&cached_leaf));
        })
    });
}

criterion_group!(benches, pm_tree_benchmark);
criterion_main!(benches);
