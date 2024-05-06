use criterion::{criterion_group, criterion_main, Criterion};
use rln::{circuit::Fr, pm_tree_adapter::PmTree};
use utils::ZerokitMerkleTree;

pub fn pmtree_benchmark(c: &mut Criterion) {
    let mut tree = PmTree::default(2).unwrap();

    let leaves: Vec<Fr> = (0..4).map(|s| Fr::from(s)).collect();

    c.bench_function("Pmtree::set", |b| {
        b.iter(|| {
            tree.set(0, leaves[0]).unwrap();
        })
    });

    c.bench_function("Pmtree:delete", |b| {
        b.iter(|| {
            tree.delete(0).unwrap();
        })
    });

    c.bench_function("Pmtree::override_range", |b| {
        b.iter(|| {
            tree.override_range(0, leaves.clone(), [0, 1, 2, 3])
                .unwrap();
        })
    });

    c.bench_function("Pmtree::compute_root", |b| {
        b.iter(|| {
            tree.compute_root().unwrap();
        })
    });

    c.bench_function("Pmtree::get", |b| {
        b.iter(|| {
            tree.get(0).unwrap();
        })
    });
}

criterion_group!(benches, pmtree_benchmark);
criterion_main!(benches);
