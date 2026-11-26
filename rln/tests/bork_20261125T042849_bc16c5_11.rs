use rln::prelude::{Fr, PoseidonHash, RLNBuilder};
use zerokit_utils::merkle_tree::{FullMerkleTree, ZerokitMerkleTree};

#[test]
fn test_delete_only_atomic_operation_applies_next_index_formula() {
    let tree = FullMerkleTree::<PoseidonHash>::default(3).unwrap();
    let mut rln = RLNBuilder::stateful().tree(tree).build();
    rln.set_leaf(0, Fr::from(7)).unwrap();

    rln.atomic_operation(4, vec![], vec![0]).unwrap();
    assert_eq!(rln.get_leaf(0).unwrap(), Fr::default());

    let appended_leaf = Fr::from(9);
    rln.set_next_leaf(appended_leaf).unwrap();
    assert_eq!(
        rln.get_leaf(4).unwrap(),
        appended_leaf,
        "atomic_operation must update next_index to max(1, 4 + 0)"
    );
}
