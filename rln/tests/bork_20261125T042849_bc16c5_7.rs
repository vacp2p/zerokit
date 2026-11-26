// Proof for finding 20261125T042849-bc16c5/7.
//
// Spec (The API / Overview): "Rust consumers SHOULD import from `rln::prelude`, which re-exports
// the full public surface (RLN types, protocol types, hashers, errors, and serialization
// traits)."
// Spec (Initialization): "Builds a stateful RLN instance around a caller-constructed Merkle tree
// (`FullMerkleTree`, `OptimalMerkleTree`, or `PmTree`)."
// Spec (Merkle Tree Backends): "Applications MAY plug in a fully custom tree ... by implementing
// the `ZerokitMerkleTree` trait, or ... by implementing the `pmtree::Database` trait for `D`."
//
// A missing re-export can only be shown at run time by reading the prelude source: a test that
// names the missing item would not compile, and a proof that does not compile is inconclusive.
// The names are matched as whole identifiers against the `pub use` list of rln/src/prelude.rs;
// rln/src/lib.rs has no other re-export of zerokit_utils or pmtree.

const PRELUDE: &str = include_str!("../src/prelude.rs");
const LIB: &str = include_str!("../src/lib.rs");

fn exported(name: &str) -> bool {
    PRELUDE
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|token| token == name)
}

#[test]
fn prelude_reexports_the_full_public_surface() {
    // Control: the matcher sees what the prelude does export.
    for present in ["PmTree", "RLNBuilder", "RLNMerkleProof", "VerifyProofError"] {
        assert!(exported(present), "control: `{present}` should be found");
    }
    assert!(
        !LIB.contains("pub use"),
        "control: rln/src/lib.rs has no crate-level re-exports"
    );

    // Named by the specification as part of the native Rust surface.
    let required = [
        // Tree backends the builder is documented to accept.
        "FullMerkleTree",
        "OptimalMerkleTree",
        // Extension-point traits.
        "ZerokitMerkleTree",
        "ZerokitMerkleProof",
        "ZerokitHasher",
        "Database",
        // Errors returned by prelude items: tree methods of RLN<Stateful<Full|Optimal>>,
        // PmTreeSledConfig::build(), zkey_from_raw(), graph_from_raw().
        "ZerokitMerkleTreeError",
        "FromConfigError",
        "ZKeyReadError",
        "GraphReadError",
    ];
    let missing: Vec<&str> = required.into_iter().filter(|n| !exported(n)).collect();
    assert!(
        missing.is_empty(),
        "rln::prelude does not re-export: {missing:?}"
    );
}
