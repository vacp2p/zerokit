#[test]
fn test_rln_has_a_public_custom_backend_construction_path() {
    let source = include_str!("../src/public.rs");
    let type_definition = source
        .split_once("pub struct RLN<State, ZkProof> {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;

    let fields_are_public = type_definition
        .lines()
        .filter(|line| line.trim_start().starts_with("pub "))
        .count()
        == 2;
    let generic_constructor = source.split("impl<State, ZkProof>").skip(1).any(|item| {
        let section = item.split("\nimpl").next().unwrap();
        section.split("pub fn ").skip(1).any(|method| {
            let signature = method.split('{').next().unwrap();
            signature.contains("-> Self") || signature.contains("-> RLN<State, ZkProof>")
        })
    });
    let generic_builder = source.contains("impl<ZKP> RLNBuilder<ZKP>");

    assert!(
        fields_are_public || generic_constructor || generic_builder,
        "RLN fields are crate-private and the only public builders fix ArkGroth16Backend"
    );
}
