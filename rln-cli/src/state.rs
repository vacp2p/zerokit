use rln::public::RLN;

#[derive(Default)]
pub(crate) struct State<'a> {
    pub rln: Option<RLN<'a>>,
}
