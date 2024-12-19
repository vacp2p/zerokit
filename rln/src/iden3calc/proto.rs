// This file is generated by prost-build and modified manually.
use std::collections::HashMap;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BigUInt {
    #[prost(bytes = "vec", tag = "1")]
    pub value_le: Vec<u8>,
}
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct InputNode {
    #[prost(uint32, tag = "1")]
    pub idx: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConstantNode {
    #[prost(message, optional, tag = "1")]
    pub value: Option<BigUInt>,
}
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct UnoOpNode {
    #[prost(enumeration = "UnoOp", tag = "1")]
    pub op: i32,
    #[prost(uint32, tag = "2")]
    pub a_idx: u32,
}
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct DuoOpNode {
    #[prost(enumeration = "DuoOp", tag = "1")]
    pub op: i32,
    #[prost(uint32, tag = "2")]
    pub a_idx: u32,
    #[prost(uint32, tag = "3")]
    pub b_idx: u32,
}
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct TresOpNode {
    #[prost(enumeration = "TresOp", tag = "1")]
    pub op: i32,
    #[prost(uint32, tag = "2")]
    pub a_idx: u32,
    #[prost(uint32, tag = "3")]
    pub b_idx: u32,
    #[prost(uint32, tag = "4")]
    pub c_idx: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Node {
    #[prost(oneof = "node::Node", tags = "1, 2, 3, 4, 5")]
    pub node: Option<node::Node>,
}
/// Nested message and enum types in `Node`.
pub mod node {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Node {
        #[prost(message, tag = "1")]
        Input(super::InputNode),
        #[prost(message, tag = "2")]
        Constant(super::ConstantNode),
        #[prost(message, tag = "3")]
        UnoOp(super::UnoOpNode),
        #[prost(message, tag = "4")]
        DuoOp(super::DuoOpNode),
        #[prost(message, tag = "5")]
        TresOp(super::TresOpNode),
    }
}
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct SignalDescription {
    #[prost(uint32, tag = "1")]
    pub offset: u32,
    #[prost(uint32, tag = "2")]
    pub len: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GraphMetadata {
    #[prost(uint32, repeated, tag = "1")]
    pub witness_signals: Vec<u32>,
    #[prost(map = "string, message", tag = "2")]
    pub inputs: HashMap<String, SignalDescription>,
}
#[derive(Clone, Copy, Debug, PartialEq, ::prost::Enumeration)]
pub enum DuoOp {
    Mul = 0,
    Div = 1,
    Add = 2,
    Sub = 3,
    Pow = 4,
    Idiv = 5,
    Mod = 6,
    Eq = 7,
    Neq = 8,
    Lt = 9,
    Gt = 10,
    Leq = 11,
    Geq = 12,
    Land = 13,
    Lor = 14,
    Shl = 15,
    Shr = 16,
    Bor = 17,
    Band = 18,
    Bxor = 19,
}

#[derive(Clone, Copy, Debug, PartialEq, ::prost::Enumeration)]
pub enum UnoOp {
    Neg = 0,
    Id = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, ::prost::Enumeration)]
pub enum TresOp {
    TernCond = 0,
}
