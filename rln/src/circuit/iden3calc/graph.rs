// This crate is based on the code by iden3. Its preimage can be found here:
// https://github.com/iden3/circom-witnesscalc/blob/5cb365b6e4d9052ecc69d4567fcf5bc061c20e94/src/graph.rs

use std::cmp::Ordering;

use ark_ff::{BigInt, BigInteger, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ruint::{aliases::U256, uint};
use serde::{Deserialize, Serialize};

use super::proto;
use crate::circuit::Fr;

const M: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes);
    a.map_err(serde::de::Error::custom)
}

#[inline(always)]
pub(crate) fn fr_to_u256(x: &Fr) -> U256 {
    U256::from_limbs(x.into_bigint().0)
}

#[inline(always)]
pub(crate) fn u256_to_fr(x: &U256) -> Fr {
    Fr::from_bigint(BigInt::new(x.into_limbs())).expect("U256 to Fr conversion must be valid")
}

#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum Operation {
    Mul,
    Div,
    Add,
    Sub,
    Pow,
    Idiv,
    Mod,
    Eq,
    Neq,
    Lt,
    Gt,
    Leq,
    Geq,
    Land,
    Lor,
    Shl,
    Shr,
    Bor,
    Band,
    Bxor,
}

impl Operation {
    fn eval_fr(&self, a: Fr, b: Fr) -> Fr {
        use Operation::*;
        match self {
            Mul => a * b,
            // We always should return something on the circuit execution.
            // So in case of division by 0 we would return 0. And the proof
            // should be invalid in the end.
            Div => {
                if b.is_zero() {
                    Fr::zero()
                } else {
                    a / b
                }
            }
            Add => a + b,
            Sub => a - b,
            // Modular exponentiation to prevent overflow and keep result in field
            Pow => {
                let a_u256 = fr_to_u256(&a);
                let b_u256 = fr_to_u256(&b);
                let result = a_u256.pow_mod(b_u256, M);
                u256_to_fr(&result)
            }
            // Integer division (not field division)
            Idiv => {
                if b.is_zero() {
                    Fr::zero()
                } else {
                    let a_u256 = fr_to_u256(&a);
                    let b_u256 = fr_to_u256(&b);
                    u256_to_fr(&(a_u256 / b_u256))
                }
            }
            // Integer modulo (not field arithmetic)
            Mod => {
                if b.is_zero() {
                    Fr::zero()
                } else {
                    let a_u256 = fr_to_u256(&a);
                    let b_u256 = fr_to_u256(&b);
                    u256_to_fr(&(a_u256 % b_u256))
                }
            }
            Eq => match a.cmp(&b) {
                Ordering::Equal => Fr::one(),
                _ => Fr::zero(),
            },
            Neq => match a.cmp(&b) {
                Ordering::Equal => Fr::zero(),
                _ => Fr::one(),
            },
            Lt => u256_to_fr(&u_lt(&fr_to_u256(&a), &fr_to_u256(&b))),
            Gt => u256_to_fr(&u_gt(&fr_to_u256(&a), &fr_to_u256(&b))),
            Leq => u256_to_fr(&u_lte(&fr_to_u256(&a), &fr_to_u256(&b))),
            Geq => u256_to_fr(&u_gte(&fr_to_u256(&a), &fr_to_u256(&b))),
            Land => {
                if a.is_zero() || b.is_zero() {
                    Fr::zero()
                } else {
                    Fr::one()
                }
            }
            Lor => {
                if a.is_zero() && b.is_zero() {
                    Fr::zero()
                } else {
                    Fr::one()
                }
            }
            Shl => shl(a, b),
            Shr => shr(a, b),
            Bor => bit_or(a, b),
            Band => bit_and(a, b),
            Bxor => bit_xor(a, b),
        }
    }
}

impl From<&Operation> for proto::DuoOp {
    fn from(v: &Operation) -> Self {
        match v {
            Operation::Mul => proto::DuoOp::Mul,
            Operation::Div => proto::DuoOp::Div,
            Operation::Add => proto::DuoOp::Add,
            Operation::Sub => proto::DuoOp::Sub,
            Operation::Pow => proto::DuoOp::Pow,
            Operation::Idiv => proto::DuoOp::Idiv,
            Operation::Mod => proto::DuoOp::Mod,
            Operation::Eq => proto::DuoOp::Eq,
            Operation::Neq => proto::DuoOp::Neq,
            Operation::Lt => proto::DuoOp::Lt,
            Operation::Gt => proto::DuoOp::Gt,
            Operation::Leq => proto::DuoOp::Leq,
            Operation::Geq => proto::DuoOp::Geq,
            Operation::Land => proto::DuoOp::Land,
            Operation::Lor => proto::DuoOp::Lor,
            Operation::Shl => proto::DuoOp::Shl,
            Operation::Shr => proto::DuoOp::Shr,
            Operation::Bor => proto::DuoOp::Bor,
            Operation::Band => proto::DuoOp::Band,
            Operation::Bxor => proto::DuoOp::Bxor,
        }
    }
}

#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum UnoOperation {
    Neg,
    Id, // identity - just return self
}

impl UnoOperation {
    fn eval_fr(&self, a: Fr) -> Fr {
        match self {
            UnoOperation::Neg => {
                if a.is_zero() {
                    Fr::zero()
                } else {
                    let mut x = Fr::MODULUS;
                    x.sub_with_borrow(&a.into_bigint());
                    Fr::from_bigint(x).expect("Negation result must be valid")
                }
            }
            _ => unimplemented!("uno operator {:?} not implemented for Montgomery", self),
        }
    }
}

impl From<&UnoOperation> for proto::UnoOp {
    fn from(v: &UnoOperation) -> Self {
        match v {
            UnoOperation::Neg => proto::UnoOp::Neg,
            UnoOperation::Id => proto::UnoOp::Id,
        }
    }
}

#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum TresOperation {
    TernCond,
}

impl TresOperation {
    fn eval_fr(&self, a: Fr, b: Fr, c: Fr) -> Fr {
        match self {
            TresOperation::TernCond => {
                if a.is_zero() {
                    c
                } else {
                    b
                }
            }
        }
    }
}

impl From<&TresOperation> for proto::TresOp {
    fn from(v: &TresOperation) -> Self {
        match v {
            TresOperation::TernCond => proto::TresOp::TernCond,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Node {
    Input(usize),
    Constant(U256),
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    MontConstant(Fr),
    UnoOp(UnoOperation, usize),
    Op(Operation, usize, usize),
    TresOp(TresOperation, usize, usize, usize),
}

pub(crate) fn evaluate(nodes: &[Node], inputs: &[U256], outputs: &[usize]) -> Vec<Fr> {
    // Evaluate the graph.
    let mut values = Vec::with_capacity(nodes.len());
    for &node in nodes.iter() {
        let value = match node {
            Node::Constant(c) => u256_to_fr(&c),
            Node::MontConstant(c) => c,
            Node::Input(i) => u256_to_fr(&inputs[i]),
            Node::Op(op, a, b) => op.eval_fr(values[a], values[b]),
            Node::UnoOp(op, a) => op.eval_fr(values[a]),
            Node::TresOp(op, a, b, c) => op.eval_fr(values[a], values[b], values[c]),
        };
        values.push(value);
    }

    // Convert from Montgomery form and return the outputs.
    let mut out = vec![Fr::from(0); outputs.len()];
    for i in 0..outputs.len() {
        out[i] = values[outputs[i]];
    }

    out
}

fn shl(a: Fr, b: Fr) -> Fr {
    if b.is_zero() {
        return a;
    }

    if b.cmp(&Fr::from(Fr::MODULUS_BIT_SIZE)).is_ge() {
        return Fr::zero();
    }

    let n = b.into_bigint().0[0] as u32;
    let a = a.into_bigint();
    Fr::from_bigint(a << n).expect("Left shift result must be valid")
}

fn shr(a: Fr, b: Fr) -> Fr {
    if b.is_zero() {
        return a;
    }

    match b.cmp(&Fr::from(254u64)) {
        Ordering::Equal => return Fr::zero(),
        Ordering::Greater => return Fr::zero(),
        _ => (),
    };

    let mut n = b.into_bigint().to_bytes_le()[0];
    let mut result = a.into_bigint();
    let c = result.as_mut();
    while n >= 64 {
        for i in 0..3 {
            c[i as usize] = c[(i + 1) as usize];
        }
        c[3] = 0;
        n -= 64;
    }

    if n == 0 {
        return Fr::from_bigint(result).expect("Right shift result must be valid");
    }

    let mask: u64 = (1 << n) - 1;
    let mut carrier: u64 = c[3] & mask;
    c[3] >>= n;
    for i in (0..3).rev() {
        let new_carrier = c[i] & mask;
        c[i] = (c[i] >> n) | (carrier << (64 - n));
        carrier = new_carrier;
    }
    Fr::from_bigint(result).expect("Right shift result must be valid")
}

fn bit_and(a: Fr, b: Fr) -> Fr {
    let a = a.into_bigint();
    let b = b.into_bigint();
    let c: [u64; 4] = [
        a.0[0] & b.0[0],
        a.0[1] & b.0[1],
        a.0[2] & b.0[2],
        a.0[3] & b.0[3],
    ];
    let mut d: BigInt<4> = BigInt::new(c);
    if d > Fr::MODULUS {
        d.sub_with_borrow(&Fr::MODULUS);
    }

    Fr::from_bigint(d).expect("Bitwise AND result must be valid")
}

fn bit_or(a: Fr, b: Fr) -> Fr {
    let a = a.into_bigint();
    let b = b.into_bigint();
    let c: [u64; 4] = [
        a.0[0] | b.0[0],
        a.0[1] | b.0[1],
        a.0[2] | b.0[2],
        a.0[3] | b.0[3],
    ];
    let mut d: BigInt<4> = BigInt::new(c);
    if d > Fr::MODULUS {
        d.sub_with_borrow(&Fr::MODULUS);
    }

    Fr::from_bigint(d).expect("Bitwise OR result must be valid")
}

fn bit_xor(a: Fr, b: Fr) -> Fr {
    let a = a.into_bigint();
    let b = b.into_bigint();
    let c: [u64; 4] = [
        a.0[0] ^ b.0[0],
        a.0[1] ^ b.0[1],
        a.0[2] ^ b.0[2],
        a.0[3] ^ b.0[3],
    ];
    let mut d: BigInt<4> = BigInt::new(c);
    if d > Fr::MODULUS {
        d.sub_with_borrow(&Fr::MODULUS);
    }

    Fr::from_bigint(d).expect("Bitwise XOR result must be valid")
}

// M / 2
const HALF_M: U256 =
    uint!(10944121435919637611123202872628637544274182200208017171849102093287904247808_U256);

fn u_gte(a: &U256, b: &U256) -> U256 {
    let a_neg = &HALF_M < a;
    let b_neg = &HALF_M < b;

    match (a_neg, b_neg) {
        (false, false) => U256::from(a >= b),
        (true, false) => uint!(0_U256),
        (false, true) => uint!(1_U256),
        (true, true) => U256::from(a >= b),
    }
}

fn u_lte(a: &U256, b: &U256) -> U256 {
    let a_neg = &HALF_M < a;
    let b_neg = &HALF_M < b;

    match (a_neg, b_neg) {
        (false, false) => U256::from(a <= b),
        (true, false) => uint!(1_U256),
        (false, true) => uint!(0_U256),
        (true, true) => U256::from(a <= b),
    }
}

fn u_gt(a: &U256, b: &U256) -> U256 {
    let a_neg = &HALF_M < a;
    let b_neg = &HALF_M < b;

    match (a_neg, b_neg) {
        (false, false) => U256::from(a > b),
        (true, false) => uint!(0_U256),
        (false, true) => uint!(1_U256),
        (true, true) => U256::from(a > b),
    }
}

fn u_lt(a: &U256, b: &U256) -> U256 {
    let a_neg = &HALF_M < a;
    let b_neg = &HALF_M < b;

    match (a_neg, b_neg) {
        (false, false) => U256::from(a < b),
        (true, false) => uint!(1_U256),
        (false, true) => uint!(0_U256),
        (true, true) => U256::from(a < b),
    }
}

#[cfg(test)]
mod test {
    use std::{ops::Div, str::FromStr};

    use ruint::uint;

    use super::*;

    #[test]
    fn test_ok() {
        let a = Fr::from(4u64);
        let b = Fr::from(2u64);
        let c = shl(a, b);
        assert_eq!(c.cmp(&Fr::from(16u64)), Ordering::Equal)
    }

    #[test]
    fn test_div() {
        assert_eq!(
            Operation::Div.eval_fr(Fr::from(2u64), Fr::from(3u64)),
            Fr::from_str(
                "7296080957279758407415468581752425029516121466805344781232734728858602831873"
            )
            .unwrap()
        );

        assert_eq!(
            Operation::Div.eval_fr(Fr::from(6u64), Fr::from(2u64)),
            Fr::from_str("3").unwrap()
        );

        assert_eq!(
            Operation::Div.eval_fr(Fr::from(7u64), Fr::from(2u64)),
            Fr::from_str(
                "10944121435919637611123202872628637544274182200208017171849102093287904247812"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_idiv() {
        assert_eq!(
            Operation::Idiv.eval_fr(Fr::from(2u64), Fr::from(3u64)),
            Fr::from_str("0").unwrap()
        );

        assert_eq!(
            Operation::Idiv.eval_fr(Fr::from(6u64), Fr::from(2u64)),
            Fr::from_str("3").unwrap()
        );

        assert_eq!(
            Operation::Idiv.eval_fr(Fr::from(7u64), Fr::from(2u64)),
            Fr::from_str("3").unwrap()
        );
    }

    #[test]
    fn test_fr_mod() {
        assert_eq!(
            Operation::Mod.eval_fr(Fr::from(7u64), Fr::from(2u64)),
            Fr::from_str("1").unwrap()
        );

        assert_eq!(
            Operation::Mod.eval_fr(Fr::from(7u64), Fr::from(9u64)),
            Fr::from_str("7").unwrap()
        );
    }

    #[test]
    fn test_u_gte() {
        let result = u_gte(&uint!(10_U256), &uint!(3_U256));
        assert_eq!(result, uint!(1_U256));

        let result = u_gte(&uint!(3_U256), &uint!(3_U256));
        assert_eq!(result, uint!(1_U256));

        let result = u_gte(&uint!(2_U256), &uint!(3_U256));
        assert_eq!(result, uint!(0_U256));

        // -1 >= 3 => 0
        let result = u_gte(
            &uint!(
                21888242871839275222246405745257275088548364400416034343698204186575808495616_U256
            ),
            &uint!(3_U256),
        );
        assert_eq!(result, uint!(0_U256));

        // -1 >= -2 => 1
        let result = u_gte(
            &uint!(
                21888242871839275222246405745257275088548364400416034343698204186575808495616_U256
            ),
            &uint!(
                21888242871839275222246405745257275088548364400416034343698204186575808495615_U256
            ),
        );
        assert_eq!(result, uint!(1_U256));

        // -2 >= -1 => 0
        let result = u_gte(
            &uint!(
                21888242871839275222246405745257275088548364400416034343698204186575808495615_U256
            ),
            &uint!(
                21888242871839275222246405745257275088548364400416034343698204186575808495616_U256
            ),
        );
        assert_eq!(result, uint!(0_U256));

        // -2 == -2 => 1
        let result = u_gte(
            &uint!(
                21888242871839275222246405745257275088548364400416034343698204186575808495615_U256
            ),
            &uint!(
                21888242871839275222246405745257275088548364400416034343698204186575808495615_U256
            ),
        );
        assert_eq!(result, uint!(1_U256));
    }

    #[test]
    fn test_x() {
        let x = M.div(uint!(2_U256));

        println!("x: {:?}", x.as_limbs());
        println!("x: {M}");
    }

    #[test]
    fn test_2() {
        let nodes: Vec<Node> = vec![];
        // let node = nodes[0];
        let node = nodes.first();
        println!("{node:?}");
    }
}
