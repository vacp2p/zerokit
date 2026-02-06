// This crate is based on the code by iden3. Its preimage can be found here:
// https://github.com/iden3/circom-witnesscalc/blob/5cb365b6e4d9052ecc69d4567fcf5bc061c20e94/src/lib.rs

pub(crate) mod graph;
mod proto;
pub(crate) mod storage;

use std::collections::HashMap;

use graph::Node;
use ruint::aliases::U256;
use zeroize::zeroize_flat_type;

use self::graph::fr_to_u256;
use super::{error::WitnessCalcError, Fr};
use crate::utils::FrOrSecret;

pub(crate) type InputSignalsInfo = HashMap<String, (usize, usize)>;

pub(crate) fn calc_witness<I: IntoIterator<Item = (String, Vec<FrOrSecret>)>>(
    inputs: I,
    graph: &super::Graph,
) -> Result<Vec<Fr>, WitnessCalcError> {
    let mut inputs: HashMap<String, Vec<U256>> = inputs
        .into_iter()
        .map(|(key, value)| {
            (
                key,
                value
                    .iter()
                    .map(|f_| match f_ {
                        FrOrSecret::IdSecret(s) => s.to_u256(),
                        FrOrSecret::Fr(f) => fr_to_u256(f),
                    })
                    .collect(),
            )
        })
        .collect();

    let mut inputs_buffer = get_inputs_buffer(get_inputs_size(&graph.nodes));

    populate_inputs(&inputs, &graph.input_mapping, &mut inputs_buffer)?;

    if let Some(v) = inputs.get_mut("identitySecret") {
        // DO NOT USE: unsafe { zeroize_flat_type(v) } only clears the Vec pointer, not the data—can cause memory leaks

        for val in v.iter_mut() {
            unsafe { zeroize_flat_type(val) };
        }
    }

    let res = graph::evaluate(&graph.nodes, inputs_buffer.as_slice(), &graph.signals)
        .map_err(WitnessCalcError::GraphEvaluation)?;

    for val in inputs_buffer.iter_mut() {
        unsafe { zeroize_flat_type(val) };
    }

    Ok(res)
}

pub(crate) fn calc_witness_partial<I: IntoIterator<Item = (String, Vec<Option<FrOrSecret>>)>>(
    inputs: I,
    graph: &super::Graph,
) -> Result<Vec<Option<Fr>>, WitnessCalcError> {
    let mut inputs: HashMap<String, Vec<Option<U256>>> = inputs
        .into_iter()
        .map(|(key, value)| {
            (
                key,
                value
                    .iter()
                    .map(|f_| {
                        f_.as_ref().map(|v| match v {
                            FrOrSecret::IdSecret(s) => s.to_u256(),
                            FrOrSecret::Fr(f) => fr_to_u256(f),
                        })
                    })
                    .collect(),
            )
        })
        .collect();

    let mut inputs_buffer = get_inputs_buffer_partial(get_inputs_size(&graph.nodes));

    populate_inputs_partial(&inputs, &graph.input_mapping, &mut inputs_buffer)?;

    if let Some(v) = inputs.get_mut("identitySecret") {
        // DO NOT USE: unsafe { zeroize_flat_type(v) } only clears the Vec pointer, not the data—can cause memory leaks

        for val in v.iter_mut() {
            if let Some(inner) = val {
                unsafe { zeroize_flat_type(inner) };
            }
        }
    }

    let res = graph::evaluate_partial(&graph.nodes, inputs_buffer.as_slice(), &graph.signals)
        .map_err(WitnessCalcError::GraphEvaluation)?;

    for val in inputs_buffer.iter_mut() {
        unsafe { zeroize_flat_type(val) };
    }

    Ok(res)
}

fn get_inputs_size(nodes: &[Node]) -> usize {
    let mut start = false;
    let mut max_index = 0usize;
    for &node in nodes.iter() {
        if let Node::Input(i) = node {
            if i > max_index {
                max_index = i;
            }
            start = true
        } else if start {
            break;
        }
    }
    max_index + 1
}

fn populate_inputs(
    input_list: &HashMap<String, Vec<U256>>,
    inputs_info: &InputSignalsInfo,
    input_buffer: &mut [U256],
) -> Result<(), WitnessCalcError> {
    for (key, value) in input_list {
        let (offset, len) = inputs_info
            .get(key)
            .ok_or_else(|| WitnessCalcError::MissingInput(key.clone()))?;

        if *len != value.len() {
            return Err(WitnessCalcError::InvalidInputLength {
                name: key.clone(),
                expected: *len,
                actual: value.len(),
            });
        }

        for (i, v) in value.iter().enumerate() {
            input_buffer[offset + i] = *v;
        }
    }

    Ok(())
}

fn populate_inputs_partial(
    input_list: &HashMap<String, Vec<Option<U256>>>,
    inputs_info: &InputSignalsInfo,
    input_buffer: &mut [Option<U256>],
) -> Result<(), WitnessCalcError> {
    for (key, value) in input_list {
        let (offset, len) = inputs_info
            .get(key)
            .ok_or_else(|| WitnessCalcError::MissingInput(key.clone()))?;

        if *len != value.len() {
            return Err(WitnessCalcError::InvalidInputLength {
                name: key.clone(),
                expected: *len,
                actual: value.len(),
            });
        }

        for (i, v) in value.iter().enumerate() {
            if let Some(val) = v {
                input_buffer[offset + i] = Some(*val);
            }
        }
    }

    Ok(())
}

/// Allocates inputs vec with position 0 set to 1
fn get_inputs_buffer(size: usize) -> Vec<U256> {
    let mut inputs = vec![U256::ZERO; size];
    inputs[0] = U256::from(1);
    inputs
}

fn get_inputs_buffer_partial(size: usize) -> Vec<Option<U256>> {
    let mut inputs = vec![None; size];
    inputs[0] = Some(U256::from(1));
    inputs
}
