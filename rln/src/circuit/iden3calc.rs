// This file is based on the code by iden3. Its preimage can be found here:
// https://github.com/iden3/circom-witnesscalc/blob/5cb365b6e4d9052ecc69d4567fcf5bc061c20e94/src/lib.rs

pub mod graph;
pub mod proto;
pub mod storage;

use ruint::aliases::U256;
use std::collections::HashMap;
use storage::deserialize_witnesscalc_graph;
use zeroize::zeroize_flat_type;

use crate::circuit::iden3calc::graph::fr_to_u256;
use crate::circuit::Fr;
use crate::utils::FrOrSecret;
use graph::Node;

pub type InputSignalsInfo = HashMap<String, (usize, usize)>;

pub fn calc_witness<I: IntoIterator<Item = (String, Vec<FrOrSecret>)>>(
    inputs: I,
    graph_data: &[u8],
) -> Vec<Fr> {
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

    let (nodes, signals, input_mapping): (Vec<Node>, Vec<usize>, InputSignalsInfo) =
        deserialize_witnesscalc_graph(std::io::Cursor::new(graph_data)).unwrap();

    let mut inputs_buffer = get_inputs_buffer(get_inputs_size(&nodes));
    populate_inputs(&inputs, &input_mapping, &mut inputs_buffer);
    if let Some(v) = inputs.get_mut("identitySecret") {
        // ~== v[0] = U256::ZERO;
        unsafe { zeroize_flat_type(v) };
    }
    let res = graph::evaluate(&nodes, inputs_buffer.as_slice(), &signals);
    inputs_buffer.iter_mut().for_each(|i| {
        unsafe { zeroize_flat_type(i) };
    });
    res
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
) {
    for (key, value) in input_list {
        let (offset, len) = inputs_info[key];
        if len != value.len() {
            panic!("Invalid input length for {}", key);
        }

        for (i, v) in value.iter().enumerate() {
            input_buffer[offset + i] = *v;
        }
    }
}

/// Allocates inputs vec with position 0 set to 1
fn get_inputs_buffer(size: usize) -> Vec<U256> {
    let mut inputs = vec![U256::ZERO; size];
    inputs[0] = U256::from(1);
    inputs
}
