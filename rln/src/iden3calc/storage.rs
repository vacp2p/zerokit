use crate::iden3calc::{
    graph,
    graph::{Operation, TresOperation, UnoOperation},
    proto, InputSignalsInfo,
};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use prost::Message;
use std::io::{Read, Write};

// format of the wtns.graph file:
// + magic line: wtns.graph.001
// + 4 bytes unsigned LE 32-bit integer: number of nodes
// + series of protobuf serialized nodes. Each node prefixed by varint length
// + protobuf serialized GraphMetadata
// + 8 bytes unsigned LE 64-bit integer: offset of GraphMetadata message

const WITNESSCALC_GRAPH_MAGIC: &[u8] = b"wtns.graph.001";

const MAX_VARINT_LENGTH: usize = 10;

impl From<proto::Node> for graph::Node {
    fn from(value: proto::Node) -> Self {
        match value.node.unwrap() {
            proto::node::Node::Input(input_node) => graph::Node::Input(input_node.idx as usize),
            proto::node::Node::Constant(constant_node) => {
                let i = constant_node.value.unwrap();
                graph::Node::MontConstant(Fr::from_le_bytes_mod_order(i.value_le.as_slice()))
            }
            proto::node::Node::UnoOp(uno_op_node) => {
                let op = proto::UnoOp::try_from(uno_op_node.op).unwrap();
                graph::Node::UnoOp(op.into(), uno_op_node.a_idx as usize)
            }
            proto::node::Node::DuoOp(duo_op_node) => {
                let op = proto::DuoOp::try_from(duo_op_node.op).unwrap();
                graph::Node::Op(
                    op.into(),
                    duo_op_node.a_idx as usize,
                    duo_op_node.b_idx as usize,
                )
            }
            proto::node::Node::TresOp(tres_op_node) => {
                let op = proto::TresOp::try_from(tres_op_node.op).unwrap();
                graph::Node::TresOp(
                    op.into(),
                    tres_op_node.a_idx as usize,
                    tres_op_node.b_idx as usize,
                    tres_op_node.c_idx as usize,
                )
            }
        }
    }
}

impl From<&graph::Node> for proto::node::Node {
    fn from(node: &graph::Node) -> Self {
        match node {
            graph::Node::Input(i) => proto::node::Node::Input(proto::InputNode { idx: *i as u32 }),
            graph::Node::Constant(_) => {
                panic!("We are not supposed to write Constant to the witnesscalc graph. All Constant should be converted to MontConstant.");
            }
            graph::Node::UnoOp(op, a) => {
                let op = proto::UnoOp::from(op);
                proto::node::Node::UnoOp(proto::UnoOpNode {
                    op: op as i32,
                    a_idx: *a as u32,
                })
            }
            graph::Node::Op(op, a, b) => proto::node::Node::DuoOp(proto::DuoOpNode {
                op: proto::DuoOp::from(op) as i32,
                a_idx: *a as u32,
                b_idx: *b as u32,
            }),
            graph::Node::TresOp(op, a, b, c) => proto::node::Node::TresOp(proto::TresOpNode {
                op: proto::TresOp::from(op) as i32,
                a_idx: *a as u32,
                b_idx: *b as u32,
                c_idx: *c as u32,
            }),
            graph::Node::MontConstant(c) => {
                let bi = Into::<num_bigint::BigUint>::into(*c);
                let i = proto::BigUInt {
                    value_le: bi.to_bytes_le(),
                };
                proto::node::Node::Constant(proto::ConstantNode { value: Some(i) })
            }
        }
    }
}

impl From<proto::UnoOp> for UnoOperation {
    fn from(value: proto::UnoOp) -> Self {
        match value {
            proto::UnoOp::Neg => UnoOperation::Neg,
            proto::UnoOp::Id => UnoOperation::Id,
        }
    }
}

impl From<proto::DuoOp> for Operation {
    fn from(value: proto::DuoOp) -> Self {
        match value {
            proto::DuoOp::Mul => Operation::Mul,
            proto::DuoOp::Div => Operation::Div,
            proto::DuoOp::Add => Operation::Add,
            proto::DuoOp::Sub => Operation::Sub,
            proto::DuoOp::Pow => Operation::Pow,
            proto::DuoOp::Idiv => Operation::Idiv,
            proto::DuoOp::Mod => Operation::Mod,
            proto::DuoOp::Eq => Operation::Eq,
            proto::DuoOp::Neq => Operation::Neq,
            proto::DuoOp::Lt => Operation::Lt,
            proto::DuoOp::Gt => Operation::Gt,
            proto::DuoOp::Leq => Operation::Leq,
            proto::DuoOp::Geq => Operation::Geq,
            proto::DuoOp::Land => Operation::Land,
            proto::DuoOp::Lor => Operation::Lor,
            proto::DuoOp::Shl => Operation::Shl,
            proto::DuoOp::Shr => Operation::Shr,
            proto::DuoOp::Bor => Operation::Bor,
            proto::DuoOp::Band => Operation::Band,
            proto::DuoOp::Bxor => Operation::Bxor,
        }
    }
}

impl From<proto::TresOp> for graph::TresOperation {
    fn from(value: proto::TresOp) -> Self {
        match value {
            proto::TresOp::TernCond => TresOperation::TernCond,
        }
    }
}

pub fn serialize_witnesscalc_graph<T: Write>(
    mut w: T,
    nodes: &Vec<graph::Node>,
    witness_signals: &[usize],
    input_signals: &InputSignalsInfo,
) -> std::io::Result<()> {
    let mut ptr = 0usize;
    w.write_all(WITNESSCALC_GRAPH_MAGIC).unwrap();
    ptr += WITNESSCALC_GRAPH_MAGIC.len();

    w.write_u64::<LittleEndian>(nodes.len() as u64)?;
    ptr += 8;

    let metadata = proto::GraphMetadata {
        witness_signals: witness_signals
            .iter()
            .map(|x| *x as u32)
            .collect::<Vec<u32>>(),
        inputs: input_signals
            .iter()
            .map(|(k, v)| {
                let sig = proto::SignalDescription {
                    offset: v.0 as u32,
                    len: v.1 as u32,
                };
                (k.clone(), sig)
            })
            .collect(),
    };

    // capacity of buf should be enough to hold the largest message + 10 bytes
    // of varint length
    let mut buf = Vec::with_capacity(metadata.encoded_len() + MAX_VARINT_LENGTH);

    for node in nodes {
        let node_pb = proto::Node {
            node: Some(proto::node::Node::from(node)),
        };

        assert_eq!(buf.len(), 0);
        node_pb.encode_length_delimited(&mut buf)?;
        ptr += buf.len();

        w.write_all(&buf)?;
        buf.clear();
    }

    metadata.encode_length_delimited(&mut buf)?;
    w.write_all(&buf)?;
    buf.clear();

    w.write_u64::<LittleEndian>(ptr as u64)?;

    Ok(())
}

fn read_message_length<R: Read>(rw: &mut WriteBackReader<R>) -> std::io::Result<usize> {
    let mut buf = [0u8; MAX_VARINT_LENGTH];
    let bytes_read = rw.read(&mut buf)?;
    if bytes_read == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Unexpected EOF",
        ));
    }

    let len_delimiter = prost::decode_length_delimiter(buf.as_ref())?;

    let lnln = prost::length_delimiter_len(len_delimiter);

    if lnln < bytes_read {
        rw.write_all(&buf[lnln..bytes_read])?;
    }

    Ok(len_delimiter)
}

fn read_message<R: Read, M: Message + std::default::Default>(
    rw: &mut WriteBackReader<R>,
) -> std::io::Result<M> {
    let ln = read_message_length(rw)?;
    let mut buf = vec![0u8; ln];
    let bytes_read = rw.read(&mut buf)?;
    if bytes_read != ln {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Unexpected EOF",
        ));
    }

    let msg = prost::Message::decode(&buf[..])?;

    Ok(msg)
}

pub fn deserialize_witnesscalc_graph(
    r: impl Read,
) -> std::io::Result<(Vec<graph::Node>, Vec<usize>, InputSignalsInfo)> {
    let mut br = WriteBackReader::new(r);
    let mut magic = [0u8; WITNESSCALC_GRAPH_MAGIC.len()];

    br.read_exact(&mut magic)?;

    if !magic.eq(WITNESSCALC_GRAPH_MAGIC) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid magic",
        ));
    }

    let mut nodes = Vec::new();
    let nodes_num = br.read_u64::<LittleEndian>()?;
    for _ in 0..nodes_num {
        let n: proto::Node = read_message(&mut br)?;
        let n2: graph::Node = n.into();
        nodes.push(n2);
    }

    let md: proto::GraphMetadata = read_message(&mut br)?;

    let witness_signals = md
        .witness_signals
        .iter()
        .map(|x| *x as usize)
        .collect::<Vec<usize>>();

    let input_signals = md
        .inputs
        .iter()
        .map(|(k, v)| (k.clone(), (v.offset as usize, v.len as usize)))
        .collect::<InputSignalsInfo>();

    Ok((nodes, witness_signals, input_signals))
}

struct WriteBackReader<R: Read> {
    reader: R,
    buffer: Vec<u8>,
}

impl<R: Read> WriteBackReader<R> {
    fn new(reader: R) -> Self {
        WriteBackReader {
            reader,
            buffer: Vec::new(),
        }
    }
}

impl<R: Read> Read for WriteBackReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut n = 0usize;

        if !self.buffer.is_empty() {
            n = std::cmp::min(buf.len(), self.buffer.len());
            self.buffer[self.buffer.len() - n..]
                .iter()
                .rev()
                .enumerate()
                .for_each(|(i, x)| {
                    buf[i] = *x;
                });
            self.buffer.truncate(self.buffer.len() - n);
        }

        while n < buf.len() {
            let m = self.reader.read(&mut buf[n..])?;
            if m == 0 {
                break;
            }
            n += m;
        }

        Ok(n)
    }
}

impl<R: Read> Write for WriteBackReader<R> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.reserve(buf.len());
        self.buffer.extend(buf.iter().rev());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::ByteOrder;
    use core::str::FromStr;
    use graph::{Operation, TresOperation, UnoOperation};
    use std::collections::HashMap;

    #[test]
    fn test_read_message() {
        let mut buf = Vec::new();
        let n1 = proto::Node {
            node: Some(proto::node::Node::Input(proto::InputNode { idx: 1 })),
        };
        n1.encode_length_delimited(&mut buf).unwrap();

        let n2 = proto::Node {
            node: Some(proto::node::Node::Input(proto::InputNode { idx: 2 })),
        };
        n2.encode_length_delimited(&mut buf).unwrap();

        let mut reader = std::io::Cursor::new(&buf);

        let mut rw = WriteBackReader::new(&mut reader);

        let got_n1: proto::Node = read_message(&mut rw).unwrap();
        assert!(n1.eq(&got_n1));

        let got_n2: proto::Node = read_message(&mut rw).unwrap();
        assert!(n2.eq(&got_n2));

        assert_eq!(reader.position(), buf.len() as u64);
    }

    #[test]
    fn test_read_message_variant() {
        let nodes = vec![
            proto::Node {
                node: Some(proto::node::Node::from(&graph::Node::Input(0))),
            },
            proto::Node {
                node: Some(proto::node::Node::from(&graph::Node::MontConstant(
                    Fr::from_str("1").unwrap(),
                ))),
            },
            proto::Node {
                node: Some(proto::node::Node::from(&graph::Node::UnoOp(
                    UnoOperation::Id,
                    4,
                ))),
            },
            proto::Node {
                node: Some(proto::node::Node::from(&graph::Node::Op(
                    Operation::Mul,
                    5,
                    6,
                ))),
            },
            proto::Node {
                node: Some(proto::node::Node::from(&graph::Node::TresOp(
                    TresOperation::TernCond,
                    7,
                    8,
                    9,
                ))),
            },
        ];

        let mut buf = Vec::new();
        for n in &nodes {
            n.encode_length_delimited(&mut buf).unwrap();
        }

        let mut nodes_got: Vec<proto::Node> = Vec::new();
        let mut reader = std::io::Cursor::new(&buf);
        let mut rw = WriteBackReader::new(&mut reader);
        for _ in 0..nodes.len() {
            nodes_got.push(read_message(&mut rw).unwrap());
        }

        assert_eq!(nodes, nodes_got);
    }

    #[test]
    fn test_write_back_reader() {
        let data = [1u8, 2, 3, 4, 5, 6];
        let mut r = WriteBackReader::new(std::io::Cursor::new(&data));

        let buf = &mut [0u8; 5];
        r.read(buf).unwrap();
        assert_eq!(buf, &[1, 2, 3, 4, 5]);

        // return [4, 5] to reader
        r.write(&buf[3..]).unwrap();
        // return [2, 3] to reader
        r.write(&buf[1..3]).unwrap();

        buf.fill(0);

        // read 3 bytes, expect [2, 3, 4] after returns
        let mut n = r.read(&mut buf[..3]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, &[2, 3, 4, 0, 0]);

        buf.fill(0);

        // read everything left in reader
        n = r.read(buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf, &[5, 6, 0, 0, 0]);
    }

    #[test]
    fn test_deserialize_inputs() {
        let nodes = vec![
            graph::Node::Input(0),
            graph::Node::MontConstant(Fr::from_str("1").unwrap()),
            graph::Node::UnoOp(UnoOperation::Id, 4),
            graph::Node::Op(Operation::Mul, 5, 6),
            graph::Node::TresOp(TresOperation::TernCond, 7, 8, 9),
        ];

        let witness_signals = vec![4, 1];

        let mut input_signals: InputSignalsInfo = HashMap::new();
        input_signals.insert("sig1".to_string(), (1, 3));
        input_signals.insert("sig2".to_string(), (5, 1));

        let mut tmp = Vec::new();
        serialize_witnesscalc_graph(&mut tmp, &nodes, &witness_signals, &input_signals).unwrap();

        let mut reader = std::io::Cursor::new(&tmp);

        let (nodes_res, witness_signals_res, input_signals_res) =
            deserialize_witnesscalc_graph(&mut reader).unwrap();

        assert_eq!(nodes, nodes_res);
        assert_eq!(input_signals, input_signals_res);
        assert_eq!(witness_signals, witness_signals_res);

        let metadata_start = LittleEndian::read_u64(&tmp[tmp.len() - 8..]);

        let mt_reader = std::io::Cursor::new(&tmp[metadata_start as usize..]);
        let mut rw = WriteBackReader::new(mt_reader);
        let metadata: proto::GraphMetadata = read_message(&mut rw).unwrap();

        let metadata_want = proto::GraphMetadata {
            witness_signals: vec![4, 1],
            inputs: input_signals
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        proto::SignalDescription {
                            offset: v.0 as u32,
                            len: v.1 as u32,
                        },
                    )
                })
                .collect(),
        };

        assert_eq!(metadata, metadata_want);
    }
}
