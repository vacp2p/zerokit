#[cfg(test)]
mod test {
    use std::io::Cursor;
    use std::str::FromStr;
    use ark_bn254::Fr;
    use claims::assert_lt;
    use rln::public::RLN;
    use rln::utils::{bytes_be_to_fr, bytes_le_to_fr};

    #[test]
    fn test_keygen_be() {

        // let q = Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495617").unwrap();
        let q = Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495616").unwrap();

        // println!("q: {}", q);

        let mut c = 0;
        loop {
            let rln = RLN::default();
            let mut output_buffer = Cursor::new(Vec::<u8>::new());
            let (secret, id_co) = rln.key_gen_be_2(&mut output_buffer).expect("TODO: panic message");
            let serialized_output = output_buffer.into_inner();
            let (secret_de, read) = bytes_be_to_fr(&serialized_output);
            let (id_commitment, _) = bytes_be_to_fr(&serialized_output[read..].to_vec());

            assert_eq!(secret, secret_de);
            assert_lt!(secret, q);

            assert_eq!(id_commitment, id_co);
            assert_lt!(id_commitment, q);

            c+=1;
            if c > 10_000 {
                break;
            }
        }

        println!("c: {}", c);
    }

    #[test]
    fn test_extended_keygen_be() {

        // let q = Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495617").unwrap();
        let q = Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495616").unwrap();

        // println!("q: {}", q);

        let mut c = 0;
        loop {
            let rln = RLN::default();
            let mut output_buffer = Cursor::new(Vec::<u8>::new());
            let (trap, nulli, secret, id_co) = rln.extended_key_gen_be_2(&mut output_buffer).expect("TODO: panic message");

            let serialized_output = output_buffer.into_inner();
            let (trap_de, read) = bytes_be_to_fr(&serialized_output);
            let (nulli_de, read) = bytes_be_to_fr(&serialized_output[read..].to_vec());
            let (secret_de, read) = bytes_be_to_fr(&serialized_output[read+read..].to_vec());
            let (id_co_de, _read) = bytes_be_to_fr(&serialized_output[read+read+read..].to_vec());

            assert_eq!(trap, trap_de);
            assert_eq!(nulli, nulli_de);

            assert_eq!(secret, secret_de);
            assert_lt!(secret, q);
            assert_eq!(id_co, id_co_de);
            assert_lt!(id_co, q);

            c+=1;
            if c > 5_000 {
                break;
            }
        }

        println!("c: {}", c);
    }
}