#[cfg(test)]
mod tests {
    use multiplier::public::Multiplier;

    #[test]
    fn multiplier_proof() {
        let mul = Multiplier::new().unwrap();
        //let inputs = mul.circom.get_public_inputs().unwrap();

        let mut output_data: Vec<u8> = Vec::new();
        let _ = mul.prove(&mut output_data);

        let proof_data = &output_data[..];

        // XXX Pass as arg?
        //let pvk = prepare_verifying_key(&mul.params.vk);

        let verified = mul.verify(proof_data).unwrap();

        assert!(verified);
    }
}
