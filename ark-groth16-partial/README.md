# Groth16 Partial Proof Generator

This crate provides a way to generate partial groth16 proofs. 
The implementation is a modified version of arkworks Groth16 prover [ark-groth16](https://github.com/arkworks-rs/groth16) 
where the proving function is split into two `prove_partial()` and `finish_proof`.

The implementation is based on the [Groth16 prover](https://github.com/logos-storage/nim-groth16) used in [rln-fast POC](https://github.com/logos-storage/rln-fast/tree/main).
