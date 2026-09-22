// This module implements the Grain LFSR used to derive the Poseidon and Poseidon2 round
// constants. Both hashes seed it identically (the Poseidon2 paper reuses the original
// Poseidon generation); they only differ in how many elements they draw.

// The following implementation was adapted from https://github.com/arkworks-rs/sponge/blob/7d9b3a474c9ddb62890014aeaefcb142ac2b3776/src/poseidon/grain_lfsr.rs

use ark_ff::PrimeField;
use num_bigint::BigUint;

pub(crate) struct PoseidonGrainLFSR {
    pub prime_num_bits: u64,
    pub state: [bool; 80],
    pub head: usize,
}

impl PoseidonGrainLFSR {
    pub(crate) fn new(
        is_field: u64,
        is_sbox_an_inverse: u64,
        prime_num_bits: u64,
        state_len: u64,
        num_full_rounds: u64,
        num_partial_rounds: u64,
    ) -> Self {
        let mut state = [false; 80];

        // Only fields are supported for now
        assert!(is_field == 1);

        // b0, b1 describes the field
        state[1] = is_field == 1;

        assert!(is_sbox_an_inverse == 0 || is_sbox_an_inverse == 1);

        // b2, ..., b5 describes the S-BOX
        state[5] = is_sbox_an_inverse == 1;

        // b6, ..., b17 are the binary representation of n (prime_num_bits)
        {
            let mut cur = prime_num_bits;
            for i in (6..=17).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b18, ..., b29 are the binary representation of t (state_len, rate + capacity)
        {
            let mut cur = state_len;
            for i in (18..=29).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b30, ..., b39 are the binary representation of R_F (the number of full rounds)
        {
            let mut cur = num_full_rounds;
            for i in (30..=39).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b40, ..., b49 are the binary representation of R_P (the number of partial rounds)
        {
            let mut cur = num_partial_rounds;
            for i in (40..=49).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b50, ..., b79 are set to 1
        for item in state.iter_mut().skip(50) {
            *item = true;
        }

        let head = 0;

        let mut res = Self {
            prime_num_bits,
            state,
            head,
        };
        res.init();
        res
    }

    fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let mut res = Vec::new();

        for _ in 0..num_bits {
            // Obtain the first bit
            let mut new_bit = self.update();

            // Loop until the first bit is true
            while !new_bit {
                // Discard the second bit
                let _ = self.update();
                // Obtain another first bit
                new_bit = self.update();
            }

            // Obtain the second bit
            res.push(self.update());
        }

        res
    }

    pub(crate) fn get_field_elements_rejection_sampling<F: PrimeField>(
        &mut self,
        num_elems: usize,
    ) -> Vec<F> {
        assert_eq!(F::MODULUS_BIT_SIZE as u64, self.prime_num_bits);
        let modulus: BigUint = F::MODULUS.into();

        let mut res = Vec::new();
        for _ in 0..num_elems {
            // Perform rejection sampling
            loop {
                // Obtain n bits and make it most-significant-bit first
                let mut bits = self.get_bits(self.prime_num_bits as usize);
                bits.reverse();

                let bytes = bits
                    .chunks(8)
                    .map(|chunk| {
                        let mut result = 0u8;
                        for (i, bit) in chunk.iter().enumerate() {
                            result |= u8::from(*bit) << i
                        }
                        result
                    })
                    .collect::<Vec<u8>>();

                let value = BigUint::from_bytes_le(&bytes);

                if value < modulus {
                    res.push(F::from(value.clone()));
                    break;
                }
            }
        }
        res
    }

    pub(crate) fn get_field_elements_mod_p<F: PrimeField>(&mut self, num_elems: usize) -> Vec<F> {
        assert_eq!(F::MODULUS_BIT_SIZE as u64, self.prime_num_bits);

        let mut res = Vec::new();
        for _ in 0..num_elems {
            // Obtain n bits and make it most-significant-bit first
            let mut bits = self.get_bits(self.prime_num_bits as usize);
            bits.reverse();

            let bytes = bits
                .chunks(8)
                .map(|chunk| {
                    let mut result = 0u8;
                    for (i, bit) in chunk.iter().enumerate() {
                        result |= u8::from(*bit) << i
                    }
                    result
                })
                .collect::<Vec<u8>>();

            res.push(F::from_le_bytes_mod_order(&bytes));
        }

        res
    }

    fn update(&mut self) -> bool {
        let new_bit = self.state[(self.head + 62) % 80]
            ^ self.state[(self.head + 51) % 80]
            ^ self.state[(self.head + 38) % 80]
            ^ self.state[(self.head + 23) % 80]
            ^ self.state[(self.head + 13) % 80]
            ^ self.state[self.head];
        self.state[self.head] = new_bit;
        self.head += 1;
        self.head %= 80;

        new_bit
    }

    fn init(&mut self) {
        for _ in 0..160 {
            let new_bit = self.state[(self.head + 62) % 80]
                ^ self.state[(self.head + 51) % 80]
                ^ self.state[(self.head + 38) % 80]
                ^ self.state[(self.head + 23) % 80]
                ^ self.state[(self.head + 13) % 80]
                ^ self.state[self.head];
            self.state[self.head] = new_bit;
            self.head += 1;
            self.head %= 80;
        }
    }
}
