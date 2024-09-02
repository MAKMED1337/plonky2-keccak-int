use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_crypto::biguint::BigUintTarget;
use plonky2_crypto::hash::keccak256::{CircuitBuilderHashKeccak, WitnessHashKeccak, KECCAK256_R};
use plonky2_crypto::hash::{CircuitBuilderHash, HashInputTarget, HashOutputTarget};
use plonky2_crypto::u32::arithmetic_u32::CircuitBuilderU32;

pub trait CircuitBuilderKeccakInt<F: RichField + Extendable<D>, const D: usize> {
    fn pad_keccak(&mut self, target: &mut HashInputTarget, input_len_bits: usize);
    fn keccak_int(&mut self, i: u32, input: &BigUintTarget) -> HashOutputTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderKeccakInt<F, D>
    for CircuitBuilder<F, D>
{
    fn pad_keccak(&mut self, target: &mut HashInputTarget, input_len_bits: usize) {
        assert!(input_len_bits % 32 == 0);
        let num_actual_blocks = 1 + input_len_bits / KECCAK256_R;

        let padded_len_bits = num_actual_blocks * KECCAK256_R;

        // bit right after the end of the message
        // because bits are aligned, we can set the whole number
        // target.set_bit(input_len_bits as u64, true);
        let one = self.constant_u32(1);
        self.connect_u32(target.input.get_limb(input_len_bits / 32), one);

        // last bit of the last block
        // target.set_bit(padded_len_bits as u64 - 1, true);
        assert!((padded_len_bits - 1) / 32 > input_len_bits / 32);

        let last_u32 = self.constant_u32(1u32 << ((padded_len_bits - 1) % 32));
        self.connect_u32(target.input.get_limb((padded_len_bits - 1) / 32), last_u32);

        for i in input_len_bits / 32 + 1..(padded_len_bits - 1) / 32 {
            let zero = self.constant_u32(0);
            self.connect_u32(target.input.get_limb(i), zero);
        }

        // self.set_hash_blocks_target(target, num_actual_blocks);
        for (i, t) in target.blocks.iter().enumerate() {
            let bool = self.constant_bool(i < num_actual_blocks - 1);
            self.connect(t.target, bool.target);
        }
    }

    // computes keccak(concat(i, message)), where i will be written in le using 4 bytes
    fn keccak_int(&mut self, i: u32, input: &BigUintTarget) -> HashOutputTarget {
        let bits = input.num_limbs() * 32 + 32;
        let blocks = (bits + KECCAK256_R - 1) / KECCAK256_R; // ceil

        let mut num_input = self.add_virtual_hash_input_target(blocks, KECCAK256_R);

        let num = self.constant_u32(i);
        self.connect_u32(num_input.input.get_limb(0), num);

        for (i, &limb) in input.limbs.iter().enumerate() {
            self.connect_u32(num_input.input.get_limb(i + 1), limb);
        }

        self.pad_keccak(&mut num_input, bits);
        self.hash_keccak256(&num_input)
    }
}

fn main() {
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::*;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let target_input = builder.add_virtual_hash_input_target(1, KECCAK256_R);
    let inner = builder.hash_keccak256(&target_input);
    let target_output = builder.keccak_int(0x10, &inner);

    let data = builder.build::<C>();

    // input: 5010
    // keccak: b93a99e0cbeef38e1b5688a1e9b9cc6caf91fa36a1a04348d5d97d538087a2fb
    // int || keccak: 10000000b93a99e0cbeef38e1b5688a1e9b9cc6caf91fa36a1a04348d5d97d538087a2fb
    // keccak2: 2d5d58fa30a14be70cfee49a37d92eea3b9d64e9a35eea4a10b45b26640b4d90
    // bytes are in le order, but bytes in hex are 01 => 1, 10 => 16
    let input = hex::decode("5010").unwrap();
    let output =
        hex::decode("2d5d58fa30a14be70cfee49a37d92eea3b9d64e9a35eea4a10b45b26640b4d90").unwrap();

    // set input/output
    let mut pw = PartialWitness::new();
    pw.set_keccak256_input_target(&target_input, &input);
    pw.set_keccak256_output_target(&target_output, &output);

    // generate proof
    let proof = data.prove(pw).unwrap();

    // verify proof
    assert!(data.verify(proof).is_ok());
}
