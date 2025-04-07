use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        structure_traits::{BaseRing, Ring, Zero},
    },
    error::error_handler::anyhow_error_and_log,
};

use super::{
    lwe_ciphertext::{encrypt_lwe_ciphertext_list, get_batch_param_lwe_enc},
    lwe_key::LweSecretKeyShare,
    lwe_keyswitch_key::LweKeySwitchKeyShare,
    randomness::MPCEncryptionRandomGenerator,
};
use itertools::{EitherOrBoth, Itertools};
use tfhe::{
    core_crypto::{commons::math::decomposition::DecompositionLevel, prelude::ByteRandomGenerator},
    shortint::parameters::{DecompositionBaseLog, DecompositionLevelCount, LweDimension},
};

pub fn generate_lwe_keyswitch_key<Z, Gen, const EXTENSION_DEGREE: usize>(
    input_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    output_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    lwe_keyswitch_key: &mut LweKeySwitchKeyShare<Z, EXTENSION_DEGREE>,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
) -> anyhow::Result<()>
where
    Z: BaseRing,
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
    Gen: ByteRandomGenerator,
{
    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();

    let mut decomposition_plaintexts_buffer =
        vec![ResiduePoly::<Z, EXTENSION_DEGREE>::ZERO; decomp_level_count.0];

    for input_key_element_key_switch_key_block in input_lwe_sk
        .data_as_raw_vec()
        .iter()
        .zip_longest(lwe_keyswitch_key.iter_mut_levels())
    {
        if let EitherOrBoth::Both(input_key_element, key_switch_key_block) =
            input_key_element_key_switch_key_block
        {
            for level_message in (1..=decomp_level_count.0)
                .rev()
                .map(DecompositionLevel)
                .zip_longest(decomposition_plaintexts_buffer.iter_mut())
            {
                if let EitherOrBoth::Both(level, message) = level_message {
                    //We only generate KSK in the smaller encryption domain, so we hardcode the 64 value here
                    let shift = 64 - decomp_base_log.0 * level.0;
                    *message = (*input_key_element) << shift;
                } else {
                    return Err(anyhow_error_and_log("zip error"));
                }
            }

            encrypt_lwe_ciphertext_list(
                output_lwe_sk,
                key_switch_key_block,
                &decomposition_plaintexts_buffer,
                generator,
            )?;
        } else {
            return Err(anyhow_error_and_log("zip error"));
        }
    }
    Ok(())
}

pub fn allocate_and_generate_new_lwe_keyswitch_key<Z, Gen, const EXTENSION_DEGREE: usize>(
    input_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    output_lwe_sk: &LweSecretKeyShare<Z, EXTENSION_DEGREE>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    generator: &mut MPCEncryptionRandomGenerator<Z, Gen, EXTENSION_DEGREE>,
) -> anyhow::Result<LweKeySwitchKeyShare<Z, EXTENSION_DEGREE>>
where
    Z: BaseRing,
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = LweKeySwitchKeyShare::new(
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_lwe_sk.lwe_dimension(),
    );

    generate_lwe_keyswitch_key(
        input_lwe_sk,
        output_lwe_sk,
        &mut new_lwe_keyswitch_key,
        generator,
    )?;

    Ok(new_lwe_keyswitch_key)
}

pub fn get_batch_param_lwe_keyswitch_key(
    output_lwe_dimension: LweDimension,
    decomp_level_count: DecompositionLevelCount,
    t_uniform_bound: usize,
) -> (usize, usize) {
    get_batch_param_lwe_enc(
        output_lwe_dimension.0 * decomp_level_count.0,
        t_uniform_bound,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use tfhe::{
        core_crypto::{
            algorithms::{
                allocate_and_encrypt_new_lwe_ciphertext, decrypt_lwe_ciphertext,
                keyswitch_lwe_ciphertext,
            },
            commons::{
                generators::EncryptionRandomGenerator,
                math::{
                    decomposition::SignedDecomposer,
                    random::{DefaultRandomGenerator, TUniform},
                },
            },
            entities::{GlweSecretKeyOwned, LweCiphertext, LweSecretKeyOwned, Plaintext},
            seeders::new_seeder,
        },
        integer::parameters::DynamicDistribution,
        shortint::{
            parameters::{DecompositionBaseLog, DecompositionLevelCount, PolynomialSize},
            CiphertextModulus,
        },
    };

    use crate::{
        algebra::{
            base_ring::Z64, galois_rings::degree_4::ResiduePolyF4Z64, structure_traits::Ring,
        },
        execution::{
            online::{
                gen_bits::{BitGenEven, RealBitGenEven},
                preprocessing::dummy::DummyPreprocessing,
                secret_distributions::{RealSecretDistributions, SecretDistributions},
            },
            runtime::session::{LargeSession, ParameterHandles},
            tfhe_internals::{
                glwe_key::GlweSecretKeyShare,
                lwe_key::LweSecretKeyShare,
                parameters::TUniformBound,
                randomness::{
                    MPCEncryptionRandomGenerator, MPCMaskRandomGenerator, MPCNoiseRandomGenerator,
                },
                utils::reconstruct_bit_vec,
            },
        },
        networking::NetworkMode,
        tests::helper::tests_and_benches::execute_protocol_large,
    };
    use tfhe_csprng::generators::SoftwareRandomGenerator;

    use super::allocate_and_generate_new_lwe_keyswitch_key;

    #[test]
    #[ignore] //Ignore for now, might be able to run on CI with bigger timeout though
    fn test_lwe_keyswitch() {
        //Testing with NIST params P=8
        let lwe_dimension = 1024_usize;
        let polynomial_size = 512_usize;
        let glwe_dimension = 3_usize;
        let message_log_modulus = 2_usize;
        let ctxt_log_modulus = 64_usize;
        let ksk_base_log = 6_usize;
        let ksk_level_count = 2_usize;
        let scaling = ctxt_log_modulus - message_log_modulus;
        let t_uniform_bound_lwe = 41_usize;

        let msg = 3_u64;
        let seed = 0;

        let num_key_bits_lwe = lwe_dimension;
        let num_key_bits_glwe = glwe_dimension * polynomial_size;

        let mut task = |mut session: LargeSession| async move {
            let mut large_preproc = DummyPreprocessing::new(seed as u64, session.clone());

            //Generate the Lwe key
            let lwe_secret_key_share = LweSecretKeyShare::<Z64, 4> {
                data: RealBitGenEven::gen_bits_even(
                    num_key_bits_lwe,
                    &mut large_preproc,
                    &mut session,
                )
                .await
                .unwrap(),
            };

            //Generate the Glwe key
            let glwe_secret_key_share = GlweSecretKeyShare::<Z64, 4> {
                data: RealBitGenEven::gen_bits_even(
                    num_key_bits_glwe,
                    &mut large_preproc,
                    &mut session,
                )
                .await
                .unwrap(),
                polynomial_size: PolynomialSize(polynomial_size),
            };

            //Prepare enough noise for the ksk
            let t_uniform_amount = glwe_dimension * polynomial_size * ksk_level_count;
            let vec_tuniform_noise = RealSecretDistributions::t_uniform(
                t_uniform_amount,
                TUniformBound(t_uniform_bound_lwe),
                &mut large_preproc,
            )
            .unwrap()
            .iter()
            .map(|share| share.value())
            .collect_vec();

            let mut mpc_encryption_rng = MPCEncryptionRandomGenerator {
                mask: MPCMaskRandomGenerator::<SoftwareRandomGenerator>::new_from_seed(seed),
                noise: MPCNoiseRandomGenerator {
                    vec: vec_tuniform_noise,
                },
            };
            //Generate the ksk
            let big_lwe_key_share = glwe_secret_key_share.clone().into_lwe_secret_key();

            let ksk_share = allocate_and_generate_new_lwe_keyswitch_key(
                &big_lwe_key_share,
                &lwe_secret_key_share,
                DecompositionBaseLog(ksk_base_log),
                DecompositionLevelCount(ksk_level_count),
                &mut mpc_encryption_rng,
            )
            .unwrap();

            let ksk_opened = ksk_share
                .clone()
                .open_to_tfhers_type(&session)
                .await
                .unwrap();
            (
                session.my_role().unwrap(),
                lwe_secret_key_share,
                glwe_secret_key_share,
                ksk_opened,
            )
        };

        let parties = 5;
        let threshold = 1;

        //This is Async because triples are generated from dummy preprocessing
        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let results = execute_protocol_large::<
            _,
            _,
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
        >(
            parties,
            threshold,
            None,
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        );

        let mut lwe_key_shares = HashMap::new();
        let mut glwe_key_shares = HashMap::new();
        let ref_ksk = results[0].3.clone();
        for (role, lwe_share, glwe_share, ksk_opened) in results.into_iter() {
            lwe_key_shares.insert(role, Vec::new());
            let lwe_key_shares = lwe_key_shares.get_mut(&role).unwrap();
            for key_share in lwe_share.data {
                (*lwe_key_shares).push(key_share);
            }

            glwe_key_shares.insert(role, Vec::new());
            let glwe_key_shares = glwe_key_shares.get_mut(&role).unwrap();
            for key_share in glwe_share.data {
                (*glwe_key_shares).push(key_share)
            }

            assert_eq!(ref_ksk, ksk_opened);
        }

        //Reconstruct the secret keys
        let lwe_key = reconstruct_bit_vec(lwe_key_shares, num_key_bits_lwe, threshold);

        let glwe_key = reconstruct_bit_vec(glwe_key_shares, num_key_bits_glwe, threshold);

        //Cast both keys to tfhe-rs
        let lwe_secret_key = LweSecretKeyOwned::from_container(lwe_key);

        let glwe_secret_key =
            GlweSecretKeyOwned::from_container(glwe_key, PolynomialSize(polynomial_size));

        let big_lwe_sk = glwe_secret_key.into_lwe_secret_key();

        //Encrypt using the Glwe key seen as an lwe key
        let ciphertext_modulus = CiphertextModulus::new_native();
        let plaintext = Plaintext(msg << scaling);
        //Does this std dev work?
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            &big_lwe_sk,
            plaintext,
            DynamicDistribution::TUniform(TUniform::new(t_uniform_bound_lwe.try_into().unwrap())),
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut output_ct = LweCiphertext::new(
            0_u64,
            lwe_secret_key.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );

        //Perform key_switch
        keyswitch_lwe_ciphertext(&ref_ksk, &ct, &mut output_ct);

        //Decrypt using small key
        let decrypted = decrypt_lwe_ciphertext(&lwe_secret_key, &output_ct);

        let decomposer = SignedDecomposer::new(
            DecompositionBaseLog(message_log_modulus),
            DecompositionLevelCount(1),
        );

        let rounded = decomposer.closest_representable(decrypted.0);

        let cleartext = rounded >> scaling;

        assert_eq!(cleartext, msg);
    }
}
