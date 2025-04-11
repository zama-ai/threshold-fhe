use std::collections::HashMap;

//This file contains code related to algebraric operations
//I put them there as they may not be needed anymore when/if
//part of this code is integrated in tfhe-rs
use itertools::{EitherOrBoth, Itertools};
use tfhe::HlCompactable;
use tfhe::{
    core_crypto::prelude::Numeric, prelude::Tagged, CompactCiphertextList, CompactPublicKey,
    HlExpandable,
};

use crate::execution::sharing::shamir::RevealOp;
use crate::{
    algebra::{
        galois_rings::common::ResiduePoly,
        poly::Poly,
        structure_traits::{BaseRing, ErrorCorrect, Ring, Zero},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        runtime::party::Role,
        sharing::{shamir::ShamirSharings, share::Share},
    },
};

use super::glwe_key::GlweSecretKeyShare;

pub fn slice_semi_reverse_negacyclic_convolution<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    output: &mut Vec<ResiduePoly<Z, EXTENSION_DEGREE>>,
    lhs: &[Z],
    rhs: &[ResiduePoly<Z, EXTENSION_DEGREE>],
) -> anyhow::Result<()> {
    debug_assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );
    debug_assert!(
        output.len() == lhs.len(),
        "output (len: {}) and lhs (len: {}) must have the same length",
        output.len(),
        lhs.len()
    );
    output.fill(ResiduePoly::ZERO);
    let mut rev_rhs = rhs.to_vec();
    rev_rhs.reverse();
    let lhs_pol = Poly::from_coefs(lhs.to_vec());
    let rhs_pol = Poly::from_coefs(rev_rhs);

    let res = pol_mul_reduce(&lhs_pol, &rhs_pol, output.len())?;
    *output = res.coefs;
    Ok(())
}

pub fn slice_to_polynomials<Z: Ring>(slice: &[Z], pol_size: usize) -> Vec<Poly<Z>> {
    let mut res: Vec<Poly<Z>> = Vec::new();
    for coefs in &slice.iter().chunks(pol_size) {
        let coef = coefs.copied().collect_vec();
        res.push(Poly::from_coefs(coef));
    }
    res
}

pub fn pol_mul_reduce<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    poly_1: &Poly<Z>,
    poly_2: &Poly<ResiduePoly<Z, EXTENSION_DEGREE>>,
    output_size: usize,
) -> anyhow::Result<Poly<ResiduePoly<Z, EXTENSION_DEGREE>>> {
    let mut coefs = (0..output_size)
        .map(|_| ResiduePoly::default())
        .collect_vec();

    debug_assert!(
        output_size == poly_1.coefs.len(),
        "Output polynomial size {:?} is not the same as input polynomial1 {:?}.",
        output_size,
        poly_1.coefs.len(),
    );
    debug_assert!(
        output_size == poly_2.coefs.len(),
        "Output polynomial size {:?} is not the same as input polynomial2 {:?}.",
        output_size,
        poly_2.coefs.len(),
    );

    for (lhs_degree, lhs_coef) in poly_1.coefs.iter().enumerate() {
        for (rhs_degree, rhs_coef) in poly_2.coefs.iter().enumerate() {
            let target_degree = lhs_degree + rhs_degree;
            if target_degree < output_size {
                let output_coefficient = coefs.get_mut(target_degree).ok_or_else(|| {
                    anyhow_error_and_log(format!(
                        "coefs of unexpected size, can't get at index {target_degree}"
                    ))
                })?;
                *output_coefficient += *rhs_coef * *lhs_coef;
            } else {
                let target_degree = target_degree % output_size;

                let output_coefficient = coefs.get_mut(target_degree).ok_or_else(|| {
                    anyhow_error_and_log(format!(
                        "coefs of unexpected size, can't get at index {target_degree}"
                    ))
                })?;
                *output_coefficient -= *rhs_coef * *lhs_coef;
            }
        }
    }

    Ok(Poly::from_coefs(coefs))
}

pub fn slice_wrapping_dot_product<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    lhs: &[Z],
    rhs: &[ResiduePoly<Z, EXTENSION_DEGREE>],
) -> anyhow::Result<ResiduePoly<Z, EXTENSION_DEGREE>> {
    lhs.iter()
        .zip_longest(rhs.iter())
        .try_fold(ResiduePoly::ZERO, |acc, left_right| {
            if let EitherOrBoth::Both(&left, &right) = left_right {
                Ok(acc + right * left)
            } else {
                Err(anyhow_error_and_log("zip error"))
            }
        })
}

pub fn polynomial_wrapping_add_multisum_assign<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    output_body: &mut [ResiduePoly<Z, EXTENSION_DEGREE>],
    output_mask: &[Z],
    glwe_secret_key_share: &GlweSecretKeyShare<Z, EXTENSION_DEGREE>,
) -> anyhow::Result<()>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
{
    let pol_dimension = glwe_secret_key_share.polynomial_size.0;
    let mut pol_output_body = Poly::from_coefs(output_body.to_vec());
    let pol_output_mask = slice_to_polynomials(output_mask, pol_dimension);
    let pol_glwe_secret_key_share =
        slice_to_polynomials(&glwe_secret_key_share.data_as_raw_vec(), pol_dimension);

    for poly_1_poly_2 in pol_output_mask
        .iter()
        .zip_longest(pol_glwe_secret_key_share.iter())
    {
        if let EitherOrBoth::Both(poly_1, poly_2) = poly_1_poly_2 {
            pol_output_body = pol_output_body + pol_mul_reduce(poly_1, poly_2, pol_dimension)?;
        } else {
            return Err(anyhow_error_and_log("zip error"));
        }
    }

    for coef_output_coef_pol in output_body
        .iter_mut()
        .zip_longest(pol_output_body.coefs.iter())
    {
        if let EitherOrBoth::Both(coef_output, coef_pol) = coef_output_coef_pol {
            *coef_output = *coef_pol;
        } else {
            return Err(anyhow_error_and_log("zip error"));
        }
    }
    Ok(())
}

pub fn slice_wrapping_scalar_mul_assign<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    lhs: &mut [ResiduePoly<Z, EXTENSION_DEGREE>],
    rhs: Z,
) {
    lhs.iter_mut().for_each(|lhs| *lhs = *lhs * rhs);
}

// NOTE: This may require the server key to be set to be able to expand
pub fn compact_encrypt_helper<M: HlCompactable + Numeric>(
    pk: &CompactPublicKey,
    msg: M,
    num_bits: usize,
) -> anyhow::Result<CompactCiphertextList> {
    let mut compact_list_builder = CompactCiphertextList::builder(pk);
    if num_bits == 1 {
        compact_list_builder.push(msg == M::ONE);
    } else {
        compact_list_builder.push_with_num_bits(msg, num_bits)?;
    }
    Ok(compact_list_builder.build())
}

pub fn expanded_encrypt<M: HlCompactable + Numeric, T: HlExpandable + Tagged>(
    pk: &CompactPublicKey,
    msg: M,
    num_bits: usize,
) -> anyhow::Result<T> {
    use crate::execution::tfhe_internals::utils;
    use tfhe::prelude::CiphertextList;
    let compact_list = utils::compact_encrypt_helper(pk, msg, num_bits)?;
    let expanded = compact_list.expand()?;
    expanded
        .get::<T>(0)?
        .ok_or(anyhow::anyhow!("expanded ciphertext list is empty"))
}

pub fn reconstruct_bit_vec<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    input: HashMap<Role, Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
    expected_num_bits: usize,
    threshold: usize,
) -> Vec<u64>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let mut output_bit_vec = Vec::new();
    for idx in 0..expected_num_bits {
        let mut vec_bit = Vec::new();
        for (_, values) in input.iter() {
            vec_bit.push(values[idx]);
        }

        let key_bit = ShamirSharings::create(vec_bit)
            .reconstruct(threshold)
            .unwrap()
            .to_scalar()
            .unwrap();

        //Assert we indeed have a bit
        assert_eq!(key_bit * (Z::ONE - key_bit), Z::ZERO);
        if key_bit == Z::ZERO {
            output_bit_vec.push(0_u64);
        } else {
            output_bit_vec.push(1_u64);
        }
    }
    output_bit_vec
}

pub fn reconstruct_glwe_body_vec<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    input: HashMap<Role, Vec<Share<ResiduePoly<Z, EXTENSION_DEGREE>>>>,
    expected_num_glwe_ctxt: usize,
    polynomial_size: usize,
    threshold: usize,
) -> Vec<Vec<Z>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ErrorCorrect,
{
    let mut output_body_vec = Vec::new();
    for glwe_ctxt_idx in 0..expected_num_glwe_ctxt {
        let mut body = Vec::new();
        let slice_start_idx = glwe_ctxt_idx * polynomial_size;
        let slice_end_idx = slice_start_idx + polynomial_size;
        for curr_glwe_ctxt_index in slice_start_idx..slice_end_idx {
            let mut vec_body = Vec::new();
            for (_role, values) in input.iter() {
                vec_body.push(values[curr_glwe_ctxt_index]);
            }
            body.push(
                ShamirSharings::create(vec_body)
                    .reconstruct(threshold)
                    .unwrap()
                    .to_scalar()
                    .unwrap(),
            );
        }

        output_body_vec.push(body);
    }
    output_body_vec
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;
    use std::path::Path;

    use itertools::Itertools;
    use tfhe::core_crypto::entities::{GlweSecretKeyOwned, LweSecretKeyOwned};

    use crate::algebra::base_ring::{Z128, Z64};
    use crate::algebra::galois_rings::common::ResiduePoly;
    use crate::execution::tfhe_internals::parameters::{DKGParams, DKGParamsBasics};
    use crate::{
        algebra::structure_traits::ErrorCorrect,
        execution::{
            endpoints::keygen::PrivateKeySet, runtime::party::Role, sharing::share::Share,
        },
    };

    use super::reconstruct_bit_vec;

    fn reconstruct_bit_vec_from_glwe_share_enum<const EXTENSION_DEGREE: usize>(
        input: HashMap<
            Role,
            crate::execution::endpoints::keygen::GlweSecretKeyShareEnum<EXTENSION_DEGREE>,
        >,
        expected_num_bits: usize,
        threshold: usize,
    ) -> Vec<u64>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        // TODO hopefully this method will go away since it's not
        // an elegant way to do reconstruction because we
        // have an enum on every share, instead of an enum on
        // all the shares, not to mention the use of "unsafe_cast"
        let some_key = input.keys().last().unwrap();
        let some_val = input.get(some_key).unwrap();
        match some_val {
            crate::execution::endpoints::keygen::GlweSecretKeyShareEnum::Z64(_share) => {
                let input: HashMap<_, _> = input
                    .into_iter()
                    .map(|(k, v)| (k, v.unsafe_cast_to_z64().data))
                    .collect();
                reconstruct_bit_vec::<Z64, EXTENSION_DEGREE>(input, expected_num_bits, threshold)
            }
            crate::execution::endpoints::keygen::GlweSecretKeyShareEnum::Z128(_share) => {
                let input: HashMap<_, _> = input
                    .into_iter()
                    .map(|(k, v)| (k, v.unsafe_cast_to_z128().data))
                    .collect();
                reconstruct_bit_vec::<Z128, EXTENSION_DEGREE>(input, expected_num_bits, threshold)
            }
        }
    }

    pub fn reconstruct_lwe_secret_key_from_file<
        const EXTENSION_DEGREE: usize,
        Params: DKGParamsBasics + ?Sized,
    >(
        parties: usize,
        threshold: usize,
        params: &Params,
        prefix_path: &Path,
    ) -> LweSecretKeyOwned<u64>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let mut sk_shares = HashMap::new();
        for party in 0..parties {
            sk_shares.insert(
                Role::indexed_by_zero(party),
                PrivateKeySet::<EXTENSION_DEGREE>::read_from_file(
                    prefix_path.join(format!("sk_p{}.der", party)).as_path(),
                )
                .unwrap(),
            );
        }

        let mut lwe_key_shares = HashMap::new();
        for (role, sk) in sk_shares {
            lwe_key_shares.insert(role, Vec::new());
            let lwe_key_shares = lwe_key_shares.get_mut(&role).unwrap();
            for key_share in sk.lwe_compute_secret_key_share.data.into_iter() {
                (*lwe_key_shares).push(key_share);
            }
        }

        //Reconstruct the keys
        let lwe_key = reconstruct_bit_vec(lwe_key_shares, params.lwe_dimension().0, threshold);
        LweSecretKeyOwned::from_container(lwe_key)
    }

    #[allow(clippy::type_complexity)]
    fn read_secret_key_shares_from_file<const EXTENSION_DEGREE: usize>(
        parties: usize,
        params: DKGParams,
        prefix_path: &Path,
    ) -> (
        HashMap<
            Role,
            crate::execution::endpoints::keygen::GlweSecretKeyShareEnum<EXTENSION_DEGREE>,
        >,
        HashMap<Role, Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>,
    ) {
        let mut sk_shares = HashMap::new();
        for party in 0..parties {
            sk_shares.insert(
                Role::indexed_by_zero(party),
                PrivateKeySet::read_from_file(
                    prefix_path.join(format!("sk_p{}.der", party)).as_path(),
                )
                .unwrap(),
            );
        }

        let mut glwe_key_shares = HashMap::new();
        let mut big_glwe_key_shares = HashMap::new();
        for (role, sk) in sk_shares {
            glwe_key_shares.insert(role, sk.glwe_secret_key_share);

            match params {
                DKGParams::WithoutSnS(_) => (),
                DKGParams::WithSnS(_) => {
                    let _ = big_glwe_key_shares
                        .insert(role, sk.glwe_secret_key_share_sns_as_lwe.unwrap().data);
                }
            }
        }
        (glwe_key_shares, big_glwe_key_shares)
    }

    pub fn reconstruct_glwe_secret_key_from_file<const EXTENSION_DEGREE: usize>(
        parties: usize,
        threshold: usize,
        params: DKGParams,
        prefix_path: &Path,
    ) -> (GlweSecretKeyOwned<u64>, Option<LweSecretKeyOwned<u128>>)
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let (glwe_key_shares, big_glwe_key_shares) =
            read_secret_key_shares_from_file::<EXTENSION_DEGREE>(parties, params, prefix_path);
        let glwe_key = reconstruct_bit_vec_from_glwe_share_enum(
            glwe_key_shares,
            params.get_params_basics_handle().glwe_sk_num_bits(),
            threshold,
        );
        let glwe_secret_key = GlweSecretKeyOwned::from_container(
            glwe_key,
            params.get_params_basics_handle().polynomial_size(),
        );

        let big_glwe_secret_key = match params {
            DKGParams::WithSnS(sns_params) => {
                let big_glwe_key = reconstruct_bit_vec(
                    big_glwe_key_shares,
                    sns_params.glwe_sk_num_bits_sns(),
                    threshold,
                )
                .into_iter()
                .map(|bit| bit as u128)
                .collect_vec();
                Some(
                    GlweSecretKeyOwned::from_container(
                        big_glwe_key,
                        sns_params.polynomial_size_sns(),
                    )
                    .into_lwe_secret_key(),
                )
            }
            DKGParams::WithoutSnS(_) => None,
        };

        (glwe_secret_key, big_glwe_secret_key)
    }
}
