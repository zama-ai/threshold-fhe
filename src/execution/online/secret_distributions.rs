use tracing::instrument;

use super::preprocessing::BitPreprocessing;
use crate::{
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::{
        sharing::share::Share,
        tfhe_internals::parameters::{NoiseInfo, TUniformBound},
    },
};

pub trait SecretDistributions {
    fn from_noise_info<Z, P>(
        noise_info: NoiseInfo,
        preproc: &mut P,
    ) -> anyhow::Result<Vec<Share<Z>>>
    where
        Z: Ring,
        P: BitPreprocessing<Z> + Send + ?Sized;

    fn t_uniform<Z, P>(
        n: usize,
        bound: TUniformBound,
        preproc: &mut P,
    ) -> anyhow::Result<Vec<Share<Z>>>
    where
        Z: Ring,
        P: BitPreprocessing<Z> + Send + ?Sized;

    fn newhope<Z, P>(n: usize, bound: usize, preproc: &mut P) -> anyhow::Result<Vec<Share<Z>>>
    where
        Z: Ring,
        P: BitPreprocessing<Z>;
}

/// Structures to execute the Secret Shared Distributions as described in Fig. 70 of NIST document.
pub struct RealSecretDistributions {}

impl SecretDistributions for RealSecretDistributions {
    fn from_noise_info<Z, P>(
        noise_info: NoiseInfo,
        preproc: &mut P,
    ) -> anyhow::Result<Vec<Share<Z>>>
    where
        Z: Ring,
        P: BitPreprocessing<Z> + Send + ?Sized,
    {
        Self::t_uniform(noise_info.amount, noise_info.tuniform_bound(), preproc)
    }

    /// Sample shares of a secret sampled from the TUniform(1, -2^bound, 2^bound)
    /// that is every value in (-2^bound, 2^bound) is selected with prob 1/2^{bound+1}
    /// and the endpoints are selected with prob 1/2^{bound+2}
    #[instrument(name = "MPC.TUniform", skip(n, bound, preproc),fields(bound=?bound,batch_size=?n))]
    fn t_uniform<Z, P>(
        n: usize,
        bound: TUniformBound,
        preproc: &mut P,
    ) -> anyhow::Result<Vec<Share<Z>>>
    where
        Z: Ring,
        P: BitPreprocessing<Z> + Send + ?Sized,
    {
        let bound = bound.0;
        let mut b = preproc.next_bit_vec(n * (bound + 2))?;

        let mut res = Vec::with_capacity(n);

        //No need to compute indexes, simply pop the shared bits
        for _ in 1..=n {
            //Start with next_random_bit() - 2^bound
            let mut ei = b
                .pop()
                .ok_or_else(|| anyhow_error_and_log("not enough bits in tuniform"))?
                - Z::from_u128(1 << bound);
            //for j in [1,bound+1], add next_random_bit() << (j-1)
            //(could do j in [0,bound], but we keep it closer to NIST doc notation)
            for j in 1..=bound + 1 {
                ei += b
                    .pop()
                    .ok_or_else(|| anyhow_error_and_log("not enough bits in tuniform"))?
                    * Z::from_u128(1 << (j - 1));
            }
            res.push(ei);
        }
        Ok(res)
    }

    #[instrument(name = "MPC.NewHope", skip(preproc,bound,n),fields(bound=?bound,batch_size=?n))]
    fn newhope<Z, P>(n: usize, bound: usize, preproc: &mut P) -> anyhow::Result<Vec<Share<Z>>>
    where
        Z: Ring,
        P: BitPreprocessing<Z>,
    {
        let mut b = preproc.next_bit_vec(2 * n * bound)?;
        let mut res = Vec::with_capacity(n);

        //No need to compute indexes, simply pop the shared bits
        //adding bound times (next_random_bit() - next_random_bit())
        //i.e. if bound = 1, we have {-1,0,1} with probability {1/4 , 1/2, 1/4}
        for _ in 1..=n {
            let mut e = b
                .pop()
                .ok_or_else(|| anyhow_error_and_log("not enough bits in newhope"))?
                - b.pop()
                    .ok_or_else(|| anyhow_error_and_log("not enough bits in newhope"))?;
            for _ in 1..bound {
                e += b
                    .pop()
                    .ok_or_else(|| anyhow_error_and_log("not enough bits in newhope"))?
                    - b.pop()
                        .ok_or_else(|| anyhow_error_and_log("not enough bits in newhope"))?;
            }
            res.push(e);
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        algebra::{
            galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
            structure_traits::Ring,
        },
        execution::{
            online::{preprocessing::dummy::DummyPreprocessing, triple::open_list},
            runtime::session::{LargeSession, ParameterHandles, SmallSession},
        },
        networking::NetworkMode,
        tests::helper::tests_and_benches::{execute_protocol_large, execute_protocol_small},
    };

    use super::{RealSecretDistributions, SecretDistributions, TUniformBound};

    #[test]
    fn test_newhope() {
        let parties = 5;
        let threshold = 1;
        let bound = 10; //NewHope(B) gives range [-10,10] with mean 0 and std deviation sqrt(5)
        let batch = 100;

        let mut task = |session: SmallSession<ResiduePolyF4Z64>, _bot: Option<String>| async move {
            let mut preproc = DummyPreprocessing::<ResiduePolyF4Z64, _, _>::new(0, session.clone());

            let res_vec = RealSecretDistributions::newhope(batch, bound, &mut preproc).unwrap();

            open_list(&res_vec, &session).await.unwrap()
        };

        // Online phase so Async because offline is dummy
        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let results = execute_protocol_small::<
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
            None,
        );

        //Ensure all values fall within bound
        let ref_res = results.first().unwrap();
        for v in ref_res {
            let r = v.to_scalar().unwrap();
            let centered_r = if r + r > r {
                r.0 as i64
            } else {
                let tmp = u64::MAX - r.0;
                -(tmp as i64 + 1)
            };
            assert!(centered_r >= -(bound as i64) && centered_r <= bound as i64);
        }
    }

    // TODO these two test could be merged into a generic test and then just calles with Z64 and Z128 respectively.
    #[test]
    fn test_uniform_z128() {
        let parties = 5;
        let threshold = 1;
        let bound = TUniformBound(2_usize);
        let batch = 100_usize;

        let mut task = |session: LargeSession| async move {
            let mut large_preproc =
                DummyPreprocessing::<ResiduePolyF4Z128, _, _>::new(0, session.clone());

            let res_vec =
                RealSecretDistributions::t_uniform(batch, bound, &mut large_preproc).unwrap();

            let opened_res = open_list(&res_vec, &session).await.unwrap();

            (session.my_role().unwrap(), opened_res)
        };

        // Rounds (only on the happy path here)
        // RealPreprocessing
        // init single sharing
        //         share dispute = 1 round
        //         pads =  1 round
        //         coinflip = vss + open = (1 + 3 + threshold) + 1
        //         verify = 1 reliable_broadcast = 3 + t rounds
        // init double sharing
        //         same as single sharing above (the single and double sharings are batched)
        //  triple batch - have been precomputed, just one open = 1 round
        //  random batch - have been precomputed = 0 rounds
        // t_uniform generates bits (mult + open) = 2 rounds
        // opening of the final output = 1 round
        //let rounds = 2 * (1 + 1 + (1 + 3 + threshold) + 1 + (3 + threshold)) + 1 + 2 + 1;
        //This is now a unit test as we use DummyPreprocessing, so only 1 round (for openeing at the end)
        // Online phase so Async because offline is dummy
        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let results = execute_protocol_large::<
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(
            parties,
            threshold,
            Some(1),
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        );

        //Check all parties agree and fall within expected bounds
        let ref_res = results[0].1.clone();
        for (_, res) in results {
            assert_eq!(res, ref_res);
        }
        for r in ref_res {
            let r = r.to_scalar().unwrap();
            //Center r
            let centered_r = if r + r > r {
                r.0 as i128
            } else {
                let tmp = u128::MAX - r.0;
                -(tmp as i128 + 1)
            };
            let bound = 2_i128.pow(bound.0 as u32);
            assert!(centered_r <= bound && centered_r >= -bound);
        }
    }

    #[test]
    fn test_uniform_z64() {
        let parties = 5;
        let threshold = 1;
        let bound = TUniformBound(2_usize);
        let batch = 100_usize;

        let mut task = |session: LargeSession| async move {
            //let mut large_preproc = RealLargePreprocessing::<ResiduePolyF4Z64>::init(
            //    &mut session,
            //    batch_sizes,
            //    TrueSingleSharing::default(),
            //    TrueDoubleSharing::default(),
            //)
            //.await
            //.unwrap();

            let mut large_preproc =
                DummyPreprocessing::<ResiduePolyF4Z64, _, _>::new(0, session.clone());

            let res_vec =
                RealSecretDistributions::t_uniform(batch, bound, &mut large_preproc).unwrap();

            let opened_res = open_list(&res_vec, &session).await.unwrap();

            (session.my_role().unwrap(), opened_res)
        };

        // Rounds (only on the happy path here)
        // RealPreprocessing
        // init single sharing
        //         share dispute = 1 round
        //         pads =  1 round
        //         coinflip = vss + open = (1 + 3 + threshold) + 1
        //         verify = 1 reliable_broadcast = 3 + t rounds
        // init double sharing
        //         same as single sharing above (the single and double sharings are batched)
        //  triple batch - have been precomputed, just one open = 1 round
        //  random batch - have been precomputed = 0 rounds
        // t_uniform generates bits (mult + open) = 2 rounds
        // opening of the final output = 1 round
        //let rounds = 2 * (1 + 1 + (1 + 3 + threshold) + 1 + (3 + threshold)) + 1 + 2 + 1;
        //This is now a unit test as we use DummyPreprocessing, so only 1 round (for openeing at the end)
        // Online phase so Async because offline is dummy
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
            Some(1),
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        );

        //Check all parties agree and fall within expected bounds
        let ref_res = results[0].1.clone();
        for (_, res) in results {
            assert_eq!(res, ref_res);
        }
        for r in ref_res {
            let r = r.to_scalar().unwrap();
            //Center r
            let centered_r = if r + r > r {
                r.0 as i64
            } else {
                let tmp = u64::MAX - r.0;
                -(tmp as i64 + 1)
            };
            let bound = 2_i64.pow(bound.0 as u32);
            assert!(centered_r <= bound && centered_r >= -bound);
        }
    }
}
