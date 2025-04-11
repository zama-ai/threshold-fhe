use crate::execution::config::BatchParams;
use crate::execution::online::preprocessing::memory::InMemoryBasePreprocessing;
use crate::execution::online::preprocessing::{
    BasePreprocessing, RandomPreprocessing, TriplePreprocessing,
};
use crate::{
    algebra::structure_traits::{ErrorCorrect, Ring},
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::triple::Triple,
        runtime::session::LargeSessionHandles,
        sharing::{open::robust_opens_to_all, share::Share},
    },
};
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use tracing::{info_span, instrument, Instrument};

pub struct LargePreprocessing<Z: Ring, S: SingleSharing<Z>, D: DoubleSharing<Z>> {
    triple_batch_size: usize,
    random_batch_size: usize,
    single_sharing_handle: S,
    double_sharing_handle: D,
    elements: Box<dyn BasePreprocessing<Z>>,
}

impl<Z: Ring + ErrorCorrect, S: SingleSharing<Z>, D: DoubleSharing<Z>> LargePreprocessing<Z, S, D> {
    /// Initializes the preprocessing with a fresh batch of triples and randomness
    /// This executes the GenTriples and Nextrandom based on the provided [`BatchParams`]
    pub async fn init<R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        session: &mut L,
        batch_sizes: BatchParams,
        mut ssh: S,
        mut dsh: D,
    ) -> anyhow::Result<Self> {
        let init_span = info_span!("MPC_Large.Init", sid=?session.session_id(), own_identity=?session.own_identity(), batch_size=?batch_sizes);
        //Init single sharing, we need 2 calls per triple and 1 call per randomness
        ssh.init(session, 2 * batch_sizes.triples + batch_sizes.randoms)
            .instrument(init_span.clone())
            .await?;

        //Init double sharing, we need 1 call per triple
        dsh.init(session, batch_sizes.triples)
            .instrument(init_span)
            .await?;

        //We always want the session to use in-memory storage, it's up to higher level process (e.g. orchestrator)
        //to maybe decide to store data somewhere else
        let base_preprocessing = Box::<InMemoryBasePreprocessing<Z>>::default();
        let mut large_preproc = Self {
            triple_batch_size: batch_sizes.triples,
            random_batch_size: batch_sizes.randoms,
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            elements: base_preprocessing,
        };

        if batch_sizes.triples > 0 {
            //Preprocess a batch of triples
            large_preproc.next_triple_batch(session).await?;
        }
        if batch_sizes.randoms > 0 {
            //Preprocess a batch of randomness
            large_preproc.next_random_batch(session).await?;
        }

        Ok(large_preproc)
    }

    /// Constructs a new batch of triples and appends this to the internal triple storage.
    /// If the method terminates correctly then an _entire_ new batch has been constructed and added to the internal stash.
    #[instrument(name="MPC_Large.GenTriples",skip(self,session), fields(sid = ?session.session_id(), own_identity = ?session.own_identity(), ?batch_size=self.triple_batch_size))]
    async fn next_triple_batch<R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<()> {
        if self.triple_batch_size == 0 {
            return Ok(());
        }

        //NOTE: We create the telemetry span fro SingleSharing Next here, but in truth the bulk of the work has been done in init
        //Next will simply pop stuff
        let single_sharing_span = info_span!(
            "SingleSharing.Next",
            session_id = ?session.session_id(),
            own_identity = ?session.own_identity(),
            batch_size = 2 * self.triple_batch_size
        );

        //NOTE: We create the telemetry span fro DoubleSharing Next here, but in truth the bulk of the work has been done in init
        //Next will simply pop stuff
        let double_sharing_span = info_span!("DoubleSharing.Next",
            sid = ?session.session_id(),
                own_identity = ?session.own_identity(),
                batch_size =  self.triple_batch_size
        );

        let mut vec_share_x = Vec::with_capacity(self.triple_batch_size);
        let mut vec_share_y = Vec::with_capacity(self.triple_batch_size);
        let mut vec_double_share_v = Vec::with_capacity(self.triple_batch_size);

        for _ in 0..self.triple_batch_size {
            vec_share_x.push(
                self.single_sharing_handle
                    .next(session)
                    .instrument(single_sharing_span.clone())
                    .await?,
            );
            vec_share_y.push(
                self.single_sharing_handle
                    .next(session)
                    .instrument(single_sharing_span.clone())
                    .await?,
            );
            vec_double_share_v.push(
                self.double_sharing_handle
                    .next(session)
                    .instrument(double_sharing_span.clone())
                    .await?,
            );
        }

        //Compute <d>_i^{2t} = <x>_i * <y>_i + <v>^{2t}
        let network_vec_share_d = vec_share_x
            .iter()
            .zip(vec_share_y.iter())
            .zip(vec_double_share_v.iter())
            .map(|((x, y), v)| *x * *y + v.degree_2t)
            .collect_vec();

        //Perform RobustOpen on the degree 2t masked z component
        //TODO: For now NIST doc doesn't explicitly call this robust_open,
        //but I believe this is exactly what we're doing
        let recons_vec_share_d = robust_opens_to_all(
            session,
            &network_vec_share_d,
            2 * session.threshold() as usize,
        )
        .await?
        .ok_or_else(|| {
            anyhow_error_and_log("Reconstruction failed in offline triple generation".to_string())
        })?;

        //Remove the mask from the opened value
        let vec_shares_z: Vec<_> = recons_vec_share_d
            .into_iter()
            .zip(vec_double_share_v.iter())
            .map(|(d, v)| d - v.degree_t)
            .collect_vec();

        let my_role = session.my_role()?;
        let res = vec_share_x
            .into_iter()
            .zip(vec_share_y.into_iter())
            .zip(vec_shares_z.into_iter())
            .map(|((x, y), z)| {
                Triple::new(
                    Share::new(my_role, x),
                    Share::new(my_role, y),
                    Share::new(my_role, z),
                )
            })
            .collect_vec();
        self.elements.append_triples(res);
        Ok(())
    }

    /// Computes a new batch of random values and appends the new batch to the the existing stash of prepreocessing random values.
    /// If the method terminates correctly then an _entire_ new batch has been constructed and added to the internal stash.
    #[instrument(name="MPC_Large.GenRandom",skip(self,session), fields(sid = ?session.session_id(), own_identity = ?session.own_identity(), batch_size = ?self.random_batch_size))]
    async fn next_random_batch<R: Rng + CryptoRng, L: LargeSessionHandles<R>>(
        &mut self,
        session: &mut L,
    ) -> anyhow::Result<()> {
        //NOTE: We create the telemetry span fro SingleSharing Next here, but in truth the bulk of the work has been done in init
        //Next will simply pop stuff
        let single_sharing_span = info_span!(
            "SingleSharing.Next",
            sid = ?session.session_id(),
            own_identity = ?session.own_identity(),
            batch_size = self.random_batch_size
        );
        let my_role = session.my_role()?;
        let mut res = Vec::with_capacity(self.random_batch_size);
        for _ in 0..self.random_batch_size {
            res.push(Share::new(
                my_role,
                self.single_sharing_handle
                    .next(session)
                    .instrument(single_sharing_span.clone())
                    .await?,
            ));
        }
        self.elements.append_randoms(res);
        Ok(())
    }
}

impl<Z: Ring, S, D> TriplePreprocessing<Z> for LargePreprocessing<Z, S, D>
where
    S: SingleSharing<Z>,
    D: DoubleSharing<Z>,
{
    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
        self.elements.next_triple_vec(amount)
    }

    fn append_triples(&mut self, triples: Vec<Triple<Z>>) {
        self.elements.append_triples(triples);
    }

    fn triples_len(&self) -> usize {
        self.elements.triples_len()
    }
}

impl<Z: Ring, S, D> RandomPreprocessing<Z> for LargePreprocessing<Z, S, D>
where
    S: SingleSharing<Z>,
    D: DoubleSharing<Z>,
{
    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        self.elements.next_random_vec(amount)
    }

    fn append_randoms(&mut self, randoms: Vec<Share<Z>>) {
        self.elements.append_randoms(randoms);
    }

    fn randoms_len(&self) -> usize {
        self.elements.randoms_len()
    }
}

impl<Z: Ring, S, D> BasePreprocessing<Z> for LargePreprocessing<Z, S, D>
where
    S: SingleSharing<Z> + Sync,
    D: DoubleSharing<Z> + Sync,
{
}

use crate::execution::large_execution::share_dispute::RealShareDispute;

use super::{
    coinflip::RealCoinflip,
    double_sharing::{DoubleSharing, RealDoubleSharing},
    local_double_share::RealLocalDoubleShare,
    local_single_share::RealLocalSingleShare,
    single_sharing::{RealSingleSharing, SingleSharing},
    vss::RealVss,
};

pub type TrueSingleSharing<Z> =
    RealSingleSharing<Z, RealLocalSingleShare<RealCoinflip<RealVss>, RealShareDispute>>;
pub type TrueDoubleSharing<Z> =
    RealDoubleSharing<Z, RealLocalDoubleShare<RealCoinflip<RealVss>, RealShareDispute>>;
pub type RealLargePreprocessing<Z> =
    LargePreprocessing<Z, TrueSingleSharing<Z>, TrueDoubleSharing<Z>>;

#[cfg(test)]
mod tests {

    use super::{TrueDoubleSharing, TrueSingleSharing};
    use crate::algebra::structure_traits::{Derive, ErrorCorrect, Invert, RingEmbed};
    use crate::execution::config::BatchParams;
    use crate::execution::online::preprocessing::memory::InMemoryBasePreprocessing;
    use crate::execution::online::preprocessing::{RandomPreprocessing, TriplePreprocessing};
    use crate::execution::sharing::shamir::RevealOp;
    use crate::networking::NetworkMode;
    use crate::{
        algebra::{
            galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
            structure_traits::Ring,
        },
        execution::{
            large_execution::{
                coinflip::{
                    tests::{DroppingCoinflipAfterVss, MaliciousCoinflipRecons},
                    Coinflip, RealCoinflip,
                },
                double_sharing::{tests::create_real_double_sharing, DoubleSharing},
                local_double_share::{
                    tests::{MaliciousReceiverLocalDoubleShare, MaliciousSenderLocalDoubleShare},
                    LocalDoubleShare, RealLocalDoubleShare,
                },
                local_single_share::{
                    tests::{MaliciousReceiverLocalSingleShare, MaliciousSenderLocalSingleShare},
                    LocalSingleShare, RealLocalSingleShare,
                },
                offline::LargePreprocessing,
                share_dispute::{
                    tests::{
                        DroppingShareDispute, MaliciousShareDisputeRecons, WrongShareDisputeRecons,
                    },
                    RealShareDispute, ShareDispute,
                },
                single_sharing::{tests::create_real_single_sharing, SingleSharing},
                vss::{
                    tests::{
                        DroppingVssAfterR1, DroppingVssAfterR2, DroppingVssFromStart,
                        MaliciousVssR1,
                    },
                    RealVss, Vss,
                },
            },
            online::{preprocessing::BasePreprocessing, triple::Triple},
            runtime::session::{
                BaseSessionHandles, LargeSession, LargeSessionHandles, ParameterHandles,
            },
            sharing::{open::robust_opens_to_all, shamir::ShamirSharings, share::Share},
        },
        tests::helper::{
            tests::{execute_protocol_large_w_disputes_and_malicious, TestingParameters},
            tests_and_benches::execute_protocol_large,
        },
    };
    use async_trait::async_trait;
    use itertools::Itertools;
    use rstest::rstest;

    impl<Z: Ring, S: SingleSharing<Z>, D: DoubleSharing<Z>> Default for LargePreprocessing<Z, S, D> {
        fn default() -> Self {
            Self {
                triple_batch_size: 0,
                random_batch_size: 0,
                single_sharing_handle: S::default(),
                double_sharing_handle: D::default(),
                elements: Box::<InMemoryBasePreprocessing<Z>>::default(),
            }
        }
    }

    impl<Z: Ring, S: SingleSharing<Z>, D: DoubleSharing<Z>> Clone for LargePreprocessing<Z, S, D> {
        fn clone(&self) -> Self {
            Self {
                triple_batch_size: self.triple_batch_size,
                random_batch_size: self.random_batch_size,
                single_sharing_handle: self.single_sharing_handle.clone(),
                double_sharing_handle: self.double_sharing_handle.clone(),
                elements: Box::<InMemoryBasePreprocessing<Z>>::default(),
            }
        }
    }

    fn test_offline_strategies<
        Z: Ring + RingEmbed + Derive + Invert + ErrorCorrect,
        const EXTENSION_DEGREE: usize,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
        P: GenericMaliciousPreprocessing<Z, S, D> + 'static,
    >(
        params: TestingParameters,
        malicious_offline: P,
    ) {
        let num_batches = 3;
        let (_, malicious_due_to_dispute) = params.get_dispute_map();
        let batch_sizes = BatchParams {
            triples: 10,
            randoms: 10,
        };
        let mut task_honest = |mut session: LargeSession| async move {
            let mut res_triples = Vec::new();
            let mut res_random = Vec::new();

            for _ in 0..num_batches {
                let mut real_preproc =
                    LargePreprocessing::<Z, TrueSingleSharing<Z>, TrueDoubleSharing<Z>>::init(
                        &mut session,
                        batch_sizes,
                        TrueSingleSharing::default(),
                        TrueDoubleSharing::default(),
                    )
                    .await
                    .unwrap();

                res_triples.append(&mut real_preproc.next_triple_vec(batch_sizes.triples).unwrap());
                res_random.append(&mut real_preproc.next_random_vec(batch_sizes.randoms).unwrap());
            }

            (
                session.my_role().unwrap(),
                (res_triples, res_random),
                session.corrupt_roles().clone(),
                session.disputed_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, mut malicious_offline: P| async move {
            for _ in 0..num_batches {
                let _ = malicious_offline.init(&mut session, batch_sizes).await;
            }

            session.my_role().unwrap()
        };

        //Preprocessing assumes Sync network
        let (result_honest, _) =
            execute_protocol_large_w_disputes_and_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &params.dispute_pairs,
                &[
                    malicious_due_to_dispute.clone(),
                    params.malicious_roles.to_vec(),
                ]
                .concat(),
                malicious_offline,
                NetworkMode::Sync,
                None,
                &mut task_honest,
                &mut task_malicious,
            );

        //make sure the dispute and malicious set of all honest parties is in sync
        let ref_malicious_set = result_honest[0].2.clone();
        let ref_dispute_set = result_honest[0].3.clone();
        for (_, _, malicious_set, dispute_set) in result_honest.iter() {
            assert_eq!(malicious_set, &ref_malicious_set);
            assert_eq!(dispute_set, &ref_dispute_set);
        }

        //If it applies
        //Make sure malicious parties are detected as such
        if params.should_be_detected {
            for role in &[
                malicious_due_to_dispute.clone(),
                params.malicious_roles.to_vec(),
            ]
            .concat()
            {
                assert!(ref_malicious_set.contains(role));
            }
        } else {
            assert!(ref_malicious_set.is_empty());
        }

        //Check that everything reconstructs, and that triples are triples
        for triple_idx in 0..num_batches * batch_sizes.randoms {
            let mut vec_x = Vec::new();
            let mut vec_y = Vec::new();
            let mut vec_z = Vec::new();
            let mut vec_r = Vec::new();
            for (_, res, _, _) in result_honest.iter() {
                let (x, y, z) = res.0[triple_idx].take();
                let r = res.1[triple_idx];
                vec_x.push(x);
                vec_y.push(y);
                vec_z.push(z);
                vec_r.push(r);
            }
            let shamir_sharing_x = ShamirSharings::create(vec_x);
            let shamir_sharing_y = ShamirSharings::create(vec_y);
            let shamir_sharing_z = ShamirSharings::create(vec_z);
            let x = shamir_sharing_x.reconstruct(params.threshold);
            let y = shamir_sharing_y.reconstruct(params.threshold);
            let z = shamir_sharing_z.reconstruct(params.threshold);
            assert!(x.is_ok());
            assert!(y.is_ok());
            assert!(z.is_ok());
            assert_eq!(x.unwrap() * y.unwrap(), z.unwrap());

            let shamir_sharing_r = ShamirSharings::create(vec_r);
            let r = shamir_sharing_r.reconstruct(params.threshold);
            assert!(r.is_ok());
        }
    }

    #[async_trait]
    trait GenericMaliciousPreprocessing<
        Z: Ring + Derive + ErrorCorrect,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    >: BasePreprocessing<Z> + Clone + Send
    {
        async fn init(
            &mut self,
            session: &mut LargeSession,
            batch_sizes: BatchParams,
        ) -> anyhow::Result<()>;

        async fn next_triple_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()>;

        async fn next_random_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()>;
    }

    #[derive(Default, Clone)]
    ///Malicious strategy that introduces an error in the reconstruction of beaver
    /// NOTE: Expect to fill single_sharing and double_sharing at creation
    pub(crate) struct CheatingLargePreprocessing<
        Z: Ring + Derive + ErrorCorrect,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    > {
        triple_batch_size: usize,
        random_batch_size: usize,
        single_sharing_handle: S,
        double_sharing_handle: D,
        available_triples: Vec<Triple<Z>>,
        available_randoms: Vec<Share<Z>>,
    }

    #[derive(Default, Clone)]
    ///Acts as a wrapper around the acutal protocol, needed because of the trait design around preprocessing
    pub(crate) struct HonestLargePreprocessing<
        Z: Ring + Derive + ErrorCorrect,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    > {
        single_sharing_handle: S,
        double_sharing_handle: D,
        large_preproc: LargePreprocessing<Z, S, D>,
    }

    #[async_trait]
    impl<
            Z: Ring + Derive + ErrorCorrect,
            S: SingleSharing<Z> + Sync,
            D: DoubleSharing<Z> + Sync,
        > GenericMaliciousPreprocessing<Z, S, D> for CheatingLargePreprocessing<Z, S, D>
    {
        async fn init(
            &mut self,
            session: &mut LargeSession,
            batch_sizes: BatchParams,
        ) -> anyhow::Result<()> {
            //Init single sharing
            self.single_sharing_handle
                .init(session, 2 * batch_sizes.triples + batch_sizes.randoms)
                .await?;

            //Init double sharing
            self.double_sharing_handle
                .init(session, batch_sizes.triples)
                .await?;

            self.triple_batch_size = batch_sizes.triples;
            self.random_batch_size = batch_sizes.randoms;
            self.available_triples.clear();
            self.available_randoms.clear();

            self.next_triple_batch(session).await?;
            self.next_random_batch(session).await?;

            Ok(())
        }

        //Lie to other in reconstructing masked product
        async fn next_triple_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()> {
            let mut vec_share_x = Vec::with_capacity(self.triple_batch_size);
            let mut vec_share_y = Vec::with_capacity(self.triple_batch_size);
            let mut vec_double_share_v = Vec::with_capacity(self.triple_batch_size);
            for _ in 0..self.triple_batch_size {
                vec_share_x.push(self.single_sharing_handle.next(session).await?);
                vec_share_y.push(self.single_sharing_handle.next(session).await?);
                vec_double_share_v.push(self.double_sharing_handle.next(session).await?);
            }

            //Add random error to every d and remove one
            let mut network_vec_share_d = vec_share_x
                .iter()
                .zip(vec_share_y.iter())
                .zip(vec_double_share_v.iter())
                .map(|((x, y), v)| {
                    let res = *x * *y + v.degree_2t + Z::sample(session.rng());
                    res
                })
                .collect_vec();
            network_vec_share_d.pop();

            let recons_vec_share_d = robust_opens_to_all(
                session,
                &network_vec_share_d,
                2 * session.threshold() as usize,
            )
            .await?
            .unwrap();

            let vec_share_z: Vec<_> = recons_vec_share_d
                .into_iter()
                .zip(vec_double_share_v.iter())
                .map(|(d, v)| d - v.degree_t)
                .collect_vec();

            let my_role = session.my_role()?;
            let res = vec_share_x
                .into_iter()
                .zip(vec_share_y)
                .zip(vec_share_z)
                .map(|((x, y), z)| {
                    Triple::new(
                        Share::new(my_role, x),
                        Share::new(my_role, y),
                        Share::new(my_role, z),
                    )
                })
                .collect_vec();
            self.available_triples = res;
            Ok(())
        }

        async fn next_random_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()> {
            let my_role = session.my_role()?;
            let mut res = Vec::with_capacity(self.random_batch_size);
            for _ in 0..self.random_batch_size {
                res.push(Share::new(
                    my_role,
                    self.single_sharing_handle.next(session).await?,
                ));
            }
            self.available_randoms = res;
            Ok(())
        }
    }

    impl<Z, S, D> TriplePreprocessing<Z> for CheatingLargePreprocessing<Z, S, D>
    where
        Z: Ring + Derive + ErrorCorrect,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    {
        fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
            if self.available_triples.len() >= amount {
                Ok(self.available_triples.drain(0..amount).collect())
            } else {
                Ok(Vec::new())
            }
        }

        fn append_triples(&mut self, triples: Vec<Triple<Z>>) {
            self.available_triples.extend(triples);
        }

        fn triples_len(&self) -> usize {
            self.available_triples.len()
        }
    }

    impl<Z, S, D> RandomPreprocessing<Z> for CheatingLargePreprocessing<Z, S, D>
    where
        Z: Ring + ErrorCorrect + Derive,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    {
        fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
            if self.available_randoms.len() >= amount {
                Ok(self.available_randoms.drain(0..amount).collect())
            } else {
                Ok(Vec::new())
            }
        }

        fn append_randoms(&mut self, randoms: Vec<Share<Z>>) {
            self.available_randoms.extend(randoms);
        }

        fn randoms_len(&self) -> usize {
            self.available_randoms.len()
        }
    }

    impl<Z, S, D> BasePreprocessing<Z> for CheatingLargePreprocessing<Z, S, D>
    where
        Z: Ring + ErrorCorrect + Derive,
        S: SingleSharing<Z> + Sync,
        D: DoubleSharing<Z> + Sync,
    {
    }

    //Needed because LargePreprocessing doesnt implement a specific trait
    #[async_trait]
    impl<
            Z: Ring + Derive + ErrorCorrect,
            S: SingleSharing<Z> + Sync,
            D: DoubleSharing<Z> + Sync,
        > GenericMaliciousPreprocessing<Z, S, D> for HonestLargePreprocessing<Z, S, D>
    {
        async fn init(
            &mut self,
            session: &mut LargeSession,
            batch_sizes: BatchParams,
        ) -> anyhow::Result<()> {
            self.large_preproc = LargePreprocessing::<Z, S, D>::init(
                session,
                batch_sizes,
                self.single_sharing_handle.clone(),
                self.double_sharing_handle.clone(),
            )
            .await
            .unwrap();
            Ok(())
        }

        async fn next_triple_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()> {
            self.large_preproc.next_triple_batch(session).await
        }

        async fn next_random_batch(&mut self, session: &mut LargeSession) -> anyhow::Result<()> {
            self.large_preproc.next_random_batch(session).await
        }
    }

    impl<Z, S, D> TriplePreprocessing<Z> for HonestLargePreprocessing<Z, S, D>
    where
        Z: Ring + Derive + ErrorCorrect,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    {
        fn next_triple(&mut self) -> anyhow::Result<Triple<Z>> {
            self.large_preproc.next_triple()
        }
        fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
            self.large_preproc.next_triple_vec(amount)
        }

        fn append_triples(&mut self, triples: Vec<Triple<Z>>) {
            self.large_preproc.append_triples(triples);
        }

        fn triples_len(&self) -> usize {
            self.large_preproc.triples_len()
        }
    }

    impl<Z, S, D> RandomPreprocessing<Z> for HonestLargePreprocessing<Z, S, D>
    where
        Z: Ring + ErrorCorrect + Derive,
        S: SingleSharing<Z>,
        D: DoubleSharing<Z>,
    {
        fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
            self.large_preproc.next_random_vec(amount)
        }

        fn append_randoms(&mut self, randoms: Vec<Share<Z>>) {
            self.large_preproc.append_randoms(randoms);
        }

        fn randoms_len(&self) -> usize {
            self.large_preproc.randoms_len()
        }
    }

    impl<Z, S, D> BasePreprocessing<Z> for HonestLargePreprocessing<Z, S, D>
    where
        Z: Ring + ErrorCorrect + Derive,
        S: SingleSharing<Z> + Sync,
        D: DoubleSharing<Z> + Sync,
    {
    }

    // Rounds (happy path)
    // init single sharing
    //         share dispute = 1 round
    //         pads =  1 round
    //         coinflip = vss + open = (1 + 3 + threshold) + 1
    //         verify = m reliable_broadcast = m*(3 + t) rounds
    // init double sharing
    //         same as single sharing above (single and double sharings are batched)
    //  triple batch - have been precomputed, just one open = 1 round
    //  random batch - have been precomputed = 0 rounds
    // = 2 * (1 + 1 + (1 + 3 + threshold) + 1 + m*(3 + threshold)) + 1
    // Note: 3 batches, so above rounds times 3
    // m = 20 for extension degree 4
    #[rstest]
    #[case(TestingParameters::init_honest(5, 1, Some(3 * 177)))]
    #[case(TestingParameters::init_honest(9, 2, Some(3 * 219)))]
    fn test_large_offline_z128(#[case] params: TestingParameters) {
        let malicious_offline = HonestLargePreprocessing::<
            ResiduePolyF4Z128,
            TrueSingleSharing<ResiduePolyF4Z128>,
            TrueDoubleSharing<ResiduePolyF4Z128>,
        >::default();

        test_offline_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
            _,
            _,
        >(params, malicious_offline);
    }

    // Rounds: same as for z128, see above
    #[rstest]
    #[case(TestingParameters::init_honest(5, 1, Some(3 * 177)))]
    #[case(TestingParameters::init_honest(9, 2, Some(3 * 219)))]
    fn test_large_offline_z64(#[case] params: TestingParameters) {
        let malicious_offline = HonestLargePreprocessing::<
            ResiduePolyF4Z64,
            TrueSingleSharing<ResiduePolyF4Z64>,
            TrueDoubleSharing<ResiduePolyF4Z64>,
        >::default();

        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _, _, _>(
            params,
            malicious_offline,
        );
    }

    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(5,1,&[2],&[0,3],&[],true,None),
            )]
        params: TestingParameters,
        #[values(
                DroppingVssFromStart::default(),
                DroppingVssAfterR1::default(),
                MaliciousVssR1::init(&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                DroppingCoinflipAfterVss::init(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::init(&params.roles_to_lie_to)

            )]
        _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                )
            )]
        ldl_strategy: LDL,
    ) {
        let ssh = create_real_single_sharing::<ResiduePolyF4Z64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _, _, _>(
            params.clone(),
            malicious_offline,
        );

        let ssh = create_real_single_sharing::<ResiduePolyF4Z128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
            _,
            _,
        >(params.clone(), malicious_offline);
    }

    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught_bis<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(5,1,&[2],&[0,3],&[],true,None),
            )]
        params: TestingParameters,
        #[values(RealVss::default())] _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                DroppingCoinflipAfterVss::init(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::init(&params.roles_to_lie_to)
            )]
        _share_dispute_strategy: S,
        #[values(
                MaliciousSenderLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                MaliciousSenderLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        let ssh = create_real_single_sharing::<ResiduePolyF4Z64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _, _, _>(
            params.clone(),
            malicious_offline,
        );

        let ssh = create_real_single_sharing::<ResiduePolyF4Z128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
            _,
            _,
        >(params.clone(), malicious_offline);
    }

    #[rstest]
    fn test_large_offline_malicious_subprotocols_not_caught<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(5,1,&[2],&[0],&[],false,None),
            )]
        params: TestingParameters,
        #[values(
                RealVss::default(),
                DroppingVssAfterR2::default(),
                MaliciousVssR1::init(&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                MaliciousCoinflipRecons::init(_vss_strategy.clone()),
            )]
        _coinflip_strategy: C,
        #[values(RealShareDispute::default())] _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                ),
                MaliciousReceiverLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                ),
                MaliciousReceiverLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        let ssh = create_real_single_sharing::<ResiduePolyF4Z64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = CheatingLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            ..Default::default()
        };
        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _, _, _>(
            params.clone(),
            malicious_offline,
        );

        let ssh = create_real_single_sharing::<ResiduePolyF4Z128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = CheatingLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            ..Default::default()
        };
        test_offline_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
            _,
            _,
        >(params.clone(), malicious_offline);
    }

    // Test what happens when no more triples are present
    #[test]
    fn test_no_more_elements() {
        let parties = 5;
        let threshold = 1;

        const TRIPLE_BATCH_SIZE: usize = 10_usize;
        const RANDOM_BATCH_SIZE: usize = 10_usize;

        async fn task(
            mut session: LargeSession,
        ) -> (
            LargeSession,
            Vec<Triple<ResiduePolyF4Z128>>,
            Vec<Share<ResiduePolyF4Z128>>,
        ) {
            let mut preproc = LargePreprocessing::<
                ResiduePolyF4Z128,
                TrueSingleSharing<ResiduePolyF4Z128>,
                TrueDoubleSharing<ResiduePolyF4Z128>,
            >::init(
                &mut session,
                BatchParams {
                    triples: TRIPLE_BATCH_SIZE,
                    randoms: RANDOM_BATCH_SIZE,
                },
                TrueSingleSharing::default(),
                TrueDoubleSharing::default(),
            )
            .await
            .unwrap();
            let mut triple_res = preproc.next_triple_vec(TRIPLE_BATCH_SIZE - 1).unwrap();
            triple_res.push(preproc.next_triple().unwrap());
            let mut rand_res = preproc.next_random_vec(RANDOM_BATCH_SIZE - 1).unwrap();
            rand_res.push(preproc.next_random().unwrap());
            // We have now used the entire batch of values and should thus fail
            assert!(preproc.next_triple().is_err());
            let err = preproc.next_triple().unwrap_err().to_string();
            assert!(err.contains("Not enough triples to pop 1"));
            let err = preproc.next_random().unwrap_err().to_string();
            assert!(err.contains("Not enough randomness to pop 1"));
            (session, triple_res, rand_res)
        }

        //Preprocessing assumes Sync network
        let result = execute_protocol_large::<
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(parties, threshold, None, NetworkMode::Sync, None, &mut task);

        for (_session, res_trip, res_rand) in result.iter() {
            assert_eq!(res_trip.len(), TRIPLE_BATCH_SIZE);
            assert_eq!(res_rand.len(), RANDOM_BATCH_SIZE);
        }
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught_9p<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(9,2,&[1,4],&[0,2,5,6],&[],true,None)
            )]
        params: TestingParameters,
        #[values(
                DroppingVssFromStart::default(),
                DroppingVssAfterR1::default(),
                MaliciousVssR1::init(&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                DroppingCoinflipAfterVss::init(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::init(&params.roles_to_lie_to)

            )]
        _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                )
            )]
        ldl_strategy: LDL,
    ) {
        let ssh = create_real_single_sharing::<ResiduePolyF4Z64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _, _, _>(
            params.clone(),
            malicious_offline,
        );

        let ssh = create_real_single_sharing::<ResiduePolyF4Z128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
            _,
            _,
        >(params.clone(), malicious_offline);
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_large_offline_malicious_subprotocols_caught_bis_9p<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(9,2,&[1,4],&[0,2,5,6],&[],true,None)
            )]
        params: TestingParameters,
        #[values(RealVss::default())] _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                DroppingCoinflipAfterVss::init(_vss_strategy.clone())
            )]
        _coinflip_strategy: C,
        #[values(
                RealShareDispute::default(),
                DroppingShareDispute::default(),
                WrongShareDisputeRecons::default(),
                MaliciousShareDisputeRecons::init(&params.roles_to_lie_to)
            )]
        _share_dispute_strategy: S,
        #[values(
                MaliciousSenderLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                MaliciousSenderLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        let ssh = create_real_single_sharing::<ResiduePolyF4Z64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _, _, _>(
            params.clone(),
            malicious_offline,
        );

        let ssh = create_real_single_sharing::<ResiduePolyF4Z128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = HonestLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            large_preproc: LargePreprocessing::default(),
        };
        test_offline_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
            _,
            _,
        >(params.clone(), malicious_offline);
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    fn test_large_offline_malicious_subprotocols_not_caught_9p<
        V: Vss,
        C: Coinflip,
        S: ShareDispute,
        LSL: LocalSingleShare + 'static,
        LDL: LocalDoubleShare + 'static,
    >(
        #[values(
                TestingParameters::init(9,2,&[1,4],&[0,2],&[],false,None)
            )]
        params: TestingParameters,
        #[values(
                RealVss::default(),
                DroppingVssAfterR2::default(),
                MaliciousVssR1::init(&params.roles_to_lie_to)
            )]
        _vss_strategy: V,
        #[values(
                RealCoinflip::init(_vss_strategy.clone()),
                MaliciousCoinflipRecons::init(_vss_strategy.clone()),
            )]
        _coinflip_strategy: C,
        #[values(RealShareDispute::default())] _share_dispute_strategy: S,
        #[values(
                RealLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                ),
                MaliciousReceiverLocalSingleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        lsl_strategy: LSL,
        #[values(
                RealLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone()
                ),
                MaliciousReceiverLocalDoubleShare::init(
                    _coinflip_strategy.clone(),
                    _share_dispute_strategy.clone(),
                    &params.roles_to_lie_to
                )
            )]
        ldl_strategy: LDL,
    ) {
        let ssh = create_real_single_sharing::<ResiduePolyF4Z64, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = CheatingLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            ..Default::default()
        };
        test_offline_strategies::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _, _, _>(
            params.clone(),
            malicious_offline,
        );

        let ssh = create_real_single_sharing::<ResiduePolyF4Z128, _>(lsl_strategy.clone());
        let dsh = create_real_double_sharing(ldl_strategy.clone());
        let malicious_offline = CheatingLargePreprocessing {
            single_sharing_handle: ssh,
            double_sharing_handle: dsh,
            ..Default::default()
        };
        test_offline_strategies::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
            _,
            _,
            _,
        >(params.clone(), malicious_offline);
    }
}
