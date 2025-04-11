//! Choreographer is a GRPC client that communicates with
//! the kms-core (with the moby binary) parties to do benchmarks.
//! It is a trusted entity and should not be used with production kms-core.
use crate::choreography::grpc::gen::{
    CrsGenRequest, CrsGenResultRequest, PreprocDecryptRequest, ThresholdDecryptRequest,
    ThresholdKeyGenResultRequest,
};
use crate::choreography::requests::CrsGenParams;
use crate::conf::choreo::ChoreoConf;
use crate::execution::endpoints::decryption::DecryptionMode;
use crate::execution::endpoints::keygen::FhePubKeySet;
use crate::execution::runtime::party::RoleAssignment;
use crate::execution::tfhe_internals::parameters::{Ciphertext64, DkgParamsAvailable};
use crate::execution::zk::ceremony::compute_witness_dim;
use crate::{
    algebra::base_ring::Z64,
    choreography::grpc::gen::choreography_client::ChoreographyClient,
    execution::{
        runtime::party::{Identity, Role},
        zk::ceremony::InternalPublicParameter,
    },
    networking::constants::{MAX_EN_DECODE_MESSAGE_SIZE, NETWORK_TIMEOUT_LONG},
    session_id::SessionId,
};
use conf_trace::telemetry::ContextPropagator;
use std::collections::HashMap;
use tokio::{task::JoinSet, time::Duration};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Uri};
use tracing::{instrument, Instrument};

use super::grpc::gen::{
    PreprocKeyGenRequest, PrssInitRequest, StatusCheckRequest, ThresholdDecryptResultRequest,
    ThresholdKeyGenRequest,
};
use super::grpc::SupportedRing;
use super::requests::{
    PreprocDecryptParams, PreprocKeyGenParams, PrssInitParams, SessionType, Status, TfheType,
    ThresholdDecryptParams, ThresholdKeyGenParams, ThresholdKeyGenResultParams, ThroughtputParams,
};

pub struct ChoreoRuntime {
    pub role_assignments: HashMap<Role, Identity>,
    pub channels: HashMap<Role, Channel>,
}

#[derive(Debug)]
pub struct GrpcOutputs {
    pub outputs: HashMap<String, Z64>,
    pub elapsed_times: Option<HashMap<Role, Vec<Duration>>>,
}

pub type NetworkTopology = HashMap<Role, Uri>;

impl ChoreoRuntime {
    pub fn new_from_conf(conf: &ChoreoConf) -> Result<ChoreoRuntime, Box<dyn std::error::Error>> {
        let topology = &conf.threshold_topology;

        let role_assignments: RoleAssignment = topology.into();

        // we need to set the protocol in URI correctly
        // depending on whether the certificates are present
        let host_channels = topology.choreo_physical_topology_into_network_topology()?;

        ChoreoRuntime::new_with_net_topology(role_assignments, host_channels)
    }

    fn new_with_net_topology(
        role_assignments: HashMap<Role, Identity>,
        network_topology: NetworkTopology,
    ) -> Result<ChoreoRuntime, Box<dyn std::error::Error>> {
        let channels = network_topology
            .iter()
            .map(|(role, host)| {
                let endpoint: &Uri = host;
                tracing::debug!("connecting to endpoint: {:?}", endpoint);
                let channel = Channel::builder(endpoint.clone())
                    .timeout(*NETWORK_TIMEOUT_LONG)
                    .connect_lazy();
                Ok((*role, channel))
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?;

        Ok(ChoreoRuntime {
            role_assignments,
            channels,
        })
    }

    pub fn new_client(
        &self,
        channel: Channel,
    ) -> ChoreographyClient<InterceptedService<Channel, ContextPropagator>> {
        ChoreographyClient::with_interceptor(channel, ContextPropagator)
            .max_decoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
            .max_encoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
    }

    #[instrument(name = "PRSS-INIT Request", skip(self, session_id), fields(sid = ?session_id))]
    pub async fn inititate_prss_init(
        &self,
        session_id: SessionId,
        ring: SupportedRing,
        threshold: u32,
        seed: Option<u64>,
    ) -> anyhow::Result<()> {
        let role_assignment = bincode::serialize(&self.role_assignments)?;

        let prss_params = bincode::serialize(&PrssInitParams { session_id, ring })?;

        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());

            let request = PrssInitRequest {
                role_assignment: role_assignment.to_vec(),
                threshold,
                params: prss_params.to_vec(),
                seed,
            };

            join_set.spawn(
                async move { client.prss_init(request).await }.instrument(tracing::Span::current()),
            );
        });
        while let Some(response) = join_set.join_next().await {
            response??;
        }

        Ok(())
    }

    #[instrument(name = "DKG-Preproc Request", skip(self,session_id), fields(sid = ?session_id))]
    pub async fn initiate_preproc_keygen(
        &self,
        session_id: SessionId,
        session_type: SessionType,
        dkg_params: DkgParamsAvailable,
        num_sessions: u32,
        percentage_offline: u32,
        threshold: u32,
        seed: Option<u64>,
    ) -> anyhow::Result<SessionId> {
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let preproc_kg_params = bincode::serialize(&PreprocKeyGenParams {
            session_type,
            session_id,
            percentage_offline,
            dkg_params: dkg_params.to_param(),
            num_sessions,
        })?;

        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = PreprocKeyGenRequest {
                role_assignment: role_assignment.to_vec(),
                threshold,
                params: preproc_kg_params.to_vec(),
                seed,
            };

            join_set.spawn(
                async move { client.preproc_key_gen(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses: Vec<SessionId> = Vec::new();
        while let Some(response) = join_set.join_next().await {
            responses.push(bincode::deserialize(&(response??.into_inner().request_id)).unwrap());
        }

        let ref_response = responses.first().unwrap();
        for response in responses.iter() {
            assert_eq!(response, ref_response);
        }

        Ok(*ref_response)
    }

    #[instrument(name = "DKG Request", skip(self,session_id, session_id_preproc), fields(sid = ?session_id, preproc_sid = ?session_id_preproc))]
    pub async fn initiate_threshold_keygen(
        &self,
        session_id: SessionId,
        dkg_params: DkgParamsAvailable,
        session_id_preproc: Option<SessionId>,
        threshold: u32,
        seed: Option<u64>,
    ) -> anyhow::Result<SessionId> {
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let threshold_keygen_params = bincode::serialize(&ThresholdKeyGenParams {
            session_id,
            dkg_params: dkg_params.to_param(),
            session_id_preproc,
        })?;

        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = ThresholdKeyGenRequest {
                role_assignment: role_assignment.to_vec(),
                threshold,
                params: threshold_keygen_params.to_vec(),
                seed,
            };

            join_set.spawn(
                async move { client.threshold_key_gen(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses: Vec<SessionId> = Vec::new();
        while let Some(response) = join_set.join_next().await {
            responses.push(bincode::deserialize(&(response??.into_inner().request_id)).unwrap());
        }

        let ref_response = responses.first().unwrap();
        for response in responses.iter() {
            assert_eq!(response, ref_response);
        }

        Ok(*ref_response)
    }

    ///NOTE: If dkg_params.is_some(), we will actually generate a new set of keys and stored it under session_id,
    ///otherwise we try and retrieve existing keys
    #[instrument(name = "DKG-Result Request", skip(self, session_id), fields(sid = ?session_id))]
    pub async fn initiate_threshold_keygen_result(
        &self,
        session_id: SessionId,
        dkg_params: Option<DkgParamsAvailable>,
        seed: Option<u64>,
    ) -> anyhow::Result<FhePubKeySet> {
        let role_assignment = bincode::serialize(&self.role_assignments)?;

        let threshold_keygen_result_params = bincode::serialize(&ThresholdKeyGenResultParams {
            session_id,
            dkg_params: dkg_params.map_or_else(|| None, |v| Some(v.to_param())),
        })?;

        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = ThresholdKeyGenResultRequest {
                role_assignment: role_assignment.to_vec(),
                params: threshold_keygen_result_params.to_vec(),
                seed,
            };
            join_set.spawn(
                async move { client.threshold_key_gen_result(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses = Vec::new();
        while let Some(response) = join_set.join_next().await {
            let response = response??.into_inner();
            responses.push(response.pub_keyset);
        }

        //NOTE: Cant really assert here as keys dont implement eq trait, and cant assert eq on serialized data
        //let ref_response = responses.first().unwrap();
        //for response in responses.iter() {
        //    assert_eq!(response, ref_response);
        //}
        let pub_key = responses.pop().unwrap();
        let pub_key = bincode::deserialize(&pub_key)?;
        Ok(pub_key)
    }

    #[instrument(name = "DDec-Preproc Request", skip(self,session_id), fields(num_ctxts=?num_ctxts, ctxt_type=?ctxt_type, sid = ?session_id))]
    pub async fn initiate_preproc_decrypt(
        &self,
        session_id: SessionId,
        key_sid: SessionId,
        decryption_mode: DecryptionMode,
        num_ctxts: u128,
        ctxt_type: TfheType,
        threshold: u32,
        seed: Option<u64>,
    ) -> anyhow::Result<SessionId> {
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let preproc_decrypt_params = bincode::serialize(&PreprocDecryptParams {
            session_id,
            key_sid,
            decryption_mode,
            num_ctxts,
            ctxt_type,
        })?;

        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = PreprocDecryptRequest {
                role_assignment: role_assignment.to_vec(),
                threshold,
                params: preproc_decrypt_params.to_vec(),
                seed,
            };

            join_set.spawn(
                async move { client.preproc_decrypt(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses: Vec<SessionId> = Vec::new();
        while let Some(response) = join_set.join_next().await {
            responses.push(bincode::deserialize(&(response??.into_inner().request_id)).unwrap());
        }

        let ref_response = responses.first().unwrap();
        for response in responses.iter() {
            assert_eq!(ref_response, response)
        }

        Ok(*ref_response)
    }

    #[instrument(name = "DDec Request", skip(self, session_id, ctxts), fields(num_ctxts = ?ctxts.len(), ctxt_type=?tfhe_type, sid = ?session_id))]
    #[allow(clippy::too_many_arguments)]
    pub async fn initiate_threshold_decrypt(
        &self,
        session_id: SessionId,
        key_sid: SessionId,
        decryption_mode: DecryptionMode,
        preproc_sid: Option<SessionId>,
        ctxts: Vec<Ciphertext64>,
        throughput: Option<ThroughtputParams>,
        tfhe_type: TfheType,
        threshold: u32,
        seed: Option<u64>,
    ) -> anyhow::Result<SessionId> {
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let threshold_decrypt_params = bincode::serialize(&ThresholdDecryptParams {
            session_id,
            decryption_mode,
            key_sid,
            preproc_sid,
            throughput,
            ctxts,
            tfhe_type,
        })?;

        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = ThresholdDecryptRequest {
                role_assignment: role_assignment.to_vec(),
                threshold,
                params: threshold_decrypt_params.to_vec(),
                seed,
            };

            join_set.spawn(
                async move { client.threshold_decrypt(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses: Vec<SessionId> = Vec::new();
        while let Some(response) = join_set.join_next().await {
            responses.push(bincode::deserialize(&(response??.into_inner().request_id)).unwrap());
        }

        let ref_response = responses.first().unwrap();
        for response in responses.iter() {
            assert_eq!(ref_response, response)
        }

        Ok(*ref_response)
    }

    #[instrument(name = "DDec-Result Request", skip(self,session_id),fields(sid = ?session_id))]
    pub async fn initiate_threshold_decrypt_result(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<Vec<Z64>> {
        let mut join_set = JoinSet::new();
        let serialized_sid = bincode::serialize(&session_id)?;
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = ThresholdDecryptResultRequest {
                request_id: serialized_sid.to_vec(),
            };

            join_set.spawn(
                async move { client.threshold_decrypt_result(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses: Vec<Vec<Z64>> = Vec::new();
        while let Some(response) = join_set.join_next().await {
            responses.push(bincode::deserialize(&(response??.into_inner().plaintext))?);
        }

        let ref_response = responses.first().unwrap();
        for response in responses.iter() {
            assert_eq!(ref_response, response)
        }

        Ok(ref_response.clone())
    }

    #[instrument(name = "CRS-Gen Request", skip(self, session_id), fields(sid = ?session_id))]
    pub async fn initiate_crs_gen(
        &self,
        session_id: SessionId,
        dkg_params: DkgParamsAvailable,
        threshold: u32,
        seed: Option<u64>,
    ) -> anyhow::Result<SessionId> {
        let role_assignment = bincode::serialize(&self.role_assignments)?;
        let witness_dim = compute_witness_dim(
            &dkg_params
                .to_param()
                .get_params_basics_handle()
                .get_compact_pk_enc_params(),
            None,
        )? as u128;
        let crs_gen_params = bincode::serialize(&CrsGenParams {
            session_id,
            witness_dim,
        })?;

        let mut join_set = JoinSet::new();

        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = CrsGenRequest {
                role_assignment: role_assignment.to_vec(),
                threshold,
                params: crs_gen_params.to_vec(),
                max_num_bits: None,
                seed,
            };

            join_set.spawn(
                async move { client.crs_gen(request).await }.instrument(tracing::Span::current()),
            );
        });

        let mut responses: Vec<SessionId> = Vec::new();
        while let Some(response) = join_set.join_next().await {
            responses.push(bincode::deserialize(&(response??.into_inner().request_id)).unwrap());
        }

        let ref_response = responses.first().unwrap();
        for response in responses.iter() {
            assert_eq!(ref_response, response)
        }

        Ok(*ref_response)
    }

    #[instrument(name = "CRS-Result Request", skip(self,session_id),fields(sid = ?session_id))]
    pub async fn initiate_crs_gen_result(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<InternalPublicParameter> {
        let serialized_sid = bincode::serialize(&session_id)?;
        let mut join_set = JoinSet::new();
        self.channels.values().for_each(|channel| {
            let mut client = self.new_client(channel.clone());
            let request = CrsGenResultRequest {
                request_id: serialized_sid.to_vec(),
            };

            join_set.spawn(
                async move { client.crs_gen_result(request).await }
                    .instrument(tracing::Span::current()),
            );
        });

        let mut responses: Vec<InternalPublicParameter> = Vec::new();
        while let Some(response) = join_set.join_next().await {
            responses.push(bincode::deserialize(&(response??.into_inner()).crs).unwrap());
        }

        let ref_response = responses.first().unwrap();
        for response in responses.iter() {
            assert_eq!(ref_response, response)
        }
        Ok(ref_response.clone())
    }

    pub async fn initiate_status_check(
        &self,
        session_id: SessionId,
        retry: bool,
        interval: Duration,
    ) -> anyhow::Result<Vec<(Role, Status)>> {
        let mut join_set = JoinSet::new();
        let serialized_sid = bincode::serialize(&session_id)?;
        let request = StatusCheckRequest {
            request_id: serialized_sid,
        };
        let mut result = Vec::new();
        loop {
            self.channels.iter().for_each(|(role, channel)| {
                let mut client = self.new_client(channel.clone());

                let request = request.clone();
                let role = *role;
                join_set.spawn(async move { (role, client.status_check(request).await) });
            });

            while let Some(response) = join_set.join_next().await {
                let (role, response) = response?;
                let status: Status = bincode::deserialize(&response?.into_inner().status)?;
                result.push((role, status));
            }

            if !retry || result.iter().all(|(_, status)| *status != Status::Ongoing) {
                return Ok(result);
            } else {
                println!("Status Check for Session ID {session_id} -- Still have running parties");
                result.sort_by_key(|(role, _)| role.one_based());
                for (role, status) in result.drain(..) {
                    println!("Role {role}, Status {:?}", status);
                }
                tokio::time::sleep(interval).await;
            }
        }
    }
}
