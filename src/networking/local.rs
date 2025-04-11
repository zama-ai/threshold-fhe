use crate::error::error_handler::anyhow_error_and_log;

use super::constants::NETWORK_TIMEOUT;
use super::*;
use constants::NETWORK_TIMEOUT_ASYNC;
use constants::NETWORK_TIMEOUT_BK;
use constants::NETWORK_TIMEOUT_BK_SNS;
use dashmap::DashMap;
use std::cmp::min;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::Duration;

/// A simple implementation of networking for local execution.
///
/// This implementation is intended for local development/testing purposes
/// only. It simply stores all values in a hashmap without any actual networking.
//This is using mutexes for everything round related to be able to
//mutate state without needing self to be mutable in functions' signature
pub struct LocalNetworking {
    current_network_timeout: Mutex<Duration>,
    next_network_timeout: Mutex<Duration>,
    max_elapsed_time: Mutex<Duration>,
    pairwise_channels: SimulatedPairwiseChannels,
    pub owner: Identity,
    pub send_counter: DashMap<Identity, usize>,
    pub network_round: Arc<Mutex<usize>>,
    already_sent: Arc<Mutex<HashSet<(Identity, usize)>>>,
    pub init_time: OnceLock<Instant>,
    network_mode: NetworkMode,
    //If set, the party will sleep for the given duration at the start of each round
    delayed_party: Option<Duration>,
}

impl Default for LocalNetworking {
    fn default() -> Self {
        Self {
            current_network_timeout: Mutex::new(*NETWORK_TIMEOUT),
            next_network_timeout: Mutex::new(*NETWORK_TIMEOUT),
            max_elapsed_time: Mutex::new(Duration::ZERO),
            pairwise_channels: Default::default(),
            owner: Default::default(),
            send_counter: Default::default(),
            network_round: Default::default(),
            already_sent: Default::default(),
            init_time: OnceLock::new(), // init_time will be initialized on first access
            network_mode: NetworkMode::Sync,
            delayed_party: None,
        }
    }
}

#[derive(Default)]
pub struct LocalNetworkingProducer {
    pairwise_channels: SimulatedPairwiseChannels,
}

impl LocalNetworkingProducer {
    pub fn from_ids(identities: &[Identity]) -> Self {
        let pairwise_channels = DashMap::new();
        for v1 in identities.to_owned().iter() {
            for v2 in identities.to_owned().iter() {
                if v1 != v2 {
                    let (tx, rx) = unbounded_channel::<LocalTaggedValue>();
                    pairwise_channels.insert(
                        (v1.clone(), v2.clone()),
                        (Arc::new(tx), Arc::new(tokio::sync::Mutex::new(rx))),
                    );
                }
            }
        }
        LocalNetworkingProducer {
            pairwise_channels: Arc::new(pairwise_channels),
        }
    }
    pub fn user_net(
        &self,
        owner: Identity,
        network_mode: NetworkMode,
        delayed_party: Option<Duration>,
    ) -> LocalNetworking {
        // Async network means a timeout of 1 year
        let timeout = match network_mode {
            NetworkMode::Sync => *NETWORK_TIMEOUT,
            NetworkMode::Async => *NETWORK_TIMEOUT_ASYNC,
        };

        LocalNetworking {
            pairwise_channels: Arc::clone(&self.pairwise_channels),
            owner,
            network_mode,
            current_network_timeout: Mutex::new(timeout),
            next_network_timeout: Mutex::new(timeout),
            delayed_party,
            ..Default::default()
        }
    }
}

impl LocalNetworking {
    pub fn from_identity(owner: Identity) -> Self {
        LocalNetworking {
            owner,
            ..Default::default()
        }
    }
    pub fn from_ids(owner: Identity, identities: &[Identity]) -> Self {
        let pairwise_channels = DashMap::new();
        for v1 in identities.to_owned().iter() {
            for v2 in identities.to_owned().iter() {
                if v1 != v2 {
                    let (tx, rx) = unbounded_channel::<LocalTaggedValue>();
                    pairwise_channels.insert(
                        (v1.clone(), v2.clone()),
                        (Arc::new(tx), Arc::new(tokio::sync::Mutex::new(rx))),
                    );
                }
            }
        }
        LocalNetworking {
            pairwise_channels: Arc::new(pairwise_channels),
            owner,
            ..Default::default()
        }
    }
}

type SimulatedPairwiseChannels = Arc<
    DashMap<
        (Identity, Identity),
        (
            Arc<UnboundedSender<LocalTaggedValue>>,
            Arc<tokio::sync::Mutex<UnboundedReceiver<LocalTaggedValue>>>,
        ),
    >,
>;

#[async_trait]
impl Networking for LocalNetworking {
    async fn send(&self, val: Vec<u8>, receiver: &Identity) -> anyhow::Result<(), anyhow::Error> {
        let (tx, _) = self
            .pairwise_channels
            .get(&(self.owner.clone(), receiver.clone()))
            .ok_or_else(|| {
                anyhow_error_and_log(format!(
                "Could not retrieve pairwise channels in receive call, owner: {:?}, receiver: {:?}.",
                self.owner, receiver
            ))
            })?
            .value()
            .clone();

        let net_round = {
            match self.network_round.lock() {
                Ok(net_round) => *net_round,
                _ => panic!(
                    "Another user of the {:?} mutex panicked",
                    self.network_round
                ),
            }
        };

        let tagged_value = LocalTaggedValue {
            send_counter: net_round,
            value: val,
        };

        match self.already_sent.lock() {
            Ok(mut already_sent) => {
                if already_sent.contains(&(receiver.clone(), net_round)) {
                    panic!(
                        "Trying to send to {} in round {} more than once !",
                        receiver, net_round
                    )
                } else {
                    already_sent.insert((receiver.clone(), net_round));
                }
            }
            _ => panic!(
                "Another user of the {:?} mutex panicked.",
                self.already_sent
            ),
        }

        tx.send(tagged_value).map_err(|e| e.into())
    }

    async fn receive(&self, sender: &Identity) -> anyhow::Result<Vec<u8>> {
        let (_, rx) = self
            .pairwise_channels
            .get(&(sender.clone(), self.owner.clone()))
            .ok_or_else(|| {
                anyhow_error_and_log(format!(
                "Could not retrieve pairwise channels in receive call, owner: {:?}, sender: {:?}",
                self.owner, sender
            ))
            })?
            .value()
            .clone();
        let mut rx = rx.lock().await;

        let mut tagged_value = rx
            .recv()
            .await
            .ok_or_else(|| anyhow_error_and_log("Trying to receive from a closed channel"))?;

        let network_round: usize = *self
            .network_round
            .lock()
            .map_err(|e| anyhow_error_and_log(format!("Locking error: {:?}", e)))?;

        while tagged_value.send_counter < network_round {
            tracing::debug!(
                "@ round {} - dropped value {:?} from round {}",
                network_round,
                tagged_value.value[..min(tagged_value.value.len(), 16)].to_vec(),
                tagged_value.send_counter
            );
            tagged_value = rx
                .recv()
                .await
                .ok_or_else(|| anyhow_error_and_log("Trying to receive from a closed channel"))?;
        }

        Ok(tagged_value.value)
    }

    fn increase_round_counter(&self) -> anyhow::Result<()> {
        if let Some(duration) = self.delayed_party {
            std::thread::sleep(duration);
        }
        //Locking all mutexes in same place
        //Update max_elapsed_time
        if let (
            Ok(mut max_elapsed_time),
            Ok(mut current_round_timeout),
            Ok(next_round_timeout),
            Ok(mut net_round),
        ) = (
            self.max_elapsed_time.lock(),
            self.current_network_timeout.lock(),
            self.next_network_timeout.lock(),
            self.network_round.lock(),
        ) {
            *max_elapsed_time += *current_round_timeout;

            //Update next round timeout
            *current_round_timeout = *next_round_timeout;

            //Update round counter
            *net_round += 1;
            tracing::debug!(
                "changed network round to: {:?} on party: {:?}, with timeout: {:?}",
                *net_round,
                self.owner,
                *current_round_timeout
            );
        } else {
            return Err(anyhow_error_and_log("Couldn't lock mutex"));
        }
        Ok(())
    }

    fn get_timeout_current_round(&self) -> anyhow::Result<Instant> {
        // initialize init_time on first access
        // this avoids running into timeouts when large computations happen after the test runtime is set up and before the first message is received.
        let init_time = self.init_time.get_or_init(Instant::now);

        if let (Ok(max_elapsed_time), Ok(network_timeout)) = (
            self.max_elapsed_time.lock(),
            self.current_network_timeout.lock(),
        ) {
            Ok(*init_time + *network_timeout + *max_elapsed_time)
        } else {
            Err(anyhow_error_and_log("Couldn't lock mutex"))
        }
    }

    fn get_current_round(&self) -> anyhow::Result<usize> {
        if let Ok(net_round) = self.network_round.lock() {
            Ok(*net_round)
        } else {
            Err(anyhow_error_and_log("Couldn't lock network round mutex"))
        }
    }

    fn set_timeout_for_next_round(&self, timeout: Duration) -> anyhow::Result<()> {
        match self.get_network_mode() {
            NetworkMode::Sync => {
                if let Ok(mut next_network_timeout) = self.next_network_timeout.lock() {
                    *next_network_timeout = timeout;
                } else {
                    return Err(anyhow_error_and_log("Couldn't lock mutex"));
                }
            }
            NetworkMode::Async => {
                tracing::warn!(
                    "Trying to change network timeout with async network, doesn't do anything"
                );
            }
        }
        Ok(())
    }

    fn set_timeout_for_bk(&self) -> anyhow::Result<()> {
        self.set_timeout_for_next_round(*NETWORK_TIMEOUT_BK)
    }

    fn set_timeout_for_bk_sns(&self) -> anyhow::Result<()> {
        self.set_timeout_for_next_round(*NETWORK_TIMEOUT_BK_SNS)
    }

    fn get_network_mode(&self) -> NetworkMode {
        self.network_mode
    }

    #[cfg(feature = "choreographer")]
    fn get_num_byte_sent(&self) -> anyhow::Result<usize> {
        Ok(0)
    }

    #[cfg(feature = "choreographer")]
    fn get_num_byte_received(&self) -> anyhow::Result<usize> {
        Ok(0)
    }
}

#[derive(Debug, Clone)]
struct LocalTaggedValue {
    value: Vec<u8>,
    send_counter: usize,
}

#[cfg(test)]
mod tests {

    use crate::networking::value::NetworkValue;

    use super::*;
    use std::num::Wrapping;

    #[tokio::test]
    async fn test_sync_networking() {
        let identities: Vec<Identity> = vec!["alice".into(), "bob".into()];
        let net_producer = LocalNetworkingProducer::from_ids(&identities);

        let net_alice = net_producer.user_net("alice".into(), NetworkMode::Sync, None);
        let net_bob = net_producer.user_net("bob".into(), NetworkMode::Sync, None);

        let task1 = tokio::spawn(async move {
            let recv = net_bob.receive(&"alice".into()).await;
            assert_eq!(
                bincode::serialize(&NetworkValue::<Wrapping::<u64>>::from_network(recv).unwrap())
                    .unwrap(),
                bincode::serialize(&NetworkValue::RingValue(Wrapping::<u64>(1234))).unwrap()
            );
        });

        let task2 = tokio::spawn(async move {
            let value = NetworkValue::RingValue(Wrapping::<u64>(1234));
            net_alice.send(value.to_network(), &"bob".into()).await
        });

        let _ = tokio::try_join!(task1, task2).unwrap();
    }
    #[tokio::test]
    #[should_panic = "Trying to send to bob in round 0 more than once !"]
    async fn test_sync_networking_panic() {
        let identities: Vec<Identity> = vec!["alice".into(), "bob".into()];
        let net_producer = LocalNetworkingProducer::from_ids(&identities);

        let net_alice = net_producer.user_net("alice".into(), NetworkMode::Sync, None);

        let value = NetworkValue::RingValue(Wrapping::<u64>(1234));
        let _ = net_alice
            .send(value.clone().to_network(), &"bob".into())
            .await;
        let _ = net_alice.send(value.to_network(), &"bob".into()).await;
    }
}
