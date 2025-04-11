use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::runtime::{party::Role, session::BaseSessionHandles},
    networking::value::NetworkValue,
};
use rand::{CryptoRng, Rng};
use std::{collections::HashMap, sync::Arc};
use tokio::{task::JoinSet, time::timeout_at};

use super::{shamir::ShamirSharings, share::Share};
use crate::algebra::structure_traits::Ring;
use crate::execution::sharing::shamir::InputOp;

pub async fn robust_input<Z, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &mut S,
    value: &Option<Vec<Z>>,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<Vec<Share<Z>>>
where
    Z: Ring,
    ShamirSharings<Z>: InputOp<Z>,
{
    session.network().increase_round_counter()?;
    if role.one_based() == input_party_id {
        let threshold = session.threshold();
        let sis = {
            match value {
                Some(v) => v.clone(),
                None => {
                    return Err(anyhow_error_and_log(
                        "Expected Some(v) as an input argument for the input party, got None"
                            .to_string(),
                    ))
                }
            }
        };
        let num_parties = session.num_parties();

        let mut share_map = HashMap::new();
        let mut output = Vec::new();
        for si in sis.into_iter() {
            let shares = ShamirSharings::share(session.rng(), si, num_parties, threshold as usize)?;
            for share in shares.shares {
                share_map
                    .entry(share.owner())
                    .and_modify(|entry: &mut Vec<Z>| entry.push(share.value()))
                    .or_insert(vec![share.value()]);
            }
        }

        let mut set = JoinSet::new();
        for (to_send_role, to_send) in share_map.into_iter() {
            if to_send_role == *role {
                output = to_send.into_iter().map(|v| Share::new(*role, v)).collect();
                continue;
            }
            let receiver = session.identity_from(&to_send_role)?;

            let networking = Arc::clone(session.network());
            set.spawn(async move {
                let _ = networking
                    .send(NetworkValue::VecRingValue(to_send).to_network(), &receiver)
                    .await;
            });
        }
        while (set.join_next().await).is_some() {}
        Ok(output)
    } else {
        let sender = session.identity_from(&Role::indexed_by_one(input_party_id))?;

        let networking = Arc::clone(session.network());
        let data = tokio::spawn(timeout_at(
            session.network().get_timeout_current_round()?,
            async move { networking.receive(&sender).await },
        ))
        .await??;

        let data = match NetworkValue::from_network(data)? {
            NetworkValue::VecRingValue(rv) => rv,
            _ => Err(anyhow_error_and_log(
                "I have received sth different from a ring value!".to_string(),
            ))?,
        };

        Ok(data.into_iter().map(|v| Share::new(*role, v)).collect())
    }
}
