//! The sync module allows syncing private Stamp transactions between your devices or devices you
//! directly share with.
//!
//! The goal is to be able to share private information (not just Stamp identities, but anything
//! that can be shoved into a [`TransactionBody::ExtV1`][stamp_core::dag::TransactionBody]
//! transaction) such that untrusted intermediaries can forward information to the correct nodes
//! *without being able to read it*.
//!
//! The best practice here is to wrap your transactions in the `Transaction::ExtV1` container
//! (even if syncing an identity). The reason for this is it allows a generic way to encrypt the
//! payload -- which in the case of a Stamp identity you almost always want and in the case of
//! other p2p protocols you'd need to wrap it in an `ExtV1` transaction anyway -- and also attach
//! *public* metadata to the transaction that allows for generic routing (via the `ty` and
//! `context` fields of the Ext transaction). Payload encryption and metadata routing make it so an
//! untrusted third party can relay the transactions *without knowing their contents*.
//!
//! This uses a two-tiered sharing token: trusted nodes get the full token (which contains a key
//! allowing decryption) and untrusted nodes just get the ability to verify transactions and read
//! their metadata with no ability to decrypt.
//!
//! This is useful for syncing your private Stamp transactions between your devices, but also
//! allows more intimate interactions/direct sharing between participants *without* requiring an
//! always-on *trusted* node (aka, an attack surface).

use crate::{
    error::{Error, Result},
    util,
};
use futures::{prelude::*, select};
use rasn::{Encode, Decode, AsnType};
use stamp_core::{
    crypto::base::SignKeypairPublic,
    dag::{TransactionID, Transaction},
    identity::keychain::AdminKeypairPublic,
    util::BinaryVec,
};
use std::fmt;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error};


/// Describes a simple, recursive querying mechanism for grabbing transactions from peers.
#[derive(Debug, Clone, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum TransactionQuery {
    /// All conditions must match (AND)
    #[rasn(tag(explicit(0)))]
    All(Vec<TransactionQuery>),
    /// Any of the conditions can match (OR)
    #[rasn(tag(explicit(1)))]
    Any(Vec<TransactionQuery>),
    /// This condition cannot match (NOT).
    #[rasn(tag(explicit(2)))]
    Not(Box<TransactionQuery>),
    /// Query transactions by their `ExtV1.context` field
    #[rasn(tag(explicit(3)))]
    TransactionContext {
        #[rasn(tag(explicit(0)))]
        key: BinaryVec,
        #[rasn(tag(explicit(1)))]
        val: BinaryVec,
    },
    /// Grab a transaction by its ID
    #[rasn(tag(explicit(4)))]
    TransactionID(TransactionID),
    /// Grab a transaction by its `ExtV1.type` field
    #[rasn(tag(explicit(5)))]
    TransactionType(BinaryVec),
}

/// Send a command to the sync runner
#[derive(Debug)]
pub enum Command {
    /// Forwards a command to the core
    Forward(crate::core::Command),
    /// Ask peers for transactions
    QueryTransactions(TransactionQuery),
    /// Quit the loop
    Quit,
    /// Send a Stamp transaction. Generally, this should be an ExtV1 transaction with an encrypted
    /// `payload` that has both the `TransactionID` of the inner transaction and the channel we're
    /// operating on in the `context` field under `transaction_id` and `channel` fields
    /// restecpively.
    SendTransactions(Vec<Transaction>),
}

/// Sync events we might want to pay attention to
#[derive(Debug)]
pub enum Event {
    /// An error happened
    Error(Error),
    /// Sent out when it might be a good time to ask for transactions
    MaybeRequestTransactions,
    /// An incoming transaction query.
    QueryTransactions(TransactionQuery),
    /// Quit signal
    Quit,
    /// Let the listener know we've subscribed to our topic
    Subscribed { topic: String },
    /// Received some transactinos.
    ///
    /// Generally, this should be an ExtV1 transaction with an encrypted
    /// `payload` that has both the `TransactionID` of the inner transaction and the channel we're
    /// operating on in the `context` field under `transaction_id` and `channel` fields
    /// restecpively.
    Transactions(Vec<Transaction>),
    /// Let the listener know we've unsubscribed from our topic
    Unsubscribed { topic: String },
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(e) => write!(f, "Event::Error({})", e),
            Self::MaybeRequestTransactions => write!(f, "Event::MaybeRequestTransactions"),
            Self::QueryTransactions(qry) => {
                write!(f, "Event::QueryTransactions({:?})", qry)
            }
            Self::Quit => write!(f, "Event::Quit"),
            Self::Subscribed { topic } => write!(f, "Event::Subscribed({})", topic),
            Self::Transactions(transactions) => {
                write!(f, "Event::Transactions({} entries)", transactions.len())
            }
            Self::Unsubscribed { topic } => write!(f, "Event::Unsubscribed({})", topic),
        }
    }
}

/// This is a message sent between private sync nodes. Note that we never send
/// unencrypted identity transactions over the wire, and we don't deal with decryption
/// in this library. It's up to the [Event] listener to do the Right Thing with
/// whatever key they (don't) have.
#[derive(Debug, Clone, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum Message {
    /// Query a transaction set from our peers.
    #[rasn(tag(explicit(0)))]
    QueryTransactions(TransactionQuery),
    /// Send transactions out to the gossip group.
    #[rasn(tag(explicit(1)))]
    SendTransactions(Vec<Transaction>),
}

/// Wraps the raw core event/command pipeline to add stuff relevant to private
/// syncing.
#[tracing::instrument(skip(channel, sync_pubkey, core_incoming, core_outgoing, sync_incoming, sync_outgoing))]
pub async fn run(channel: &str, sync_pubkey: &SignKeypairPublic, core_incoming: Sender<crate::core::Command>, mut core_outgoing: Receiver<crate::core::Event>, mut sync_incoming: Receiver<Command>, sync_outgoing: Sender<Event>) -> Result<()> {
    // convert the signing pubkey into an admin key, which is the only type of key allowed to sign
    // transactions.
    let sync_pubkey_as_admin = AdminKeypairPublic::from(sync_pubkey.clone());
    let channel = String::from(channel);
    macro_rules! sender {
        ($sender:expr, $val:expr) => {
            match $sender.send($val).await {
                Err(e) => error!("stamp_net::sync::run() -- {:?}", e),
                _ => {}
            }
        }
    }
    let mut subscribed = false;
    let topic_name = format!("sync:private:{}", channel);
    loop {
        select! {
            cmd = sync_incoming.recv().fuse() => match cmd {
                Some(Command::Forward(core_cmd)) => {
                    sender! { core_incoming, core_cmd }
                }
                Some(Command::Quit) => {
                    sender! { core_incoming, crate::core::Command::Quit }
                }
                Some(Command::QueryTransactions(qry)) => {
                    match util::serialize(&Message::QueryTransactions(qry)) {
                        Ok(ser) => {
                            sender!{ core_incoming, crate::core::Command::TopicSend {
                                topic: topic_name.clone(),
                                message: ser,
                            } }
                        }
                        Err(e) => error!("Error serializing identity request: {}", e),
                    }
                }
                Some(Command::SendTransactions(transactions)) => {
                    let verified = transactions.into_iter()
                        .filter(|trans| trans.is_signed_by(&sync_pubkey_as_admin))
                        .map(|trans| trans.verify_hash_and_signatures().map(|_| trans))
                        .collect::<stamp_core::error::Result<Vec<_>>>();

                    match verified {
                        Ok(transactions) => {
                            match util::serialize(&Message::SendTransactions(transactions)) {
                                Ok(ser) => {
                                    sender!{ core_incoming, crate::core::Command::TopicSend {
                                        topic: topic_name.clone(),
                                        message: ser,
                                    } }
                                }
                                Err(e) => error!("Error serializing transaction message: {}", e),
                            }
                        }
                        Err(e) => error!("Failed to validate outgoing transactions: {}", e),
                    }
                }
                _ => {}
            },
            event = core_outgoing.recv().fuse() => match event {
                Some(crate::core::Event::DiscoveryReady) => {
                    sender!{ core_incoming, crate::core::Command::TopicSubscribe { topic: topic_name.clone() } }
                }
                Some(crate::core::Event::Error(e)) => {
                    sender!{ sync_outgoing, Event::Error(e) }
                }
                Some(crate::core::Event::GossipMessage { peer_id, topic, data }) => {
                    if topic == topic_name {
                        match util::deserialize::<Message>(&data) {
                            Ok(Message::SendTransactions(transactions)) => {
                                let verified = transactions.into_iter()
                                    .filter(|trans| trans.is_signed_by(&sync_pubkey_as_admin))
                                    .map(|trans| trans.verify_hash_and_signatures().map(|_| trans))
                                    .collect::<stamp_core::error::Result<Vec<_>>>();
                                match verified {
                                    Ok(transactions) => {
                                        sender!{ sync_outgoing, Event::Transactions(transactions) }
                                    }
                                    Err(e) => error!("Failed to verify transactions (channel {}): {}", topic_name, e),
                                }
                            }
                            Ok(Message::QueryTransactions(qry)) => {
                                sender!{ sync_outgoing, Event::QueryTransactions(qry) }
                            }
                            Err(e) => error!("Error deserializing message: {} (from {:?})", e, peer_id),
                        }
                    }
                }
                Some(crate::core::Event::GossipSubscribed { topic }) => {
                    if topic == topic_name {
                        subscribed = true;
                        sender!{ sync_outgoing, Event::Subscribed { topic } }
                        sender!{ sync_outgoing, Event::MaybeRequestTransactions }
                    }
                }
                Some(crate::core::Event::GossipUnsubscribed { topic }) => {
                    if topic == topic_name {
                        subscribed = false;
                        sender!{ sync_outgoing, Event::Unsubscribed { topic } }
                    }
                }
                Some(crate::core::Event::Pong) => {
                    if subscribed {
                        sender!{ sync_outgoing, Event::MaybeRequestTransactions }
                    }
                }
                Some(crate::core::Event::Quit) => {
                    sender!{ sync_outgoing, Event::Quit }
                    break;
                }
                _ => {}
            },
        }
    }
    Ok::<(), Error>(())
}

