mod reqres;

use chrono::Utc;
// NOTE: NResult is required because as of writing this, libp2p doesn't namespace the `Result`
// object in the swarm derive macro, so their Result conflicts with ours.
pub use crate::agent::reqres::{Request, Response, TransactionQuery};
use crate::{
    agent::reqres::ReqresBehavior,
    error::{Error, Result as NResult},
};
use futures::{prelude::*, select};
pub use libp2p::kad::Quorum;
use libp2p::{
    dcutr, identify, identity,
    kad::{self, store::RecordStore},
    multiaddr, noise, ping, relay, request_response,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use stamp_core::{
    crypto::base::{SecretKey, SignKeypair, SignKeypairPublic},
    dag::{Transaction, TransactionBody},
    identity::IdentityID,
    util::SerdeBinary,
};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

/// The max size a published identity can be. above this, we don't store it remotely. You have to
/// store it yourself.
const MAX_PUBLISHED_IDENTITY_SIZE: usize = 1024 * 1024 * 2;
const MAX_DHT_RECORD_SIZE: usize = 1024 * 1024 * 64;

#[derive(Debug)]
pub enum Event {
    DiscoveryReady,
    Error(Error),
    KadBootstrapped,
    Ping,
    RequestIncoming {
        request_id: Uuid,
        topic_name: String,
        query: TransactionQuery,
    },
    Quit,
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "StampEvent")]
pub struct StampBehavior {
    dcutr: Toggle<dcutr::Behaviour>,
    identify: identify::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    ping: ping::Behaviour,
    relay_client: Toggle<relay::client::Behaviour>,
    relay: Toggle<relay::Behaviour>,
    reqres: ReqresBehavior<Request, Response>,
}

#[derive(Debug)]
pub enum StampEvent {
    Dcutr(dcutr::Event),
    Identify(identify::Event),
    Kad(kad::Event),
    PeerList(Vec<PeerId>),
    Ping(ping::Event),
    Relay(relay::Event),
    RelayClient(relay::client::Event),
    ReqRes(request_response::Event<Request, Response>),
}

#[derive(Debug)]
enum CommandResult {
    Ok(Option<StampEvent>),
    Err(Error),
}

impl From<dcutr::Event> for StampEvent {
    fn from(event: dcutr::Event) -> Self {
        Self::Dcutr(event)
    }
}

impl From<identify::Event> for StampEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<kad::Event> for StampEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kad(event)
    }
}

impl From<ping::Event> for StampEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<relay::Event> for StampEvent {
    fn from(event: relay::Event) -> Self {
        Self::Relay(event)
    }
}

impl From<relay::client::Event> for StampEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::RelayClient(event)
    }
}

impl From<request_response::Event<Request, Response>> for StampEvent {
    fn from(event: request_response::Event<Request, Response>) -> Self {
        Self::ReqRes(event)
    }
}

/// Generate a new random peer key.
pub fn random_peer_key() -> identity::Keypair {
    identity::Keypair::generate_ed25519()
}

/// Allows matching requests and responses
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum RequestID {
    /// Used for tracking Kad queries
    Kad(kad::QueryId),
    /// Used for tracking commands
    Uuid(Uuid),
}

#[derive(Debug)]
enum Command {
    GetConnectedPeers,
    IdentityLookup(IdentityID),
    IdentityPublish {
        publish_transaction: Transaction,
        quorum: Quorum,
    },
    KadQueryProviders(String),
    KadStartProvide(String),
    KadStopProvide(String),
    Maintenance,
    Quit,
}

#[derive(Debug)]
struct CommandContainer {
    id: RequestID,
    ty: Command,
}

impl CommandContainer {
    pub fn new(id: RequestID, ty: Command) -> Self {
        Self { id, ty }
    }
}

fn validate_publish_transaction(publish_transaction: &Transaction) -> NResult<IdentityID> {
    match publish_transaction.entry().body() {
        TransactionBody::PublishV1 { transactions } => {
            let identity = transactions.build_identity()?;
            publish_transaction.verify(Some(&identity))?;
            Ok(identity.id().clone())
        }
        _ => Err(Error::IdentityInvalid),
    }
}

pub struct Agent {
    relay_mode: bool,
    swarm: Mutex<Swarm<StampBehavior>>,
    event_send: mpsc::Sender<Event>,
    request_tracker: Mutex<HashMap<RequestID, (i64, oneshot::Sender<CommandResult>)>>,
    cmd_send: mpsc::Sender<CommandContainer>,
    cmd_recv: Mutex<mpsc::Receiver<CommandContainer>>,
}

impl Agent {
    /// Create a new agent.
    #[tracing::instrument(skip(local_key))]
    pub fn new(
        local_key: identity::Keypair,
        relay_mode: bool,
    ) -> NResult<(Self, mpsc::Receiver<Event>)> {
        let local_pubkey = local_key.public();
        let local_peer_id = PeerId::from(local_key.public());
        info!("Local peer id: {:?}", local_peer_id);

        let dcutr = Toggle::from(if relay_mode {
            None
        } else {
            Some(dcutr::Behaviour::new(local_peer_id.clone()))
        });

        let reqres = {
            let config = request_response::Config::default();
            ReqresBehavior::<Request, Response>::new(
                [(
                    libp2p::StreamProtocol::new("/stampnet/sync/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                config,
            )
        };

        let identify = {
            let config = identify::Config::new("stampnet/1.0.0".into(), local_pubkey)
                .with_push_listen_addr_updates(false);
            identify::Behaviour::new(config)
        };

        let kad = {
            let mut store_config = kad::store::MemoryStoreConfig::default();
            store_config.max_value_bytes = MAX_DHT_RECORD_SIZE;
            let store = kad::store::MemoryStore::with_config(local_peer_id.clone(), store_config);
            let mut config = kad::Config::default();
            config.set_protocol_names(vec![libp2p::StreamProtocol::new("/stampnet/dht/1.0.0")]);
            // we're going to filter incoming Puts in kad. published identities must match
            // the key they are being stored under
            config.set_record_filtering(kad::StoreInserts::FilterBoth);
            let mut kad = kad::Behaviour::with_config(local_peer_id.clone(), store, config);
            if relay_mode {
                kad.set_mode(Some(kad::Mode::Server));
            }
            kad
        };

        let ping = {
            let config = ping::Config::new();
            ping::Behaviour::new(config)
        };

        let relay = {
            if relay_mode {
                info!("creating relay behavior");
                let config = relay::Config::default();
                Toggle::from(Some(relay::Behaviour::new(local_peer_id.clone(), config)))
            } else {
                Toggle::from(None)
            }
        };

        let mut behavior = StampBehavior {
            dcutr,
            identify,
            kad,
            ping,
            relay,
            relay_client: Toggle::from(None),
            reqres,
        };

        let builder = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_dns()?;
        let swarm = if true || relay_mode {
            builder
                .with_behaviour(|_key| Ok(behavior))
                .map_err(|e| Error::BehaviorError(format!("{:?}", e)))?
                .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
                .build()
        } else {
            builder
                .with_relay_client(noise::Config::new, yamux::Config::default)?
                .with_behaviour(|_key, relay_client| {
                    behavior.relay_client = Toggle::from(Some(relay_client));
                    Ok(behavior)
                })
                .map_err(|e| Error::BehaviorError(format!("{:?}", e)))?
                .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
                .build()
        };
        let (event_send, event_recv) = mpsc::channel(10);
        let (cmd_send, cmd_recv) = mpsc::channel(10);
        let agent = Self {
            relay_mode,
            swarm: Mutex::new(swarm),
            event_send,
            request_tracker: Mutex::new(HashMap::new()),
            cmd_send,
            cmd_recv: Mutex::new(cmd_recv),
        };
        Ok((agent, event_recv))
    }

    /// A util to wait on the given request ID
    async fn run_command(&self, command: Command) -> NResult<oneshot::Receiver<CommandResult>> {
        let uuid = Uuid::now_v7();
        let req_id = RequestID::Uuid(uuid);
        let expires = Utc::now().timestamp() + 10;
        let (tx, rx) = oneshot::channel();
        {
            let mut request_tracker = self.request_tracker.lock().await;
            request_tracker.insert(req_id.clone(), (expires, tx));
        }
        self.cmd_send
            .send(CommandContainer::new(req_id, command))
            .await
            .map_err(|e| Error::Future(format!("error sending command: {}", e)))?;
        Ok(rx)
    }

    /// Start the agent. This initiates listening and joining of other nodes.
    #[tracing::instrument(skip(self, join))]
    pub async fn run(&self, bind: Multiaddr, join: Vec<Multiaddr>) -> NResult<()> {
        {
            let mut swarm = self.swarm.lock().await;
            swarm.listen_on(bind.clone()).map_err(|e| {
                error!("cannot bind {:?}", bind);
                Error::Transport(format!("{:?}", e))
            })?;
            for address in join {
                match swarm.dial(address.clone()) {
                    Ok(_) => info!("Dialed {:?}", address),
                    Err(e) => error!("Dial {:?} failed: {:?}", address, e),
                }
            }
        }

        let mut request_id_mapper: HashMap<RequestID, RequestID> = HashMap::new();

        macro_rules! respond {
            ($req_id:expr, $response:expr) => {{
                let mut req_id = $req_id.clone();
                loop {
                    if let Some((_exp, tx)) = self.request_tracker.lock().await.remove(&req_id) {
                        match tx.send($response) {
                            Err(_) => error!(
                                "respond {}:{} -- {:?} problem responding",
                                file!(),
                                line!(),
                                req_id
                            ),
                            _ => {}
                        }
                        break;
                    } else {
                        // see if this dumb req id points to another req.
                        if let Some(rid) = request_id_mapper.remove(&req_id) {
                            debug!(
                                "respond {}:{} -- looping: {:?} -> {:?}",
                                file!(),
                                line!(),
                                req_id,
                                rid
                            );
                            req_id = rid;
                        } else {
                            debug!(
                                "respond {}:{} -- {:?} has no matching request",
                                file!(),
                                line!(),
                                req_id
                            );
                            break;
                        }
                    }
                }
            }};
        }

        macro_rules! send_event {
            ($val:expr, $event_tx:expr) => {
                match $event_tx.send($val).await {
                    Err(e) => {
                        error!("send_event {}:{} -- {}", file!(), line!(), e);
                    }
                    _ => {}
                }
            };
            ($val:expr) => {
                send_event! { $val, self.event_send }
            };
        }

        let mut kad_has_bootstrapped = false;
        let mut swarm = self.swarm.lock().await;
        let mut cmd_recv = self.cmd_recv.lock().await;
        let maintenance_cmd_send = self.cmd_send.clone();
        tokio::task::spawn(async move {
            loop {
                let uuid = Uuid::now_v7();
                let req_id = RequestID::Uuid(uuid);
                match maintenance_cmd_send
                    .send(CommandContainer::new(req_id, Command::Maintenance))
                    .await
                {
                    Ok(_) => {}
                    Err(e) => warn!("problem sending maintenance command: {:?}", e),
                }
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });
        loop {
            select! {
                cmd = cmd_recv.recv().fuse() => {
                    let (req_id, cmd) = if let Some(cmd) = cmd {
                        let CommandContainer { id: req_id, ty: cmd } = cmd;
                        (req_id, cmd)
                    } else {
                        continue;
                    };
                    match cmd {
                        Command::GetConnectedPeers => {
                            let peers = swarm.connected_peers().cloned().collect::<Vec<_>>();
                            respond! { &req_id, CommandResult::Ok(Some(StampEvent::PeerList(peers))) }
                        }
                        Command::IdentityLookup(identity_id) => {
                            let store_key = format!("/stampnet/publish/identity/{}", identity_id);
                            let key = kad::RecordKey::new(&store_key);
                            let qid = swarm.behaviour_mut().kad.get_record(key);
                            request_id_mapper.insert(RequestID::Kad(qid), req_id);
                        }
                        Command::IdentityPublish { publish_transaction, quorum } => {
                            let process_identity = || {
                                let identity_id = validate_publish_transaction(&publish_transaction)?;
                                let serialized = publish_transaction.serialize_binary()?;
                                Ok((identity_id, serialized))
                            };
                            let (identity_id, serialized) = match process_identity() {
                                Ok(id) => id,
                                Err(e) => {
                                    respond! { &req_id, CommandResult::Err(e) }
                                    continue;
                                }
                            };
                            if serialized.len() > MAX_PUBLISHED_IDENTITY_SIZE {
                                warn!("kad: put identity: published identity size {} is larger than storage threshold {}, peers will likely not publish and you will have to keep this node up indefinitely.", serialized.len(), MAX_PUBLISHED_IDENTITY_SIZE);
                            }
                            let store_key = format!("/stampnet/publish/identity/{}", identity_id);
                            let record = kad::Record::new(Vec::from(store_key.as_bytes()), serialized);
                            let qid = match swarm.behaviour_mut().kad.put_record(record, quorum) {
                                Ok(qid) => qid,
                                Err(e) => {
                                    respond! { &req_id, CommandResult::Err(e.into()) }
                                    continue;
                                }
                            };
                            request_id_mapper.insert(RequestID::Kad(qid), req_id);
                        }
                        Command::KadQueryProviders(key) => {
                            let key = kad::RecordKey::new(&key);
                            let qid = swarm.behaviour_mut().kad.get_providers(key.clone());
                            request_id_mapper.insert(RequestID::Kad(qid), req_id);
                        }
                        Command::KadStartProvide(key) => {
                            let key = kad::RecordKey::new(&key);
                            let qid = match swarm.behaviour_mut().kad.start_providing(key.clone()) {
                                Ok(qid) => qid,
                                Err(e) => {
                                    respond! { &req_id, CommandResult::Err(e.into()) }
                                    continue;
                                }
                            };
                            request_id_mapper.insert(RequestID::Kad(qid), req_id);
                        }
                        Command::KadStopProvide(key) => {
                            let key = kad::RecordKey::new(&key);
                            swarm.behaviour_mut().kad.stop_providing(&key);
                            respond! { &req_id, CommandResult::Ok(None) }
                        }
                        Command::Maintenance => {
                            // don't hang up this loop waiting on locks.
                            let mut requests = match self.request_tracker.try_lock() {
                                Ok(lock) => lock,
                                Err(_) => continue,
                            };
                            let now = Utc::now().timestamp();
                            let mut rm_req = Vec::new();
                            for (req_id, (expires, _)) in requests.iter() {
                                if expires < &now {
                                    debug!("command request {:?} timed out", req_id);
                                    rm_req.push(req_id.clone());
                                }
                            }
                            for rm_req_id in rm_req {
                                match requests.remove(&rm_req_id) {
                                    Some((_, tx)) => {
                                        match tx.send(CommandResult::Err(Error::CommandTimeout)) {
                                            Ok(_) => {}
                                            Err(e) => warn!("command timeout notification send failed: {:?}", e),
                                        }
                                    }
                                    None => {}
                                }
                            }
                        }
                        Command::Quit => {
                            info!("I QUIT!");
                            respond! { &req_id, CommandResult::Ok(None) }
                            send_event! { Event::Quit }
                            break;
                        }
                    }
                },
                ev = swarm.select_next_some() => match ev {
                    SwarmEvent::Behaviour(StampEvent::Identify(identify::Event::Received { peer_id, info })) => {
                        info!("identify: new peer: {} -- {:?} -- {:?}", peer_id, info.listen_addrs, info.protocols);
                        for addr in &info.listen_addrs {
                            swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                        }
                        if self.relay_mode && info.protocols.iter().find(|p| p.as_ref().contains("/libp2p/circuit/relay")).is_some() {
                            let mut seen: HashSet<Multiaddr> = HashSet::new();
                            for addr in info.listen_addrs.iter() {
                                let has_circuit = addr.iter().find(|m| matches!(m, multiaddr::Protocol::P2pCircuit)).is_some();
                                if has_circuit {
                                    continue;
                                }
                                let has_p2p = addr.iter().find(|m| matches!(m, multiaddr::Protocol::P2p(_))).is_some();

                                let addr = addr.clone();
                                let addr = if !has_p2p {
                                    addr.with(multiaddr::Protocol::P2p(info.public_key.to_peer_id().clone()))
                                } else {
                                    addr
                                };
                                let circuit_addr = addr.with(multiaddr::Protocol::P2pCircuit);
                                if seen.contains(&circuit_addr) {
                                    continue;
                                }
                                if swarm.listeners().find(|l| *l == &circuit_addr).is_some() {
                                    continue;
                                }
                                info!("Creating circuit relay listener: {:?}", circuit_addr);
                                match swarm.listen_on(circuit_addr.clone()) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        send_event!{ Event::Error(Error::Transport(format!("{}", e))) }
                                    }
                                }
                                seen.insert(circuit_addr);
                            }
                        }
                        if !kad_has_bootstrapped {
                            match swarm.behaviour_mut().kad.bootstrap() {
                                Err(_) => {
                                    send_event!{ Event::Error(Error::KadBootstrap) }
                                }
                                _ => {
                                    kad_has_bootstrapped = true;
                                    send_event! { Event::DiscoveryReady }
                                    if self.relay_mode {
                                        match self.run_command(Command::KadStartProvide("/stampnet/relay/provider".into())).await {
                                            Ok(rx) => {
                                                let event_tx = self.event_send.clone();
                                                tokio::task::spawn(async move {
                                                    match rx.await? {
                                                        CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed { result: kad::QueryResult::StartProviding(res), .. }))) => {
                                                            match res {
                                                                Ok(_) => {
                                                                    info!("successfully advertised node as relay");
                                                                    send_event! { Event::KadBootstrapped, event_tx }
                                                                }
                                                                Err(e) => warn!("error advertising node as relay: {:?}", e),
                                                            }
                                                        }
                                                        CommandResult::Ok(x) => warn!("weirdness advertising node as relay (unexpected return): {:?}", x),
                                                        CommandResult::Err(e) => warn!("error advertising node as relay: {}", e),
                                                    }
                                                    NResult::Ok(())
                                                });
                                            }
                                            Err(e) => warn!("error advertising node as relay: {}", e),
                                        };
                                    }
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(StampEvent::Kad(kad::Event::OutboundQueryProgressed { id: ref qid, .. })) => {
                        let query_id = qid.clone();
                        let event = match ev {
                            SwarmEvent::Behaviour(ev) => ev,
                            _ => {
                                // should never get here, obvis
                                error!("kad query matcher: unmatched event");
                                continue;
                            }
                        };
                        respond! { &RequestID::Kad(query_id), CommandResult::Ok(Some(event)) }
                    }
                    SwarmEvent::Behaviour(StampEvent::Kad(kad::Event::InboundRequest { request: kad::InboundRequest::AddProvider { record: Some(provider) } })) => {
                        match swarm.behaviour_mut().kad.store_mut().add_provider(provider.clone()) {
                            Ok(_) => info!("kad: inbound: provider added: {:?}", provider),
                            Err(e) => {
                                warn!("kad: inbound: provider add failed: {}", e);
                                continue;
                            }
                        }
                    }
                    // this block validates put records into the DHT. if publishing an identity,
                    // you must be publishing it under the key that corresponds with the identity
                    // and the identity must self-validate.
                    //
                    // it also must be under the max size.
                    SwarmEvent::Behaviour(StampEvent::Kad(kad::Event::InboundRequest { request: kad::InboundRequest::PutRecord { source, record: Some(record), .. } })) => {
                        let key_string = match String::from_utf8(Vec::from(record.key.as_ref())) {
                            Ok(s) => s,
                            Err(_) => {
                                warn!("kad: inbound: peer {:?} is setting non-utf8 (junk) keys in DHT. punish them.", source);
                                continue;
                            }
                        };
                        let rec_len = record.value.len();
                        if key_string.starts_with("/stampnet/publish/identity/") {
                            if record.value.len() > MAX_PUBLISHED_IDENTITY_SIZE {
                                warn!("kad: inbound: peer {:?} tried to publish an identity above the max size ({} > {})", source, record.value.len(), MAX_PUBLISHED_IDENTITY_SIZE);
                                continue;
                            }
                            match Transaction::deserialize_binary(&record.value) {
                                Ok(trans) => {
                                    match validate_publish_transaction(&trans) {
                                        Ok(identity_id_validated) => {
                                            let identity_id = key_string.strip_prefix("/stampnet/publish/identity/");
                                            let id_validated = format!("{}", identity_id_validated);
                                            if Some(id_validated.as_str()) != identity_id {
                                                warn!("kad: inbound: peer {:?} sent and identity {} that did not match the key {}", source, id_validated, key_string);
                                                continue;
                                            }
                                        }
                                        Err(e) => {
                                            warn!("kad: inbound: peer {:?} sent an identity for storage that did not validate: {}", source, e);
                                            continue;
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("kad: inbound: peer {:?} sent an identity for storage that could not be deserialized: {:?}", source, e);
                                    continue;
                                }
                            }
                        }
                        // if we made it here, store the key
                        match swarm.behaviour_mut().kad.store_mut().put(record) {
                            Ok(_) => info!("kad: inbound: put: {}: {} bytes", key_string, rec_len),
                            Err(e) => {
                                warn!("kat: inbound: put: failed to store value in key {}: {}", key_string, e);
                                continue;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(StampEvent::Ping(ev)) => {
                        send_event!{ Event::Ping }
                        trace!("ping: {:?}", ev);
                    }
                    SwarmEvent::Behaviour(any) => {
                        debug!("swarm event: {:?}", any);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        info!("swarm: connection opened: {} -- {:?}", peer_id, endpoint);
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        info!("swarm: connection closed: {} -- {:?}", peer_id, cause);
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Listening on {:?}", address);
                    }
                    _ => {}
                },
            }
        }
        Ok(())
    }

    /// Ask Kad to mark us as a provider for something.
    #[tracing::instrument(skip(self))]
    async fn kad_provide(&self, resource: String) -> NResult<StampEvent> {
        let rx = self.run_command(Command::KadStartProvide(resource)).await?;
        let ev = match rx.await? {
            CommandResult::Ok(Some(ev)) => {
                match ev {
                    StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::StartProviding(Ok(_)),
                        ..
                    }) => {}
                    _ => Err(Error::CommandGeneric(format!(
                        "failed to start providing: {:?}",
                        ev
                    )))?,
                }
                // TODO: verify that we have a success response in the kad event itself
                ev
            }
            CommandResult::Ok(None) => Err(Error::CommandGeneric(
                "blank response, expected event".into(),
            ))?,
            CommandResult::Err(e) => Err(e)?,
        };
        Ok(ev)
    }

    /// Ask Kad to stop providing on our behalf.
    #[tracing::instrument(skip(self))]
    async fn kad_stop_providing(&self, resource: String) -> NResult<()> {
        let rx = self.run_command(Command::KadStopProvide(resource)).await?;
        match rx.await? {
            CommandResult::Ok(_) => {}
            CommandResult::Err(e) => Err(e)?,
        };
        Ok(())
    }

    /// Stop this agent
    #[tracing::instrument(skip(self))]
    pub async fn quit(&self) -> NResult<()> {
        let rx = self.run_command(Command::Quit).await?;
        match rx.await? {
            CommandResult::Ok(_) => {}
            CommandResult::Err(e) => Err(e)?,
        }
        Ok(())
    }

    /// Generate a full topic name.
    fn create_topic_name(pubkey: &SignKeypairPublic, topic_name: &str) -> String {
        format!(
            "/stampnet/share/topic/{}:{}",
            pubkey.key_id().as_string(),
            topic_name
        )
    }

    /// Advertise in the network that we are the provider of a given topic. Requires knowledge of
    /// the public key associated with the topic's secret key.
    #[tracing::instrument(skip(self, pubkey))]
    pub async fn join_topic(
        &self,
        pubkey: &SignKeypairPublic,
        topic_name: &str,
    ) -> NResult<String> {
        let topic_full = Self::create_topic_name(pubkey, topic_name);
        self.kad_provide(topic_full.clone()).await?;
        Ok(topic_full)
    }

    /// Advertise to the network that we are no longer a provider/participant in a given topic.
    /// Requires knowledge of the public key associated with the topic's secret key.
    #[tracing::instrument(skip(self, pubkey))]
    pub async fn leave_topic(
        &self,
        pubkey: &SignKeypairPublic,
        topic_name: &str,
    ) -> NResult<String> {
        let topic_full = Self::create_topic_name(pubkey, topic_name);
        self.kad_stop_providing(topic_full.clone()).await?;
        Ok(topic_full)
    }

    /// Query messages from a few nodes in the given topic.
    #[tracing::instrument(skip(self))]
    pub async fn query_topic(
        &self,
        master_key: &SecretKey,
        sign_key: &SignKeypair,
        topic_name: &str,
        query: TransactionQuery,
    ) -> NResult<Option<Vec<Transaction>>> {
        let topic_full = Self::create_topic_name(&sign_key.clone().into(), topic_name);
        let rx = self
            .run_command(Command::KadQueryProviders(topic_full))
            .await?;
        let providers = match rx.await? {
            CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetProviders(Ok(getres)),
                ..
            }))) => match getres {
                kad::GetProvidersOk::FoundProviders { providers, .. } => providers,
                _ => return Ok(None),
            },
            CommandResult::Ok(e) => Err(Error::CommandGeneric(format!(
                "topic provider lookup failed: {:?}",
                e
            )))?,
            CommandResult::Err(e) => Err(e)?,
        };
        println!("---\nproviders: {:?}", providers);
        Ok(Some(vec![]))
    }

    /// Publish an identity.
    #[tracing::instrument(skip(self, publish_transaction))]
    pub async fn publish_identity(
        &self,
        publish_transaction: Transaction,
        quorum: Quorum,
    ) -> NResult<String> {
        let rx = self
            .run_command(Command::IdentityPublish {
                publish_transaction,
                quorum,
            })
            .await?;
        let key = match rx.await? {
            CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })),
                ..
            }))) => String::from_utf8(key.to_vec())
                .map_err(|e| Error::Kad(format!("error converting kad key: {:?}", e)))?,
            CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                result:
                    kad::QueryResult::PutRecord(Err(kad::PutRecordError::QuorumFailed { key, .. })),
                ..
            }))) => Err(Error::KadPutQuorumFailed)?,
            CommandResult::Ok(e) => {
                Err(Error::CommandGeneric(format!("publish failure: {:?}", e)))?
            }
            CommandResult::Err(e) => Err(e)?,
        };
        Ok(key)
    }

    /// Look up an identity.
    #[tracing::instrument(skip(self))]
    pub async fn lookup_identity(&self, identity_id: IdentityID) -> NResult<Option<Transaction>> {
        let rx = self
            .run_command(Command::IdentityLookup(identity_id))
            .await?;
        let identity_maybe = match rx.await? {
            CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetRecord(Ok(getres)),
                ..
            }))) => match getres {
                kad::GetRecordOk::FoundRecord(kad::PeerRecord { peer, record }) => {
                    let key = String::from_utf8(record.key.to_vec())
                        .map_err(|e| Error::Kad(format!("error converting kad key: {:?}", e)))?;
                    info!("identity record at {} provided by {:?}", key, peer);
                    let trans = Transaction::deserialize_binary(&record.value)?;
                    validate_publish_transaction(&trans)?;
                    Some(trans)
                }
                kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. } => None,
            },
            CommandResult::Ok(e) => Err(Error::CommandGeneric(format!("lookup failure: {:?}", e)))?,
            CommandResult::Err(e) => Err(e)?,
        };
        Ok(identity_maybe)
    }

    /// Get the connected peers to this node.
    #[tracing::instrument(skip(self))]
    pub async fn connected_peers(&self) -> NResult<Vec<PeerId>> {
        let rx = self.run_command(Command::GetConnectedPeers).await?;
        let peers = match rx.await? {
            CommandResult::Ok(Some(StampEvent::PeerList(peers))) => peers,
            CommandResult::Ok(_) => Err(Error::CommandGeneric(
                "invalid event for connected peers".into(),
            ))?,
            CommandResult::Err(e) => Err(e)?,
        };
        Ok(peers)
    }
}
