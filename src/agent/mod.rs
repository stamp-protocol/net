mod behavior;

pub use behavior::*;

use crate::error::{Error, Result};
use chrono::Utc;
use futures::{prelude::*, select};
pub use libp2p::kad::Quorum;
use libp2p::{
    dcutr, identify, identity, kad, multiaddr, noise, ping, relay,
    swarm::{behaviour::toggle::Toggle, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use stamp_core::{dag::Transaction, identity::IdentityID, util::SerdeBinary};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

/// The max size a published identity can be. above this, we don't store it remotely. You have to
/// store it yourself.
const MAX_PUBLISHED_IDENTITY_SIZE: usize = 1024 * 1024 * 4;
/// The max packet size we can have in our DHT. Identities larger than this are going to have to be
/// distributed in other ways.
const MAX_DHT_RECORD_SIZE: usize = 1024 * 1024 * 8;
/// How long an [`Agent`] command has to run before we time it out and clean it up.
const COMMAND_TIMEOUT: i64 = 60;

/// Do we want to run as a relay server, client, or none?
#[derive(Clone, Debug, PartialEq)]
pub enum RelayMode {
    Server,
    Client,
    None,
}

/// Do we want to run as a relay server, client, or none?
#[derive(Clone, Debug, PartialEq)]
pub enum DHTMode {
    Server,
    Client,
}

#[derive(Debug)]
pub enum Event {
    Error(Error),
    IdentifyRecv,
    Ping,
    Quit,
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
    Dial(Vec<Multiaddr>),
    IdentityLookup(IdentityID),
    IdentityPublish { publish_transaction: Transaction, quorum: Quorum },
    KadBootstrap,
    KadQueryProviders(String),
    KadStartProvide(String),
    KadStopProvide(String),
    Maintenance,
    Quit,
}

#[derive(Debug)]
enum CommandResult {
    Ok(Option<StampEvent>),
    Err(Error),
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

/// Generate a new random peer key.
pub fn random_peer_key() -> identity::Keypair {
    identity::Keypair::generate_ed25519()
}

/// Create a store that puts values into memory (volatile across restarts).
pub fn memory_store(peer_id: &PeerId) -> kad::store::MemoryStore {
    let mut store_config = kad::store::MemoryStoreConfig::default();
    store_config.max_value_bytes = MAX_DHT_RECORD_SIZE;
    kad::store::MemoryStore::with_config(peer_id.clone(), store_config)
}

pub struct Agent<S: kad::store::RecordStore + Send + 'static> {
    relay_mode: RelayMode,
    swarm: Mutex<Swarm<StampBehavior<S>>>,
    event_send: mpsc::Sender<Event>,
    request_tracker: Mutex<HashMap<RequestID, (bool, i64, mpsc::Sender<CommandResult>)>>,
    cmd_send: mpsc::Sender<CommandContainer>,
    cmd_recv: Mutex<mpsc::Receiver<CommandContainer>>,
}

impl<S: kad::store::RecordStore + Send + 'static> Agent<S> {
    /// Create a new agent.
    #[tracing::instrument(skip(local_key, store))]
    pub fn new(local_key: identity::Keypair, store: S, relay_mode: RelayMode, dht_mode: DHTMode) -> Result<(Self, mpsc::Receiver<Event>)>
    where
        S: kad::store::RecordStore,
    {
        let local_pubkey = local_key.public();
        let local_peer_id = PeerId::from(local_key.public());
        info!("Local peer id: {:?}", local_peer_id);

        let dcutr = Toggle::from(if relay_mode == RelayMode::Server {
            None
        } else {
            Some(dcutr::Behaviour::new(local_peer_id.clone()))
        });

        let identify = {
            let config = identify::Config::new("stampnet/1.0.0".into(), local_pubkey).with_push_listen_addr_updates(false);
            identify::Behaviour::new(config)
        };

        let kad = {
            let mut config = kad::Config::default();
            config
                .set_replication_factor(std::num::NonZeroUsize::new(20).unwrap())
                .set_query_timeout(Duration::from_secs(60))
                .set_parallelism(std::num::NonZeroUsize::new(5).unwrap())
                .disjoint_query_paths(true)
                .set_protocol_names(vec![libp2p::StreamProtocol::new("/stampnet/dht/1.0.0")])
                // we're going to filter incoming Puts in kad. published identities must match
                // the key they are being stored under
                .set_record_filtering(kad::StoreInserts::FilterBoth)
                // make sure our identities can actually be sent across state lines. this took a
                // long time to find, so i thought i'd leave a comment to tell the tale of my
                // triumphs.
                .set_max_packet_size(MAX_DHT_RECORD_SIZE);
            let mut kad = kad::Behaviour::with_config(local_peer_id.clone(), store, config);
            if dht_mode == DHTMode::Server {
                kad.set_mode(Some(kad::Mode::Server));
            }
            kad
        };

        let ping = {
            let config = ping::Config::new();
            ping::Behaviour::new(config)
        };

        let relay = {
            if relay_mode == RelayMode::Server {
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
        };

        let builder = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
            .with_dns()?;
        let swarm = if relay_mode == RelayMode::Server || relay_mode == RelayMode::None {
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
        let (event_send, event_recv) = mpsc::channel(64);
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

    /// Run a command and return the request id and a receiver channel.
    ///
    /// If `stream` is set to `true` then the command will be left "open" and must be closed on the
    /// receiving end via [`close_command`], which allows multiple events to be received.
    async fn run_command_impl(&self, command: Command, stream: bool) -> Result<(RequestID, mpsc::Receiver<CommandResult>)> {
        let uuid = Uuid::now_v7();
        let req_id = RequestID::Uuid(uuid);
        let expires = Utc::now().timestamp() + COMMAND_TIMEOUT;
        let (tx, rx) = mpsc::channel(1024); // arbitrary
        {
            let mut request_tracker = self.request_tracker.lock().await;
            request_tracker.insert(req_id.clone(), (stream, expires, tx));
        }
        self.cmd_send
            .send(CommandContainer::new(req_id.clone(), command))
            .await
            .map_err(|e| Error::Future(format!("error sending command: {}", e)))?;
        Ok((req_id, rx))
    }

    /// A util to wait on the given request ID
    async fn run_command(&self, command: Command) -> Result<mpsc::Receiver<CommandResult>> {
        self.run_command_impl(command, false).await.map(|x| x.1)
    }

    /// A util to wait on the given request ID, but keep the request open for multiple events until
    /// it is explicitely closed via [`close_request`].
    async fn run_command_stream(&self, command: Command) -> Result<(RequestID, mpsc::Receiver<CommandResult>)> {
        self.run_command_impl(command, true).await
    }

    /// Removes a request from the tracker, meaning no more messages can be sent on it.
    async fn close_command(&self, req_id: &RequestID) -> bool {
        self.request_tracker.lock().await.remove(req_id).is_some()
    }

    /// Start the agent. This initiates listening and joining of other nodes.
    #[tracing::instrument(skip(self, join))]
    pub async fn run(&self, bind: Multiaddr, join: Vec<Multiaddr>) -> Result<()> {
        let listener_id = {
            let mut swarm = self.swarm.lock().await;
            let listener = swarm.listen_on(bind.clone()).map_err(|e| {
                error!("cannot bind {:?}", bind);
                Error::Transport(format!("{:?}", e))
            })?;
            for address in join {
                match swarm.dial(address.clone()) {
                    Ok(_) => info!("Dialed {:?}", address),
                    Err(e) => error!("Dial {:?} failed: {:?}", address, e),
                }
            }
            listener
        };

        /// Maps different types of requests to others, allowing messages/events to be sent along
        /// multiple hops to a final destination.
        struct RequestMapper {
            mapping: HashMap<RequestID, (i64, RequestID)>,
        }

        impl RequestMapper {
            fn new() -> Self {
                Self { mapping: HashMap::new() }
            }

            fn insert(&mut self, req_from: RequestID, req_to: RequestID) {
                let expires = Utc::now().timestamp() + COMMAND_TIMEOUT;
                self.mapping.insert(req_from, (expires, req_to));
            }

            fn get(&self, req_from: &RequestID) -> Option<&(i64, RequestID)> {
                self.mapping.get(req_from)
            }

            fn maintenance(&mut self, now: i64) {
                let mut rm_map = Vec::new();
                for (req_id, (expires, _)) in self.mapping.iter() {
                    if expires < &now {
                        debug!("command id mapping {:?} has timed out", req_id);
                        rm_map.push(req_id.clone());
                    }
                }
                for rm_map_id in rm_map {
                    self.mapping.remove(&rm_map_id);
                }
            }
        }

        let mut request_id_mapper = RequestMapper::new();

        macro_rules! respond {
            ($req_id:expr, $response:expr) => {{
                let mut req_id = $req_id.clone();
                'respond: loop {
                    let mut handle = self.request_tracker.lock().await;
                    if let Some((stream, exp, tx)) = handle.remove(&req_id) {
                        // TODO: figure out why we aren't getting our kad events through this
                        // stream
                        if stream {
                            // if we're streaming, save the handle back into the request tracker.
                            // the listener needs to do the cleanup in this case.
                            handle.insert(req_id.clone(), (stream, exp, tx.clone()));
                        }
                        match tx.send($response).await {
                            Err(_) => error!("respond {}:{} -- {:?} problem responding", file!(), line!(), req_id),
                            _ => {}
                        }
                        break 'respond;
                    } else {
                        // see if this dumb req id points to another req.
                        if let Some((_exp, rid)) = request_id_mapper.get(&req_id) {
                            debug!("respond {}:{} -- looping: {:?} -> {:?}", file!(), line!(), req_id, rid);
                            req_id = rid.clone();
                        } else {
                            debug!("respond {}:{} -- {:?} has no matching request", file!(), line!(), req_id);
                            break 'respond;
                        }
                    }
                }
            }};
        }

        macro_rules! send_event {
            ($val:expr, $event_tx:expr) => {
                match $event_tx.try_send($val) {
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        warn!("send_event: channel full -- {}:{}", file!(), line!());
                    }
                    Err(e) => {
                        error!("send_event: error -- {}:{} -- {}", file!(), line!(), e);
                    }
                    _ => {}
                }
            };
            ($val:expr) => {
                send_event! { $val, self.event_send }
            };
        }

        let mut swarm = self.swarm.lock().await;
        let mut cmd_recv = self.cmd_recv.lock().await;
        let maintenance_cmd_send = self.cmd_send.clone();
        tokio::task::spawn(async move {
            loop {
                let uuid = Uuid::now_v7();
                let req_id = RequestID::Uuid(uuid);
                match maintenance_cmd_send.send(CommandContainer::new(req_id, Command::Maintenance)).await {
                    Ok(_) => {}
                    Err(e) => warn!("problem sending maintenance command: {:?}", e),
                }
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });
        'run: loop {
            select! {
                cmd = cmd_recv.recv().fuse() => {
                    let (req_id, cmd) = if let Some(cmd) = cmd {
                        let CommandContainer { id: req_id, ty: cmd } = cmd;
                        (req_id, cmd)
                    } else {
                        continue 'run;
                    };
                    trace!("run() -- select: cmd: {req_id:?} -- {cmd:?}");
                    match cmd {
                        Command::GetConnectedPeers => {
                            let peers = swarm.connected_peers().cloned().collect::<Vec<_>>();
                            respond! { &req_id, CommandResult::Ok(Some(StampEvent::PeerList(peers))) }
                        }
                        Command::Dial(peers) => {
                            for address in peers {
                                match swarm.dial(address.clone()) {
                                    Ok(_) => info!("Dialed {:?}", address),
                                    Err(e) => error!("Dial {:?} failed: {:?}", address, e),
                                }
                            }
                            respond! { &req_id, CommandResult::Ok(None) }
                        }
                        Command::IdentityLookup(identity_id) => {
                            let store_key = format!("/stampnet/publish/identity/{}", identity_id);
                            let key = kad::RecordKey::new(&store_key);
                            let qid = swarm.behaviour_mut().kad.get_record(key);
                            request_id_mapper.insert(RequestID::Kad(qid), req_id);
                        }
                        Command::IdentityPublish { publish_transaction, quorum } => {
                            let process_identity = || {
                                let (_, identity) = publish_transaction.clone().validate_publish_transaction()?;
                                let identity_id = identity.id().clone();
                                let serialized = publish_transaction.serialize_binary()?;
                                Ok((identity_id, serialized))
                            };
                            let (identity_id, serialized) = match process_identity() {
                                Ok(id) => id,
                                Err(e) => {
                                    respond! { &req_id, CommandResult::Err(e) }
                                    continue 'run;
                                }
                            };
                            let num_bytes = serialized.len();
                            if num_bytes > MAX_PUBLISHED_IDENTITY_SIZE {
                                warn!("dht: put identity: published identity size {} is larger than storage threshold {} and peers will likely not publish.", serialized.len(), MAX_PUBLISHED_IDENTITY_SIZE);
                                respond! { &req_id, CommandResult::Err(Error::IdentityTooLarge) }
                                continue 'run;
                            }
                            let store_key = format!("/stampnet/publish/identity/{}", identity_id);
                            let key = kad::RecordKey::new(&store_key);
                            let mut record = kad::Record::new(key, serialized);
                            record.expires = Some(Instant::now() + Duration::from_secs(60 * 60 * 24 * 365));
                            info!("dht: outbound: put: {}: {} bytes", store_key, num_bytes);
                            let qid = match swarm.behaviour_mut().kad.put_record(record, quorum) {
                                Ok(qid) => qid,
                                Err(e) => {
                                    respond! { &req_id, CommandResult::Err(e.into()) }
                                    continue 'run;
                                }
                            };
                            request_id_mapper.insert(RequestID::Kad(qid), req_id);
                        }
                        Command::KadBootstrap => {
                            let qid = match swarm.behaviour_mut().kad.bootstrap() {
                                Ok(qid) => qid,
                                Err(_) => {
                                    respond! { &req_id, CommandResult::Err(Error::DHTNoPeers) }
                                    continue 'run;
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
                            let qid = match swarm.behaviour_mut().kad.start_providing(key) {
                                Ok(qid) => qid,
                                Err(e) => {
                                    respond! { &req_id, CommandResult::Err(e.into()) }
                                    continue 'run;
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
                                Err(_) => continue 'run,
                            };
                            // clean up timed out out command requests
                            let now = Utc::now().timestamp();
                            let mut rm_req = Vec::new();
                            for (req_id, (_, expires, _)) in requests.iter() {
                                if expires < &now {
                                    debug!("command request {:?} timed out", req_id);
                                    rm_req.push(req_id.clone());
                                }
                            }
                            for rm_req_id in rm_req {
                                match requests.remove(&rm_req_id) {
                                    Some((_, _, tx)) => {
                                        match tx.send(CommandResult::Err(Error::CommandTimeout)).await {
                                            Ok(_) => {}
                                            Err(e) => warn!("command timeout notification send failed: {:?}", e),
                                        }
                                    }
                                    None => {}
                                }
                            }
                            // clean up timed out command request mappings
                            request_id_mapper.maintenance(now);
                        }
                        Command::Quit => {
                            info!("quitting");
                            respond! { &req_id, CommandResult::Ok(None) }
                            send_event! { Event::Quit }
                            break 'run;
                        }
                    }
                },
                ev = swarm.select_next_some() => {
                    trace!("run() -- select: swarm event: {ev:?}");
                    match ev {
                        SwarmEvent::Behaviour(StampEvent::Identify(identify::Event::Received { peer_id, info })) => {
                            info!("identify: new peer: {} -- {:?} -- {:?}", peer_id, info.listen_addrs, info.protocols);
                            for addr in &info.listen_addrs {
                                let update = swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                debug!("identify: new peer: dht result: {:?}", update);
                            }
                            send_event!{ Event::IdentifyRecv }
                            if self.relay_mode == RelayMode::Server && info.protocols.iter().find(|p| p.as_ref().contains("/libp2p/circuit/relay")).is_some() {
                                let mut seen: HashSet<Multiaddr> = HashSet::new();
                                for addr in info.listen_addrs.iter() {
                                    let has_circuit = addr.iter().find(|m| matches!(m, multiaddr::Protocol::P2pCircuit)).is_some();
                                    if has_circuit {
                                        continue 'run;
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
                                        continue 'run;
                                    }
                                    if swarm.listeners().find(|l| *l == &circuit_addr).is_some() {
                                        continue 'run;
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
                        }
                        SwarmEvent::Behaviour(StampEvent::Kad(kad::Event::OutboundQueryProgressed { id: ref qid, .. })) => {
                            let query_id = qid.clone();
                            let event = match ev {
                                SwarmEvent::Behaviour(ev) => ev,
                                _ => {
                                    // should never get here, obvis
                                    error!("dht query matcher: unmatched event");
                                    continue 'run;
                                }
                            };
                            respond! { &RequestID::Kad(query_id), CommandResult::Ok(Some(event)) }
                        }
                        SwarmEvent::Behaviour(StampEvent::Kad(kad::Event::InboundRequest { request: kad::InboundRequest::AddProvider { record: Some(provider) } })) => {
                            match swarm.behaviour_mut().kad.store_mut().add_provider(provider.clone()) {
                                Ok(_) => info!("dht: inbound: provider added: {:?}", provider),
                                Err(e) => {
                                    warn!("dht: inbound: provider add failed: {}", e);
                                    continue 'run;
                                }
                            }
                        }
                        // this block validates records put into the DHT. if publishing an identity,
                        // you must be publishing it under the key that corresponds with the identity
                        // and the identity must self-validate.
                        //
                        // it also must be under the max size.
                        SwarmEvent::Behaviour(StampEvent::Kad(kad::Event::InboundRequest { request: kad::InboundRequest::PutRecord { source, record: Some(record), .. } })) => {
                            let key_string = match String::from_utf8(Vec::from(record.key.as_ref())) {
                                Ok(s) => s,
                                Err(_) => {
                                    warn!("dht: inbound: peer {:?} is setting non-utf8 (junk) keys in DHT. punish them.", source);
                                    continue 'run;
                                }
                            };
                            let rec_len = record.value.len();
                            if key_string.starts_with("/stampnet/publish/identity/") {
                                if record.value.len() > MAX_PUBLISHED_IDENTITY_SIZE {
                                    warn!("dht: inbound: peer {:?} tried to publish an identity above the max size ({} > {})", source, record.value.len(), MAX_PUBLISHED_IDENTITY_SIZE);
                                    continue 'run;
                                }
                                match Transaction::deserialize_binary(&record.value) {
                                    Ok(trans) => {
                                        match trans.validate_publish_transaction() {
                                            Ok((_, identity)) => {
                                                let identity_id_validated = identity.id().clone();
                                                let identity_id = key_string.strip_prefix("/stampnet/publish/identity/");
                                                let id_validated = format!("{}", identity_id_validated);
                                                if Some(id_validated.as_str()) != identity_id {
                                                    warn!("dht: inbound: peer {:?} sent and identity {} that did not match the key {}", source, id_validated, key_string);
                                                    continue 'run;
                                                }
                                            }
                                            Err(e) => {
                                                warn!("dht: inbound: peer {:?} sent an identity for storage that did not validate: {}", source, e);
                                                continue 'run;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("dht: inbound: peer {:?} sent an identity for storage that could not be deserialized: {:?}", source, e);
                                        continue 'run;
                                    }
                                }
                            }
                            // if we made it here, store the key
                            match swarm.behaviour_mut().kad.store_mut().put(record) {
                                Ok(_) => info!("dht: inbound: put: {}: {} bytes", key_string, rec_len),
                                Err(e) => {
                                    warn!("kat: inbound: put: failed to store value in key {}: {}", key_string, e);
                                    continue 'run;
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
                    }
                },
            }
        }
        swarm.remove_listener(listener_id);
        let connected_peers = swarm.connected_peers().cloned().collect::<Vec<_>>();
        for peer in connected_peers {
            match swarm.disconnect_peer_id(peer) {
                Err(e) => warn!("run(): swarm: error disconnectin peer: {:?}", e),
                _ => {}
            }
        }
        Ok(())
    }

    /// Bootstrap the DHT
    #[tracing::instrument(skip(self))]
    pub async fn dht_bootstrap(&self) -> Result<()> {
        let (req_id, mut rx) = self.run_command_stream(Command::KadBootstrap).await?;
        let res = loop {
            let ev = rx.recv().await.ok_or(Error::ChannelClosed)?;
            match ev {
                CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                    result: kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { .. })),
                    step,
                    ..
                }))) => {
                    if step.last {
                        break Ok(());
                    }
                }
                CommandResult::Ok(Some(ev)) => {
                    break Err(Error::CommandGeneric(format!("failed to bootstrap: {:?}", ev)));
                }
                CommandResult::Ok(None) => {
                    break Err(Error::CommandGeneric("blank response, expected event".into()));
                }
                CommandResult::Err(e) => break Err(e),
            }
        };
        self.close_command(&req_id).await;
        res?;
        if self.relay_mode == RelayMode::Server {
            // mark us as a relay provider...
            self.dht_provide("/stampnet/relay/provider".into()).await?;
            info!("successfully advertised node as relay");
        }
        Ok(())
    }

    /// Ask the DHT to mark us as a provider for something.
    #[tracing::instrument(skip(self))]
    async fn dht_provide(&self, resource: String) -> Result<()> {
        let mut rx = self.run_command(Command::KadStartProvide(resource)).await?;
        match rx.recv().await.ok_or(Error::ChannelClosed)? {
            CommandResult::Ok(Some(ev)) => match ev {
                StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                    result: kad::QueryResult::StartProviding(Ok(_)),
                    ..
                }) => {}
                _ => Err(Error::CommandGeneric(format!("failed to start providing: {:?}", ev)))?,
            },
            CommandResult::Ok(None) => Err(Error::CommandGeneric("blank response, expected event".into()))?,
            CommandResult::Err(e) => Err(e)?,
        }
        Ok(())
    }

    /// Ask the DHT to stop providing on our behalf.
    #[tracing::instrument(skip(self))]
    #[allow(dead_code)]
    async fn dht_stop_providing(&self, resource: String) -> Result<()> {
        let mut rx = self.run_command(Command::KadStopProvide(resource)).await?;
        match rx.recv().await.ok_or(Error::ChannelClosed)? {
            CommandResult::Ok(_) => {}
            CommandResult::Err(e) => Err(e)?,
        };
        Ok(())
    }

    /// Query providers for a given key.
    #[tracing::instrument(skip(self))]
    pub async fn dht_get_providers(&self, resource: String) -> Result<Vec<PeerId>> {
        let (req_id, mut rx) = self.run_command_stream(Command::KadQueryProviders(resource)).await?;
        let mut providers_list = HashSet::new();
        let res = loop {
            let ev = rx.recv().await;
            match ev {
                Some(CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                    result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { mut providers, .. })),
                    step,
                    ..
                })))) => {
                    providers_list.extend(providers.drain());
                    if step.last {
                        break Ok(());
                    }
                }
                Some(CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                    result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. })),
                    step,
                    ..
                })))) => {
                    if step.last {
                        break Ok(());
                    }
                }
                Some(CommandResult::Ok(ev)) => {
                    info!("Agent.dht_get_providers() -- unknown response: {:?}", ev);
                }
                Some(CommandResult::Err(e)) => break Err(e),
                None => {
                    break Err(Error::ChannelClosed)?;
                }
            }
        };
        self.close_command(&req_id).await;
        res?;
        Ok(providers_list.drain().collect::<Vec<_>>())
    }

    /// Stop this agent
    #[tracing::instrument(skip(self))]
    pub async fn quit(&self) -> Result<()> {
        let mut rx = self.run_command(Command::Quit).await?;
        match rx.recv().await.ok_or(Error::ChannelClosed)? {
            CommandResult::Ok(_) => {}
            CommandResult::Err(e) => Err(e)?,
        }
        Ok(())
    }

    /// Publish an identity.
    #[tracing::instrument(skip(self, publish_transaction))]
    pub async fn publish_identity(&self, publish_transaction: Transaction, quorum: Quorum) -> Result<String> {
        let mut rx = self
            .run_command(Command::IdentityPublish {
                publish_transaction,
                quorum,
            })
            .await?;
        let ev = rx.recv().await.ok_or(Error::ChannelClosed)?;
        let key = match ev {
            CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })),
                ..
            }))) => String::from_utf8(key.to_vec()).map_err(|e| Error::DHT(format!("error converting kad key: {:?}", e)))?,
            CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::PutRecord(Err(kad::PutRecordError::QuorumFailed { .. })),
                ..
            }))) => Err(Error::DHTPutQuorumFailed)?,
            CommandResult::Ok(e) => Err(Error::CommandGeneric(format!("publish failure: {:?}", e)))?,
            CommandResult::Err(e) => Err(e)?,
        };
        Ok(key)
    }

    /// Look up an identity.
    #[tracing::instrument(skip(self, identity_id), fields(identity_id = %identity_id))]
    pub async fn lookup_identity(&self, identity_id: IdentityID) -> Result<Option<Transaction>> {
        let mut rx = self.run_command(Command::IdentityLookup(identity_id)).await?;
        let identity_maybe = match rx.recv().await.ok_or(Error::ChannelClosed)? {
            CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetRecord(Ok(getres)),
                ..
            }))) => match getres {
                kad::GetRecordOk::FoundRecord(kad::PeerRecord { peer, record }) => {
                    let key =
                        String::from_utf8(record.key.to_vec()).map_err(|e| Error::DHT(format!("error converting kad key: {:?}", e)))?;
                    info!("identity record at {} provided by {:?}", key, peer);
                    let trans = Transaction::deserialize_binary(&record.value)?;
                    trans.clone().validate_publish_transaction()?;
                    Some(trans)
                }
                kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. } => None,
            },
            CommandResult::Ok(Some(StampEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetRecord(Err(kad::GetRecordError::NotFound { .. })),
                ..
            }))) => None,
            CommandResult::Ok(e) => Err(Error::CommandGeneric(format!("lookup failure: {:?}", e)))?,
            CommandResult::Err(e) => Err(e)?,
        };
        Ok(identity_maybe)
    }

    /// Get the connected peers to this node.
    #[tracing::instrument(skip(self))]
    pub async fn connected_peers(&self) -> Result<Vec<PeerId>> {
        let mut rx = self.run_command(Command::GetConnectedPeers).await?;
        let peers = match rx.recv().await.ok_or(Error::ChannelClosed)? {
            CommandResult::Ok(Some(StampEvent::PeerList(peers))) => peers,
            CommandResult::Ok(_) => Err(Error::CommandGeneric("invalid event for connected peers".into()))?,
            CommandResult::Err(e) => Err(e)?,
        };
        Ok(peers)
    }

    /// Start talking to some peers.
    ///
    /// "Pardon me, may I use your bathroom?? Thank you!!"
    #[tracing::instrument(skip(self))]
    pub async fn dial_peers(&self, peers: Vec<Multiaddr>) -> Result<()> {
        let mut rx = self.run_command(Command::Dial(peers)).await?;
        match rx.recv().await.ok_or(Error::ChannelClosed)? {
            CommandResult::Ok(None) => {}
            CommandResult::Ok(x) => Err(Error::CommandGeneric(format!("odd result for dial_peers(): {:?}", x)))?,
            CommandResult::Err(e) => Err(e)?,
        }
        Ok(())
    }
}
