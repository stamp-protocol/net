use futures::future::join_all;
use rand::SeedableRng;
use stamp_core::{
    crypto::base::{Hash, HashAlgo, SecretKey, SignKeypair},
    dag::Transactions,
    identity::keychain::{AdminKey, AdminKeypair},
    policy::{Capability, MultisigPolicy, Policy},
    util::Timestamp,
};
use stamp_net::{
    agent::{self, random_peer_key, Agent, DHTMode, Event, RelayMode},
    Multiaddr,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::log::warn;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn setup() {
    tracing_subscriber::registry()
        .with(fmt::layer().with_span_events(fmt::format::FmtSpan::CLOSE))
        .with(EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info")).unwrap())
        .try_init()
        .unwrap_or_else(|_| ())
}

pub fn agent(relay_mode: RelayMode, dht_mode: DHTMode) -> (Agent<libp2p::kad::store::MemoryStore>, mpsc::Receiver<Event>) {
    let key = random_peer_key();
    let peer_id = libp2p::PeerId::from(key.public());
    Agent::new(key, agent::memory_store(&peer_id), relay_mode, dht_mode).unwrap()
}

pub async fn node_event_sink(node: &TestNode) {
    let multiaddr = node.multiaddr.clone();
    let events = node.events.clone();
    let num_ident = node.num_ident.clone();
    loop {
        let mut handle = events.write().await;
        match handle.recv().await {
            Some(Event::Quit) => break,
            Some(Event::IdentifyRecv) => {
                (*num_ident.write().await) += 1;
            }
            Some(ev) => tracing::log::trace!("event_sink: {} -- {:?}", multiaddr, ev),
            _ => {}
        }
    }
}

pub async fn connect_nodes(nodes: &Vec<TestNode>) {
    let peers = nodes.iter().map(|x| x.multiaddr.clone()).collect::<Vec<_>>();
    // wait a sec for listeners to start
    tokio::time::sleep(Duration::from_millis(250)).await;
    // loop over the nodes and connect each one to a few listening peers
    for (i, node) in nodes.iter().enumerate() {
        let dial_peers = vec![
            peers[(i + 1) % peers.len()].clone(),
            peers[(i + 2) % peers.len()].clone(),
            peers[(i + 4) % peers.len()].clone(),
        ];
        node.agent.dial_peers(dial_peers).await.unwrap();
    }
}

pub async fn wait_for_node_connections(nodes: &Vec<TestNode>, min_connections_per_node: usize) {
    let min_connections_per_node = std::cmp::min(min_connections_per_node, nodes.len() - 1);
    loop {
        let connection_tasks = nodes.iter().map(|n| n.num_ident.read()).collect::<Vec<_>>();
        let num_init = join_all(connection_tasks)
            .await
            .into_iter()
            .filter(|x| **x >= min_connections_per_node)
            .count();
        if num_init == nodes.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn bootstrap_dht(nodes: &Vec<TestNode>) {
    if nodes.len() < 2 {
        warn!("common::bootstrap_dht() -- too few nodes to bootstrap");
        return;
    }
    let bootstrap_tasks = nodes.iter().map(|n| n.agent.dht_bootstrap()).collect::<Vec<_>>();
    for res in join_all(bootstrap_tasks).await {
        res.unwrap();
    }
}

#[allow(dead_code)]
pub fn create_sync_keys(seed: &[u8]) -> (SecretKey, SecretKey, SignKeypair) {
    let seed: [u8; 32] = Hash::new_blake3(seed).unwrap().as_bytes().try_into().unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let shared_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
    let secret_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
    let sign_key = SignKeypair::new_ed25519(&mut rng, &secret_key).unwrap();
    (shared_key, secret_key, sign_key)
}

pub fn create_fake_identity_deterministic(now: Timestamp, seed: &[u8]) -> (SecretKey, Transactions, AdminKey) {
    let seed: [u8; 32] = Hash::new_blake3(seed).unwrap().as_bytes().try_into().unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let transactions = Transactions::new();
    let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
    let sign = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
    let admin = AdminKeypair::from(sign);
    let admin_key = AdminKey::new(admin, "Alpha", None);
    let policy = Policy::new(
        vec![Capability::Permissive],
        MultisigPolicy::MOfN {
            must_have: 1,
            participants: vec![admin_key.key().clone().into()],
        },
    );
    let trans = transactions
        .create_identity(&HashAlgo::Blake3, now, vec![admin_key.clone()], vec![policy])
        .unwrap()
        .sign(&master_key, &admin_key)
        .unwrap();
    let transactions2 = transactions.push_transaction(trans).unwrap();
    (master_key, transactions2, admin_key)
}

#[derive(Clone)]
pub struct TestNode {
    pub agent: Arc<Agent<libp2p::kad::store::MemoryStore>>,
    pub multiaddr: Multiaddr,
    pub peer_id: libp2p::PeerId,
    pub events: Arc<RwLock<mpsc::Receiver<Event>>>,
    pub num_ident: Arc<RwLock<usize>>,
}

pub fn spawn_nodes<F>(num: usize, addr_tpl: F, relay_mode: RelayMode, dht_mode: DHTMode) -> Arc<Vec<TestNode>>
where
    F: Fn(usize) -> String,
{
    let mut nodes = Vec::with_capacity(num);
    for i in 0..num {
        let mut peer_key_bytes = Vec::from(
            stamp_core::crypto::base::Hash::new_blake3(format!("peer {}", i).as_bytes())
                .unwrap()
                .as_bytes(),
        );
        let peer_id = libp2p::identity::Keypair::ed25519_from_bytes(&mut peer_key_bytes).unwrap();
        let peer_id_pub = libp2p::PeerId::from(peer_id.public());
        let store = agent::memory_store(&peer_id_pub);
        let (agent, events) = Agent::new(peer_id, store, relay_mode.clone(), dht_mode.clone()).unwrap();
        let multiaddr: Multiaddr = addr_tpl(i).as_str().parse().unwrap();
        let agent = Arc::new(agent);
        nodes.push(TestNode {
            agent,
            multiaddr,
            peer_id: peer_id_pub,
            events: Arc::new(RwLock::new(events)),
            num_ident: Arc::new(RwLock::new(0)),
        });
    }
    Arc::new(nodes)
}
