use rand::SeedableRng;
use stamp_core::{
    crypto::base::{Hash, HashAlgo, SecretKey, SignKeypair},
    dag::Transactions,
    identity::keychain::{AdminKey, AdminKeypair},
    policy::{Capability, MultisigPolicy, Policy},
    util::Timestamp,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

macro_rules! wait_on_event {
    ($rx:ident, $ev:pat_param) => {
        loop {
            match $rx.recv().await {
                Some($ev) => {
                    break;
                }
                _ => {}
            }
        }
    };
}
pub(crate) use wait_on_event;

pub fn setup() {
    tracing_subscriber::registry()
        .with(fmt::layer().with_span_events(fmt::format::FmtSpan::CLOSE))
        .with(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("info"))
                .unwrap(),
        )
        .try_init()
        .unwrap_or_else(|_| ())
}

pub fn create_sync_keys(seed: &[u8]) -> (SecretKey, SecretKey, SignKeypair) {
    let seed: [u8; 32] = Hash::new_blake3(seed)
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let shared_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
    let secret_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
    let sign_key = SignKeypair::new_ed25519(&mut rng, &secret_key).unwrap();
    (shared_key, secret_key, sign_key)
}

pub fn create_fake_identity_deterministic(
    now: Timestamp,
    seed: &[u8],
) -> (SecretKey, Transactions, AdminKey) {
    let seed: [u8; 32] = Hash::new_blake3(seed)
        .unwrap()
        .as_bytes()
        .try_into()
        .unwrap();
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
        .create_identity(
            &HashAlgo::Blake3,
            now,
            vec![admin_key.clone()],
            vec![policy],
        )
        .unwrap()
        .sign(&master_key, &admin_key)
        .unwrap();
    let transactions2 = transactions.push_transaction(trans).unwrap();
    (master_key, transactions2, admin_key)
}
