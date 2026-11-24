//! Who the relay admits (7.3.10, FR-20, E27): in `private` mode only an endpoint that presents a valid relay key; in `public`
//! mode anyone, with a keyed endpoint's priority counting at capacity. A key is bound to the first `max_endpoints` endpoints
//! that use it. The relay serves at most 500 endpoints at once; past that, a keyed endpoint takes the place of one with a lower
//! priority, and one that can't is refused with the reason.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ed25519_dalek::VerifyingKey;
use iroh::EndpointId;
use iroh_relay::server::{Access, AccessControl, ClientRequest, ConnectionId};

use crate::keys::{self, Priority};

/// The endpoints a relay serves at once.
pub const CAPACITY: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Private,
    Public,
}

/// Ends the connections of a lower-priority endpoint to make room.
pub trait Evictor: Send + Sync + std::fmt::Debug {
    fn evict(&self, endpoint: EndpointId);
}

fn deny(why: &str) -> Access {
    Access::Deny { reason: Some(why.to_string()) }
}

#[derive(Debug, Default)]
struct State {
    /// Each admitted connection: whose, and with what priority.
    /// Each connection is named by the relay's id for it.
    live: HashMap<String, (EndpointId, Priority)>,
    /// The endpoints each key is bound to.
    bound: BTreeMap<String, Vec<String>>,
}

#[derive(Debug)]
pub struct Admission {
    mode: Mode,
    verifying: VerifyingKey,
    capacity: usize,
    state: Mutex<State>,
    evictor: Mutex<Option<Arc<dyn Evictor>>>,
    /// Where the bindings are kept, so a restart doesn't free a key's endpoints.
    bindings: Option<PathBuf>,
    now: fn() -> i64,
}

fn real_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

impl Admission {
    pub fn new(mode: Mode, verifying: VerifyingKey) -> Admission {
        Admission {
            mode,
            verifying,
            capacity: CAPACITY,
            state: Mutex::new(State::default()),
            evictor: Mutex::new(None),
            bindings: None,
            now: real_now,
        }
    }

    /// Keeps key bindings in `path` (read now, written when one changes).
    pub fn with_bindings(mut self, path: PathBuf) -> Admission {
        if let Some(bound) = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
            self.state.get_mut().unwrap_or_else(|e| e.into_inner()).bound = bound;
        }
        self.bindings = Some(path);
        self
    }

    pub fn with_capacity(mut self, capacity: usize) -> Admission {
        self.capacity = capacity;
        self
    }

    pub fn with_clock(mut self, now: fn() -> i64) -> Admission {
        self.now = now;
        self
    }

    /// What ends a connection to make room (the running server's `RelayService`).
    pub fn set_evictor(&self, evictor: Arc<dyn Evictor>) {
        *self.evictor.lock().unwrap_or_else(|e| e.into_inner()) = Some(evictor);
    }

    pub fn connected(&self) -> usize {
        self.state.lock().map_or(0, |s| s.live.len())
    }

    fn save(&self, bound: &BTreeMap<String, Vec<String>>) {
        if let Some(path) = &self.bindings
            && let Ok(bytes) = serde_json::to_vec(bound)
        {
            let _ = std::fs::write(path, bytes);
        }
    }

    /// The decision for one connection.
    pub fn decide(&self, endpoint: EndpointId, connection: &str, token: Option<&str>) -> Access {
        let now = (self.now)();
        let (priority, name, max) = match token {
            Some(t) => match keys::verify(&self.verifying, t, now) {
                Ok(body) => (body.priority, Some(body.name), body.max_endpoints),
                Err(e) => return deny(&e.to_string()),
            },
            None if self.mode == Mode::Private => {
                return deny("this relay admits only endpoints with a relay key");
            }
            None => (Priority::None, None, 0),
        };
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(name) = &name {
            let id = endpoint.to_string();
            let bound = state.bound.entry(name.clone()).or_default();
            if !bound.contains(&id) {
                if bound.len() >= max as usize {
                    return deny("the relay key is already used by the most endpoints it allows");
                }
                bound.push(id);
                let snapshot = state.bound.clone();
                self.save(&snapshot);
            }
        }
        if state.live.len() >= self.capacity {
            // the lowest priority there is, if the newcomer outranks it
            let lowest = state.live.iter().min_by_key(|(_, (_, p))| *p).map(|(c, (e, p))| (c.clone(), *e, *p));
            match lowest {
                Some((c, e, p)) if priority > p => {
                    state.live.remove(&c);
                    let evictor = self.evictor.lock().ok().and_then(|e| e.clone());
                    drop(state);
                    if let Some(evictor) = evictor {
                        evictor.evict(e);
                    }
                    state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                }
                _ => return deny("the relay is full; keyed endpoints are admitted first"),
            }
        }
        state.live.insert(connection.to_string(), (endpoint, priority));
        Access::Allow
    }
}

impl AccessControl for Admission {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        self.decide(request.endpoint_id(), &request.connection_id().to_string(), request.auth_token().as_deref())
    }

    fn on_disconnect(&self, _endpoint_id: EndpointId, connection_id: ConnectionId) {
        if let Ok(mut state) = self.state.lock() {
            state.live.remove(&connection_id.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::keys::KeyBody;

    fn signing() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn endpoint(n: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[n; 32]).public()
    }

    fn token(name: &str, priority: Priority, max: u32, expires: i64) -> String {
        keys::create(&signing(), &KeyBody { name: name.into(), priority, max_endpoints: max, expires_ms: expires })
    }

    fn admission(mode: Mode) -> Admission {
        // the clock stands at 1 000 ms: tokens are made to expire before or after it
        Admission::new(mode, signing().verifying_key()).with_clock(|| 1_000)
    }

    fn conn(n: u64) -> String {
        format!("c{n}")
    }

    fn allowed(a: &Access) -> bool {
        matches!(a, Access::Allow)
    }

    fn why(a: &Access) -> String {
        match a {
            Access::Deny { reason } => reason.clone().unwrap_or_default(),
            Access::Allow => String::new(),
        }
    }

    #[test]
    fn private_refuses_unkeyed_admits_keyed() {
        let a = admission(Mode::Private);
        let unkeyed = a.decide(endpoint(1), &conn(1), None);
        assert!(!allowed(&unkeyed) && why(&unkeyed).contains("only endpoints with a relay key"), "{unkeyed:?}");
        let keyed = a.decide(endpoint(1), &conn(2), Some(&token("home", Priority::Normal, 1, 9_999)));
        assert!(allowed(&keyed), "{keyed:?}");
        // a forged token and an expired one are refused, in either mode, and say why
        let forged = a.decide(endpoint(2), &conn(3), Some("rk1.e30.AAAA"));
        assert!(!allowed(&forged) && why(&forged).contains("isn't one of this relay's"), "{forged:?}");
        let expired = a.decide(endpoint(2), &conn(4), Some(&token("old", Priority::Normal, 1, 500)));
        assert!(!allowed(&expired) && why(&expired).contains("expired"), "{expired:?}");
        let open = admission(Mode::Public);
        assert!(allowed(&open.decide(endpoint(3), &conn(5), None)), "public admits anyone");
        assert!(!allowed(&open.decide(endpoint(3), &conn(6), Some("rk1.e30.AAAA"))), "but not a forged key");
    }

    #[test]
    fn token_signed_by_relay_and_bound_to_max_endpoints() {
        let a = admission(Mode::Private);
        let two = token("pair", Priority::Normal, 2, 9_999);
        assert!(allowed(&a.decide(endpoint(1), &conn(1), Some(&two))));
        assert!(allowed(&a.decide(endpoint(2), &conn(2), Some(&two))));
        let third = a.decide(endpoint(3), &conn(3), Some(&two));
        assert!(!allowed(&third) && why(&third).contains("most endpoints it allows"), "{third:?}");
        // a bound endpoint may connect again (a reconnect), and another key has its own endpoints
        assert!(allowed(&a.decide(endpoint(1), &conn(4), Some(&two))));
        assert!(allowed(&a.decide(endpoint(3), &conn(5), Some(&token("other", Priority::Normal, 1, 9_999)))));
    }

    #[derive(Debug, Default)]
    struct Evicted(Mutex<Vec<EndpointId>>);

    impl Evictor for Evicted {
        fn evict(&self, endpoint: EndpointId) {
            self.0.lock().unwrap().push(endpoint);
        }
    }

    #[test]
    fn priority_admission_at_capacity() {
        let a = admission(Mode::Public).with_capacity(3);
        let evicted = Arc::new(Evicted::default());
        a.set_evictor(evicted.clone());
        // three unkeyed fill it; a further unkeyed one is refused and told why
        for n in 1..=3 {
            assert!(allowed(&a.decide(endpoint(n), &conn(n as u64), None)));
        }
        let full = a.decide(endpoint(4), &conn(4), None);
        assert!(!allowed(&full) && why(&full).contains("full"), "{full:?}");
        // a normal key takes an unkeyed endpoint's place, a high key takes the next, and then none is left to take
        assert!(allowed(&a.decide(endpoint(5), &conn(5), Some(&token("n", Priority::Normal, 1, 9_999)))));
        assert!(allowed(&a.decide(endpoint(6), &conn(6), Some(&token("h", Priority::High, 1, 9_999)))));
        assert_eq!(evicted.0.lock().unwrap().len(), 2, "two unkeyed endpoints made room");
        assert!(
            allowed(&a.decide(endpoint(7), &conn(7), Some(&token("h2", Priority::High, 1, 9_999)))),
            "the last unkeyed one goes too"
        );
        let again = a.decide(endpoint(8), &conn(8), Some(&token("n2", Priority::Normal, 1, 9_999)));
        assert!(!allowed(&again), "a normal key can't take a high key's place: {again:?}");
        assert_eq!(a.connected(), 3);
    }

    #[test]
    fn bindings_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("rackhand-relay-bind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bindings.json");
        let one = token("one", Priority::Normal, 1, 9_999);
        let a = admission(Mode::Private).with_bindings(path.clone());
        assert!(allowed(&a.decide(endpoint(1), &conn(1), Some(&one))));
        let restarted = admission(Mode::Private).with_bindings(path);
        assert!(
            !allowed(&restarted.decide(endpoint(2), &conn(2), Some(&one))),
            "the key's endpoint is still the first"
        );
        assert!(allowed(&restarted.decide(endpoint(1), &conn(3), Some(&one))));
    }
}
