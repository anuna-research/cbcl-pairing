//! Bounded admission and transport work shared by both reference shells.
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const CONNECTION_CAP: usize = 256;
const PEER_CONNECTION_CAP: usize = 8;
const PEER_CAP: usize = 4096;
const INPUT_BUDGET: u32 = 480;
const WINDOW: Duration = Duration::from_secs(60);
const FIRST_DEADLINE: Duration = Duration::from_secs(5);
const IDLE_DEADLINE: Duration = Duration::from_secs(30);

struct Entry {
    peer: IpAddr,
    socket: TcpStream,
    deadline: Instant,
}
#[derive(Default)]
struct State {
    next: u64,
    connections: BTreeMap<u64, Entry>,
    budgets: BTreeMap<IpAddr, (Instant, u32)>,
}
#[derive(Clone)]
pub struct Admission(Arc<Mutex<State>>);

impl Admission {
    pub fn new() -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let weak = Arc::downgrade(&state);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(250));
            let Some(state) = weak.upgrade() else { break };
            let Ok(state) = state.lock() else { break };
            for entry in state.connections.values() {
                if Instant::now() >= entry.deadline {
                    let _ = entry.socket.shutdown(Shutdown::Both);
                }
            }
        });
        Self(state)
    }

    pub fn admit(&self, stream: TcpStream) -> io::Result<BudgetStream> {
        let peer = match stream.peer_addr()?.ip() {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
                || {
                    let prefix = u128::from(ip) & (u128::MAX << 64);
                    IpAddr::V6(prefix.into())
                },
                IpAddr::V4,
            ),
            ip => ip,
        };
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("admission lock"))?;
        if state.connections.len() >= CONNECTION_CAP
            || state
                .connections
                .values()
                .filter(|entry| entry.peer == peer)
                .count()
                >= PEER_CONNECTION_CAP
            || !charge(&mut state, peer, Instant::now())
        {
            eprintln!(
                "relay_connection outcome=rejected active={}",
                state.connections.len()
            );
            return Err(io::Error::other("connection budget"));
        }
        stream.set_read_timeout(Some(FIRST_DEADLINE))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let socket = stream.try_clone()?;
        let id = state.next;
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("connection ids exhausted"))?;
        state.connections.insert(
            id,
            Entry {
                peer,
                socket,
                deadline: Instant::now() + FIRST_DEADLINE,
            },
        );
        eprintln!(
            "relay_connection outcome=accepted active={}",
            state.connections.len()
        );
        Ok(BudgetStream {
            stream,
            admission: self.clone(),
            id,
            peer,
            write_started: None,
        })
    }
}

fn charge(state: &mut State, peer: IpAddr, now: Instant) -> bool {
    state
        .budgets
        .retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
    if !state.budgets.contains_key(&peer) && state.budgets.len() >= PEER_CAP {
        return false;
    }
    let (_, used) = state.budgets.entry(peer).or_insert((now, 0));
    if *used >= INPUT_BUDGET {
        return false;
    }
    *used += 1;
    true
}

pub struct BudgetStream {
    pub stream: TcpStream,
    admission: Admission,
    id: u64,
    peer: IpAddr,
    write_started: Option<Instant>,
}
impl BudgetStream {
    pub fn charge(&self) -> io::Result<()> {
        let mut state = self
            .admission
            .0
            .lock()
            .map_err(|_| io::Error::other("admission lock"))?;
        if charge(&mut state, self.peer, Instant::now()) {
            Ok(())
        } else {
            Err(io::Error::other("input budget exhausted"))
        }
    }
    pub fn progress(&self) {
        if let Ok(mut state) = self.admission.0.lock() {
            if let Some(entry) = state.connections.get_mut(&self.id) {
                // An expired connection cannot be revived by a late message.
                if Instant::now() < entry.deadline {
                    entry.deadline = Instant::now() + IDLE_DEADLINE;
                }
            }
        }
    }
}
impl Read for BudgetStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.stream.read(buffer)?;
        if count != 0 {
            self.charge()?;
        }
        Ok(count)
    }
}
impl Write for BudgetStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let start = *self.write_started.get_or_insert_with(Instant::now);
        let remaining = Duration::from_secs(2)
            .checked_sub(start.elapsed())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| io::Error::other("write deadline"))?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(buffer).map_err(|error| {
            let _ = self.stream.shutdown(Shutdown::Both);
            // Distinguish failed writes from the WebSocket read polling timeout.
            io::Error::other(error)
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()?;
        self.write_started = None;
        Ok(())
    }
}
impl Drop for BudgetStream {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
        if let Ok(mut state) = self.admission.0.lock() {
            state.connections.remove(&self.id);
            eprintln!(
                "relay_connection outcome=closed active={}",
                state.connections.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonreading_peer_cannot_hold_a_writer_indefinitely() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let admission = Admission::new();
        let mut socket = admission.admit(socket).unwrap();
        let started = Instant::now();
        assert!(socket.write_all(&vec![0; 32 * 1024 * 1024]).is_err());
        assert!(started.elapsed() < Duration::from_secs(4));
        drop(socket);
        assert!(admission.0.lock().unwrap().connections.is_empty());
    }

    #[test]
    fn peer_budget_survives_connections_and_fails_closed_at_capacity() {
        let mut state = State::default();
        let peer = "127.0.0.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..INPUT_BUDGET {
            assert!(charge(&mut state, peer, now));
        }
        assert!(!charge(&mut state, peer, now));
        assert!(charge(&mut state, peer, now + WINDOW));
        for index in 1..PEER_CAP as u32 {
            assert!(charge(&mut state, IpAddr::V4(index.into()), now + WINDOW));
        }
        assert!(!charge(
            &mut state,
            "192.0.2.1".parse().unwrap(),
            now + WINDOW
        ));
        assert!(!charge(
            &mut state,
            "192.0.2.1".parse().unwrap(),
            now + WINDOW
        ));
    }
}
