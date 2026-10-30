//! Opens a lobby, greets every player that joins, and prints path stats.
//!
//!     cargo run --example host -- <server-addr> [players]
//!
//! Exits after `players` joiners have said hello (default: run forever).

use std::env;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use knockknock::{Client, Event, ServerTrust, SessionId, State};

const STATS_EVERY: Duration = Duration::from_secs(5);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (server, players) = match args.as_slice() {
        [server] => (server, None),
        [server, n] => match n.parse() {
            Ok(n) => (server, Some(n)),
            Err(_) => return usage(),
        },
        _ => return usage(),
    };
    match run(server, players) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[host] error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: host <server-addr> [players]");
    ExitCode::FAILURE
}

fn run(server: &str, players: Option<usize>) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::host(server, trust()?)?;
    let mut greeted = 0;
    let mut sessions: Vec<SessionId> = Vec::new();
    let mut next_stats = Instant::now() + STATS_EVERY;

    while players.is_none_or(|n| greeted < n) {
        match client.wait(Some(next_stats.saturating_duration_since(Instant::now())))? {
            Some(Event::Registered {
                lobby: Some(lobby),
                observed,
            }) => {
                println!("[host] lobby {lobby} (public endpoint {observed})");
            }
            Some(Event::Session {
                id,
                state: State::Connected { addr },
            }) => {
                println!("[host] session {id:016x} connected via {addr}");
                if !sessions.contains(&id) {
                    sessions.push(id);
                }
                client.send(id, b"welcome to the lobby")?;
            }
            Some(Event::Session { id, state }) => {
                println!("[host] session {id:016x}: {state:?}");
                if matches!(state, State::Failed(_) | State::Closed) {
                    sessions.retain(|&s| s != id);
                }
            }
            Some(Event::Data { session, data }) => {
                println!(
                    "[host] {session:016x} says: {}",
                    String::from_utf8_lossy(&data)
                );
                greeted += 1;
            }
            Some(Event::ServerError(code)) => eprintln!("[host] server error: {code}"),
            Some(Event::ServerLost) => eprintln!("[host] lost the rendezvous server"),
            Some(Event::Registered { .. }) | None => {}
        }

        if Instant::now() >= next_stats {
            next_stats += STATS_EVERY;
            for &id in &sessions {
                if let Some(st) = client.stats(id) {
                    let ms = |d: Option<Duration>| {
                        d.map_or("-".into(), |d| format!("{:.1}ms", d.as_secs_f64() * 1e3))
                    };
                    println!(
                        "[host] {id:016x}: rtt {} jitter {} loss {:.0}%",
                        ms(st.rtt),
                        ms(st.jitter),
                        st.loss * 100.0
                    );
                }
            }
        }
    }
    client.close()?;
    Ok(())
}

/// Trusts the CA in `$KNOCKKNOCK_CA` (e.g. the server's generated dev CA), or
/// the public Web PKI roots if it is unset.
fn trust() -> std::io::Result<ServerTrust> {
    match std::env::var_os("KNOCKKNOCK_CA") {
        Some(path) => ServerTrust::ca_file(path),
        None => Ok(ServerTrust::PublicRoots),
    }
}
