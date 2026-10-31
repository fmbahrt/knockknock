//! Joins a lobby, says hello to the host and waits for its greeting.
//!
//!     cargo run --example join -- <server-addr> <lobby-id> [name] [--stay]
//!
//! With `--stay` the player stays connected after the greeting (until
//! Ctrl-C), so the host keeps measuring and reporting the connection.

use std::env;
use std::process::ExitCode;
use std::time::Duration;

use knockknock::{Client, Event, LobbyId, ServerTrust, State};

fn main() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let stay = args.last().is_some_and(|a| a == "--stay");
    if stay {
        args.pop();
    }
    let (server, lobby, name) = match args.as_slice() {
        [server, lobby] => (server, lobby, "player"),
        [server, lobby, name] => (server, lobby, name.as_str()),
        _ => {
            eprintln!("usage: join <server-addr> <lobby-id> [name] [--stay]");
            return ExitCode::FAILURE;
        }
    };
    match run(server, lobby, name, stay) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[{name}] error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(
    server: &str,
    lobby: &str,
    name: &str,
    stay: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let lobby: LobbyId = lobby.parse()?;
    let mut client = Client::join(server, lobby, trust()?)?;
    let mut connected = false;

    loop {
        // Only time out while connecting; once connected, wait for the host.
        let timeout = (!connected).then_some(Duration::from_secs(15));
        let Some(event) = client.wait(timeout)? else {
            return Err("timed out".into());
        };
        match event {
            Event::Registered { observed, .. } => {
                println!("[{name}] registered, public endpoint {observed}")
            }
            Event::Session {
                id,
                state: State::Connected { addr },
            } => {
                println!("[{name}] connected to host via {addr}");
                connected = true;
                client.send(id, format!("hello from {name}").as_bytes())?;
            }
            Event::Session {
                state: State::Failed(reason),
                ..
            } => return Err(format!("failed: {reason:?}").into()),
            Event::Session {
                state: State::Closed,
                ..
            } => {
                println!("[{name}] host closed the session");
                return Ok(());
            }
            Event::Session { state, .. } => println!("[{name}] {state:?}"),
            Event::Data { data, .. } => {
                println!("[{name}] host says: {}", String::from_utf8_lossy(&data));
                if !stay {
                    client.close()?;
                    return Ok(());
                }
            }
            Event::ServerError(code) => return Err(format!("server: {code}").into()),
            Event::ServerLost => println!("[{name}] lost the rendezvous server; reconnecting"),
            Event::ServerRestored { .. } => println!("[{name}] back on the rendezvous server"),
        }
    }
}

/// Trusts the CA in `$KNOCKKNOCK_CA` (e.g. the server's generated dev CA), or
/// the public Web PKI roots if it is unset.
fn trust() -> std::io::Result<ServerTrust> {
    match std::env::var_os("KNOCKKNOCK_CA") {
        Some(path) => ServerTrust::ca_file(path),
        None => Ok(ServerTrust::PublicRoots),
    }
}
