//! Joins a lobby, says hello to the host and waits for its greeting.
//!
//!     cargo run --example join -- <server-addr> <lobby-id> [name]

use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::time::Duration;

use knockknock::{Client, Event, LobbyId, State};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (server, lobby, name) = match args.as_slice() {
        [server, lobby] => (server, lobby, "player"),
        [server, lobby, name] => (server, lobby, name.as_str()),
        _ => {
            eprintln!("usage: join <server-addr> <lobby-id> [name]");
            return ExitCode::FAILURE;
        }
    };
    match run(server, lobby, name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[{name}] error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(server: &str, lobby: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let server: SocketAddr = server
        .to_socket_addrs()?
        .next()
        .ok_or("server address did not resolve")?;
    let lobby: LobbyId = lobby.parse()?;
    let mut client = Client::join(server, lobby)?;

    loop {
        let Some(event) = client.wait(Some(Duration::from_secs(15)))? else {
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
                client.send(id, format!("hello from {name}").as_bytes())?;
            }
            Event::Session {
                state: State::Failed(reason),
                ..
            } => return Err(format!("failed: {reason:?}").into()),
            Event::Session { state, .. } => println!("[{name}] {state:?}"),
            Event::Data { data, .. } => {
                println!("[{name}] host says: {}", String::from_utf8_lossy(&data));
                client.close()?;
                return Ok(());
            }
            Event::ServerError(code) => return Err(format!("server: {code}").into()),
        }
    }
}
