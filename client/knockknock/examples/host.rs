//! Opens a lobby and greets every player that joins.
//!
//!     cargo run --example host -- <server-addr> [players]
//!
//! Exits after `players` joiners have said hello (default: run forever).

use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;

use knockknock::{Client, Event, State};

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
    let server: SocketAddr = server
        .to_socket_addrs()?
        .next()
        .ok_or("server address did not resolve")?;
    let mut client = Client::host(server)?;
    let mut greeted = 0;

    while players.is_none_or(|n| greeted < n) {
        match client.wait(None)? {
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
                client.send(id, b"welcome to the lobby")?;
            }
            Some(Event::Session { id, state }) => println!("[host] session {id:016x}: {state:?}"),
            Some(Event::Data { session, data }) => {
                println!(
                    "[host] {session:016x} says: {}",
                    String::from_utf8_lossy(&data)
                );
                greeted += 1;
            }
            Some(Event::ServerError(code)) => eprintln!("[host] server error: {code}"),
            Some(Event::Registered { .. }) | None => {}
        }
    }
    client.close()?;
    Ok(())
}
