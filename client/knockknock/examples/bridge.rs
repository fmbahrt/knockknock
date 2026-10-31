//! Drives a knockknock client over stdin/stdout, so other programs (like
//! `scripts/datatest.py`) can test real connections without bindings.
//!
//!     bridge <server-addr> host
//!     bridge <server-addr> join <lobby-id>
//!
//! Set `KNOCKKNOCK_CA` to a CA file to trust (e.g. the server's dev CA).
//!
//! Output, one event per line (session IDs are 16 hex digits):
//!
//!     registered <observed-endpoint> <lobby-id or ->
//!     state <session> connecting|connected <addr>|disconnected|failed <reason>|closed
//!     data <session> <hex payload>
//!     stats <session> <rtt-ms or -> <jitter-ms or -> <loss 0..1>
//!     error <message>
//!
//! Input, one command per line:
//!
//!     send <session or *> <hex payload>   (* = every connected session)
//!     stats                               (prints a stats line per session)
//!     close                               (closes everything and exits; so does EOF)

use std::env;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use knockknock::{Client, Event, LobbyId, ServerTrust, SessionId, State};

/// How long to block on the network before checking for commands. Adds up
/// to this much latency to sends issued over stdin.
const POLL: Duration = Duration::from_millis(1);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [server, "host"] => connect(server, None),
        [server, "join", lobby] => connect(server, Some(lobby)),
        _ => {
            eprintln!("usage: bridge <server-addr> host | bridge <server-addr> join <lobby-id>");
            return ExitCode::FAILURE;
        }
    };
    match result.and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            println!("error {e}");
            ExitCode::FAILURE
        }
    }
}

fn connect(server: &str, lobby: Option<&str>) -> Result<Client, Box<dyn std::error::Error>> {
    Ok(match lobby {
        None => Client::host(server, trust()?)?,
        Some(lobby) => Client::join(server, lobby.parse::<LobbyId>()?, trust()?)?,
    })
}

fn run(mut client: Client) -> Result<(), Box<dyn std::error::Error>> {
    let (tx, commands) = mpsc::channel();
    thread::spawn(move || {
        for line in io::stdin().lock().lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
        let _ = tx.send("close".into());
    });

    let mut out = io::stdout().lock();
    let mut connected: Vec<SessionId> = Vec::new();
    loop {
        // Flushed once per batch below: a flush per event costs a syscall each.
        while let Some(event) = client.wait(Some(POLL))? {
            print_event(&mut out, &event, &mut connected)?;
        }
        while let Ok(line) = commands.try_recv() {
            let mut words = line.split_whitespace();
            match (words.next(), words.next(), words.next()) {
                (Some("send"), Some(target), payload) => {
                    let Some(data) = decode_hex(payload.unwrap_or("")) else {
                        writeln!(out, "error bad hex payload")?;
                        continue;
                    };
                    let targets = match target {
                        "*" => connected.clone(),
                        id => match SessionId::from_str_radix(id, 16) {
                            Ok(id) => vec![id],
                            Err(_) => {
                                writeln!(out, "error bad session id {id}")?;
                                continue;
                            }
                        },
                    };
                    for id in targets {
                        if let Err(e) = client.send(id, &data) {
                            writeln!(out, "error send {id:016x}: {e}")?;
                        }
                    }
                }
                (Some("stats"), None, None) => {
                    for &id in &connected {
                        if let Some(st) = client.stats(id) {
                            let ms = |d: Option<Duration>| {
                                d.map_or("-".into(), |d| format!("{:.3}", d.as_secs_f64() * 1e3))
                            };
                            writeln!(
                                out,
                                "stats {id:016x} {} {} {:.3}",
                                ms(st.rtt),
                                ms(st.jitter),
                                st.loss
                            )?;
                        }
                    }
                }
                (Some("close"), None, None) => {
                    client.close()?;
                    return Ok(());
                }
                _ => writeln!(out, "error unknown command: {line}")?,
            }
        }
        out.flush()?;
    }
}

fn print_event(
    out: &mut impl Write,
    event: &Event,
    connected: &mut Vec<SessionId>,
) -> io::Result<()> {
    match event {
        Event::Registered { observed, lobby } => {
            let lobby = lobby.map_or("-".into(), |l| l.to_string());
            writeln!(out, "registered {observed} {lobby}")?;
        }
        Event::Session { id, state } => {
            connected.retain(|s| s != id);
            let state = match state {
                State::Connected { addr } => {
                    connected.push(*id);
                    format!("connected {addr}")
                }
                State::Failed(reason) => format!("failed {reason:?}"),
                other => format!("{other:?}").to_lowercase(),
            };
            writeln!(out, "state {id:016x} {state}")?;
        }
        Event::Data { session, data } => writeln!(out, "data {session:016x} {}", encode_hex(data))?,
        Event::ServerError(code) => writeln!(out, "error server: {code}")?,
        Event::ServerLost => writeln!(out, "error server connection lost")?,
        Event::ServerRestored { lobby } => {
            let lobby = lobby.map_or("-".into(), |l| l.to_string());
            writeln!(out, "restored {lobby}")?;
        }
    }
    Ok(())
}

fn encode_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Trusts the CA in `$KNOCKKNOCK_CA` (e.g. the server's generated dev CA), or
/// the public Web PKI roots if it is unset.
fn trust() -> std::io::Result<ServerTrust> {
    match std::env::var_os("KNOCKKNOCK_CA") {
        Some(path) => ServerTrust::ca_file(path),
        None => Ok(ServerTrust::PublicRoots),
    }
}
