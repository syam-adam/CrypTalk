mod auth;
mod client;
mod server;

use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [server|client]", args[0]);
        return;
    }

    match args[1].as_str() {
        "server" => server::run_server().await,
        "client" => client::run_client().await,
        _ => eprintln!("Invalid argument. use 'server' or 'client'."),
    }
}
