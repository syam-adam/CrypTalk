use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Local;
use std::collections::HashMap;
use std::env;
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::auth::Auth;

const SHARED_KEY: &[u8; 32] = b"anexampleverysecurekey123456780!";
const NONCE: &[u8; 12] = b"unique_nonce";

pub fn encrypt_msg(msg: &str) -> String {
    let key = Key::<Aes256Gcm>::from_slice(SHARED_KEY);
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(NONCE), msg.as_bytes())
        .expect("encryption failure!");
    STANDARD.encode(ciphertext)
}

pub fn decrypt_msg(data: &[u8]) -> Option<String> {
    let key = Key::<Aes256Gcm>::from_slice(SHARED_KEY);
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(Nonce::from_slice(NONCE), data)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

fn should_log() -> bool {
    env::var("SERVER_LOGGING")
        .map(|val| val == "true")
        .unwrap_or(false)
}

fn log_message(msg: &str) {
    let timestamped = format!(
        "{} {}",
        format!("[{}]", Local::now().format("%Y-%m-%d %H:%M:%S")),
        msg
    );
    println!("{}", timestamped);

    if let Ok(mut file) = OpenOptions::new()
        .append(true)
        .create(true)
        .open("server_log.txt")
    {
        let _ = writeln!(file, "{}", msg);
    }
}

pub async fn run_server() {
    let listener = TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("Failed to bind");
    println!("[server] Listening on 127.0.0.1:8080");

    let auth = Arc::new(Mutex::new(Auth::new()));
    let clients = Arc::new(Mutex::new(HashMap::new()));

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let auth = Arc::clone(&auth);
                let clients = Arc::clone(&clients);
                tokio::spawn(async move {
                    handle_client(stream, auth, clients).await;
                });
            }
            Err(e) => eprintln!("[server] Failed to accept: {}", e),
        }
    }
}

async fn handle_client(
    stream: TcpStream,
    auth: Arc<Mutex<Auth>>,
    clients: Arc<Mutex<HashMap<String, Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>>>>,
) {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let writer = Arc::new(Mutex::new(writer));

    // 1. Login/signup (plaintext)
    let mut username = String::new();
    let mut buffer = String::new();

    loop {
        // Prompt username
        username.clear();
        {
            let mut writer_guard = writer.lock().await;
            writer_guard.write_all(b"Username: \n").await.unwrap();
            writer_guard.flush().await.unwrap();
        }
        reader.read_line(&mut username).await.unwrap();
        let username = username.trim().to_string();

        // Prompt new user or not
        {
            let mut writer_guard = writer.lock().await;
            writer_guard
                .write_all(b"Are you a new user? (y/n): \n")
                .await
                .unwrap();
            writer_guard.flush().await.unwrap();
        }
        buffer.clear();
        reader.read_line(&mut buffer).await.unwrap();
        let is_new = buffer.trim().eq_ignore_ascii_case("y");

        // Prompt password
        {
            let mut writer_guard = writer.lock().await;
            if writer_guard.write_all(b"Password: \n").await.is_err()
                || writer_guard.flush().await.is_err()
            {
                eprintln!(
                    "[server] Write failed during password prompt for {}",
                    username
                );
                clients.lock().await.remove(&username);
                return; // exit handler early
            }
        }
        buffer.clear();
        reader.read_line(&mut buffer).await.unwrap();
        let password = buffer.trim();

        // Auth check
        let mut auth_guard = auth.lock().await;
        let auth_result = if is_new {
            auth_guard.signup(&username, password)
        } else {
            auth_guard.login(&username, password)
        };

        if let Err(err) = auth_result {
            writer
                .lock()
                .await
                .write_all(format!("[auth] Error: {}\n", err).as_bytes())
                .await
                .unwrap();
            continue;
        }

        let welcome_string = format!(
            "✅ Welcome, {}! Connected to chat. Type `help` to see available commands.\n",
            username
        );
        let welcome_msg = welcome_string.as_bytes();
        // Success
        writer.lock().await.write_all(welcome_msg).await.unwrap();

        break;
    }

    let username = username.trim().to_string();
    
    clients
        .lock()
        .await
        .insert(username.clone(), writer.clone());

    println!("[server] {} connected", username);
    // 2. Now handle encrypted chat commands
    let mut reader_lines = reader.lines();
    while let Ok(Some(line)) = reader_lines.next_line().await {
        // decrypt message or use plaintext if failed
        let decrypted = match STANDARD.decode(&line) {
            Ok(bytes) => decrypt_msg(&bytes),
            Err(_) => None,
        };
        let trimmed = decrypted.unwrap_or_else(|| line.clone()).trim().to_string();

        if should_log() {
            log_message(&format!("[{}] {}", username, trimmed));
        }
        // commands without leading slash:
        if trimmed.starts_with("msg ") {
            let parts: Vec<&str> = trimmed[4..].splitn(2, ' ').collect();
            if parts.len() != 2 {
                send_to_user(
                    &username,
                    &encrypt_msg("Usage: msg <user> <message>"),
                    &clients,
                )
                .await;
                continue;
            }
            let to_user = parts[0];
            let message = parts[1];
            let msg = format!("[{} -> you]: {}", username, message);
            if send_to_user(to_user, &encrypt_msg(&msg), &clients).await {
                // ✅ Let sender know it was sent
                send_to_user(
                    &username,
                    &encrypt_msg(&format!("✅ Message sent to {}", to_user)),
                    &clients,
                )
                .await;
            } else {
                send_to_user(
                    &username,
                    &encrypt_msg("❌ User not found or offline."),
                    &clients,
                )
                .await;
            }
        } else if trimmed.starts_with("broadcast ") {
            let msg = format!("[{} -> all]: {}", username, &trimmed[10..]);
            broadcast_message(&username, &encrypt_msg(&msg), &clients).await;
            send_to_user(
                &username,
                &encrypt_msg("✅ Broadcast message sent to all users"),
                &clients,
            )
            .await;
        } else if trimmed == "list" {
            let list = clients
                .lock()
                .await
                .keys()
                .filter(|u| *u != &username)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            send_to_user(
                &username,
                &encrypt_msg(&format!("Online users: {}", list)),
                &clients,
            )
            .await;
        } else if trimmed == "help" {
            let help_msg = "
                Available Commands:
                msg <user> <message>      - Send a private message to a specific user
                broadcast <message>       - Send a message to all online users
                list                      - View all online users
                help                      - Show this help message
                quit                      - Disconnect from the chat
                ";

            send_to_user(&username, &encrypt_msg(help_msg), &clients).await;
        } else if trimmed == "quit" {
            send_to_user(&username, &encrypt_msg("Goodbye!"), &clients).await;
            break;
        } else {
            send_to_user(
                &username,
                &encrypt_msg("Unknown command. Use help."),
                &clients,
            )
            .await;
        }
    }

    clients.lock().await.remove(&username);
    println!("[server] {} disconnected", username);
}

async fn send_to_user(
    username: &str,
    msg: &str,
    clients: &Arc<Mutex<HashMap<String, Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>>>>,
) -> bool {
    if let Some(writer_arc) = clients.lock().await.get(username) {
        let mut writer = writer_arc.lock().await;
        let _ = writer.write_all(format!("{}\n", msg).as_bytes()).await;
        let _ = writer.flush().await;
        true
    } else {
        false
    }
}

async fn broadcast_message(
    from_user: &str,
    msg: &str,
    clients: &Arc<Mutex<HashMap<String, Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>>>>,
) {
    let clients_guard = clients.lock().await;
    for (user, writer_arc) in clients_guard.iter() {
        if user != from_user {
            let mut writer = writer_arc.lock().await;
            let _ = writer.write_all(format!("{}\n", msg).as_bytes()).await;
            let _ = writer.flush().await;
        }
    }
}
