use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Local;
use colored::*;
use std::fs::OpenOptions;
use std::io;
use std::io::Write as IoWrite;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;

const SHARED_KEY: &[u8; 32] = b"anexampleverysecurekey123456780!";
const NONCE: &[u8; 12] = b"unique_nonce";

pub fn encrypt_msg(msg: &str) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(SHARED_KEY);
    let cipher = Aes256Gcm::new(key);
    cipher
        .encrypt(Nonce::from_slice(NONCE), msg.as_bytes())
        .expect("encryption failure!")
}

pub fn decrypt_msg(data: &[u8]) -> String {
    let key = Key::<Aes256Gcm>::from_slice(SHARED_KEY);
    let cipher = Aes256Gcm::new(key);
    let decrypted = cipher
        .decrypt(Nonce::from_slice(NONCE), data)
        .expect("decryption failure!");
    String::from_utf8(decrypted).expect("invalid UTF-8")
}

fn log_to_file(username: &str, line: &str) {
    if !std::env::var("CLIENT_CHAT_LOGGING")
        .map(|val| val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return; // Logging disabled ✅
    }

    let file_path = format!("{}_chat_log.txt", username);
    if let Ok(mut file) = OpenOptions::new().append(true).create(true).open(file_path) {
        let _ = writeln!(file, "{}", line);
    }
}

fn timestamp() -> String {
    format!("[{}]", Local::now().format("%Y-%m-%d %H:%M:%S"))
}

fn enrich_with_emojis(msg: &str) -> String {
    msg.replace(":)", "😊")
        .replace(":(", "😢")
        .replace(":D", "😄")
        .replace("<3", "❤️")
        .replace(":o", "😲")
        .replace(":thumbsup:", "👍")
}

pub async fn run_client() {
    loop {
        let should_reconnect = run_client_once().await;

        if !should_reconnect {
            println!("👋 Exiting chat. Goodbye!");
            break;
        }

        println!("🔁 Reconnecting to chat...\n");
    }
}

pub async fn run_client_once() -> bool {
    let stream = match TcpStream::connect("127.0.0.1:8080").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to connect: {}", e);
            return false;
        }
    };

    println!("[client] Connected to 127.0.0.1:8080");

    let (reader, writer) = stream.into_split();
    let mut server_reader = BufReader::new(reader);
    let mut server_writer = BufWriter::new(writer);
    let mut server_response = String::new();
    let mut username = String::new();

    // === LOGIN / SIGNUP ===
    loop {
        server_response.clear();
        if server_reader.read_line(&mut server_response).await.unwrap() == 0 {
            println!("Connection closed by server.");
            return false;
        }

        print!("{}", server_response);
        io::stdout().flush().unwrap();

        if server_response.contains("Connected to chat") || server_response.contains("[auth] Error")
        {
            break;
        }

        let mut user_input = String::new();
        io::stdin().read_line(&mut user_input).unwrap();

        if username.is_empty() {
            username = user_input.trim().to_string();
        }

        server_writer
            .write_all(user_input.as_bytes())
            .await
            .unwrap();
        server_writer.flush().await.unwrap();
    }

    // === SPAWN SERVER READER TASK ===
    let mut server_lines = server_reader.lines();
    let uname_clone = username.clone();
    let read_handle = tokio::spawn(async move {
        while let Ok(Some(line)) = server_lines.next_line().await {
            let plain = match STANDARD.decode(&line) {
                Ok(bytes) => decrypt_msg(&bytes),
                Err(_) => line.clone(), // fallback
            };

            let timestamped = format!("{} {}", timestamp(), plain);
            let emoji_line = enrich_with_emojis(&timestamped);

            log_to_file(&uname_clone, &emoji_line);

            if emoji_line.contains("-> all") {
                println!("{}", emoji_line.blue());
            } else if emoji_line.contains("-> you") {
                println!("{}", emoji_line.green());
            } else {
                println!("{}", emoji_line);
            }

            print!("=> ");
            io::stdout().flush().unwrap();
        }
    });

    // === MAIN USER INPUT LOOP ===
    loop {
        print!("=> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            println!("❌ Failed to read input.");
            continue;
        }

        let trimmed = input.trim();

        if trimmed.eq_ignore_ascii_case("quit") {
            let b64 = STANDARD.encode(encrypt_msg("quit"));
            let _ = server_writer
                .write_all(format!("{}\n", b64).as_bytes())
                .await;
            let _ = server_writer.flush().await;
            break;
        }

        let encrypted = encrypt_msg(trimmed);
        let b64 = STANDARD.encode(&encrypted);

        if server_writer
            .write_all(format!("{}\n", b64).as_bytes())
            .await
            .is_err()
        {
            println!("❌ Failed to send message.");
            break;
        }
        server_writer.flush().await.ok();
    }

    let _ = read_handle.await;

    // === RECONNECT PROMPT ===
    loop {
        print!("🔄 Do you want to login again? (y/n): ");
        io::stdout().flush().unwrap();

        let mut answer = String::new();
        if io::stdin().read_line(&mut answer).is_err() {
            println!("❌ Failed to read input.");
            continue;
        }

        match answer.trim().to_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => println!("❌ Please enter 'y' or 'n'."),
        }
    }
}
