// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault CLI — `vault` binary entry point.
//!
//! M3 surface: `status`, `unlock`, `lock`, `sync`, `list`, `get`, `stop-agent`.
//! Every subcommand opens a fresh UDS connection to the agent, sends one
//! CBOR-framed request, and prints the response. The CLI never touches the
//! master key directly — it is only relayed to the agent during `unlock`.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tokio::net::UnixStream;
use zeroize::Zeroize;

use vault_ipc::proto::{
    Error as IpcError, Field, Item, ListEntry, Removed, Request, Response, Status,
};
use vault_ipc::{default_socket_path, read_frame, sanitize_socket_path, write_frame};

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Standard §13.2 attribution block — surfaced via `--version`, `--help` footer,
/// README, and the TUI About screen.
const ATTRIBUTION: &str = "\
Maintained by Mohamed Hammad <Mohamed.Hammad@SpacecraftSoftware.org>
Copyright (C) 2026 Mohamed Hammad & Spacecraft Software  |  License: GPL-3.0-or-later
https://Vault.SpacecraftSoftware.org/";

/// `--version` payload. clap only surfaces `after_help` on `--help`, so the
/// §13.2 attribution block is folded into `long_version` to satisfy the CI
/// `version-gate` (`vault --version` must carry maintainer / license / URL).
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\n",
    "Maintained by Mohamed Hammad <Mohamed.Hammad@SpacecraftSoftware.org>\n",
    "Copyright (C) 2026 Mohamed Hammad & Spacecraft Software  |  License: GPL-3.0-or-later\n",
    "https://Vault.SpacecraftSoftware.org/",
);

#[derive(Parser, Debug)]
#[command(
    name = "vault",
    version = PKG_VERSION,
    long_version = LONG_VERSION,
    about = "Vault — Bitwarden client for the terminal",
    long_about = "Vault is a terminal-native Bitwarden client. Two front-ends share a single Rust engine: a cruxpass-style TUI and an rbw-style CLI. See https://Vault.SpacecraftSoftware.org/.",
    after_help = ATTRIBUTION,
    after_long_help = ATTRIBUTION,
)]
struct Cli {
    /// Override the agent socket path. Defaults to `$VAULT_AGENT_SOCK` or
    /// `$XDG_RUNTIME_DIR/vault/agent.sock`.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Show agent state (unlocked? bound to which account? item count?).
    Status {
        /// Emit JSON instead of a human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// Derive the master key and hand it to the agent for the configured TTL.
    Unlock {
        /// Server origin, e.g. `https://vault.example.org`. Falls back to
        /// `$VAULT_SERVER`.
        #[arg(long)]
        server: Option<String>,
        /// Account email. Falls back to `$VAULT_EMAIL`.
        #[arg(long)]
        email: Option<String>,
    },
    /// Wipe the in-memory key (the agent stays running).
    Lock,
    /// Refresh the encrypted item cache from the server.
    Sync,
    /// List every cached item by decrypted name.
    List {
        /// Emit JSON instead of a tab-separated table.
        #[arg(long)]
        json: bool,
    },
    /// Decrypt and print one field of a single item.
    Get {
        /// Item name (case-insensitive match against the decrypted name).
        name: String,
        /// Field selector. Defaults to `password`.
        #[arg(long, value_enum, default_value_t = FieldArg::Password)]
        field: FieldArg,
        /// Emit JSON instead of the raw field value.
        #[arg(long)]
        json: bool,
    },
    /// Soft-delete a cipher on the server and drop it from the local cache.
    Remove {
        /// Cipher id (UUID) or decrypted item name (case-insensitive).
        selector: String,
        /// Skip the confirmation prompt. Required when stdin is not a TTY.
        #[arg(long, short = 'f')]
        force: bool,
        /// Emit JSON instead of a human-readable confirmation.
        #[arg(long)]
        json: bool,
    },
    /// Politely shut down the agent (equivalent to `Request::Quit`).
    StopAgent,
    /// Generate a password locally (no agent or server interaction).
    Generate {
        /// Password length in characters.
        #[arg(long, short = 'l', default_value_t = 20)]
        length: usize,
        /// Include symbols (`!@#$%^&*`). Off by default.
        #[arg(long, short = 's')]
        symbols: bool,
        /// Exclude lowercase letters.
        #[arg(long)]
        no_lowercase: bool,
        /// Exclude uppercase letters.
        #[arg(long)]
        no_uppercase: bool,
        /// Exclude digits.
        #[arg(long)]
        no_digits: bool,
        /// Emit JSON instead of the raw password.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum FieldArg {
    Password,
    Username,
    Totp,
    Notes,
    Uri,
}

impl From<FieldArg> for Field {
    fn from(f: FieldArg) -> Self {
        match f {
            FieldArg::Password => Self::Password,
            FieldArg::Username => Self::Username,
            FieldArg::Totp => Self::Totp,
            FieldArg::Notes => Self::Notes,
            FieldArg::Uri => Self::Uri,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let socket = match resolve_socket(cli.socket) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vault: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let Some(cmd) = cli.cmd else {
        eprintln!("vault: missing subcommand. Try `vault --help`.");
        return std::process::ExitCode::from(2);
    };
    match run(cmd, &socket).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(code) => std::process::ExitCode::from(code),
    }
}

/// Resolve the socket path: explicit `--socket` > `$VAULT_AGENT_SOCK` > default.
fn resolve_socket(cli: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = cli {
        return Ok(p);
    }
    if let Ok(env_path) = std::env::var("VAULT_AGENT_SOCK") {
        if let Some(p) = sanitize_socket_path(&env_path) {
            return Ok(p);
        }
        anyhow::bail!("VAULT_AGENT_SOCK is not an absolute path: {env_path}");
    }
    default_socket_path().ok_or_else(|| anyhow::anyhow!("no XDG_RUNTIME_DIR / TMPDIR available"))
}

async fn run(cmd: Cmd, socket: &std::path::Path) -> Result<(), u8> {
    match cmd {
        Cmd::Status { json } => cmd_status(socket, json).await,
        Cmd::Unlock { server, email } => cmd_unlock(socket, server, email).await,
        Cmd::Lock => cmd_simple(socket, Request::Lock).await,
        Cmd::Sync => cmd_simple(socket, Request::Sync).await,
        Cmd::List { json } => cmd_list(socket, json).await,
        Cmd::Get { name, field, json } => cmd_get(socket, name, field.into(), json).await,
        Cmd::Remove {
            selector,
            force,
            json,
        } => cmd_remove(socket, selector, force, json).await,
        Cmd::StopAgent => cmd_simple(socket, Request::Quit).await,
        Cmd::Generate {
            length,
            symbols,
            no_lowercase,
            no_uppercase,
            no_digits,
            json,
        } => cmd_generate(length, symbols, no_lowercase, no_uppercase, no_digits, json),
    }
}

#[allow(clippy::fn_params_excessive_bools)] // each flag mirrors a `vault generate` CLI switch
fn cmd_generate(
    length: usize,
    symbols: bool,
    no_lowercase: bool,
    no_uppercase: bool,
    no_digits: bool,
    json: bool,
) -> Result<(), u8> {
    let opts = vault_core::GenerateOptions {
        length,
        lowercase: !no_lowercase,
        uppercase: !no_uppercase,
        digits: !no_digits,
        symbols,
    };
    let pw = match vault_core::generate_password(&opts) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vault: {e}");
            return Err(2);
        }
    };
    if json {
        let v = serde_json::json!({
            "password": pw.as_str(),
            "length": opts.length,
            "classes": {
                "lowercase": opts.lowercase,
                "uppercase": opts.uppercase,
                "digits": opts.digits,
                "symbols": opts.symbols,
            },
        });
        println!("{v}");
    } else {
        println!("{}", pw.as_str());
    }
    Ok(())
}

async fn cmd_status(socket: &std::path::Path, json: bool) -> Result<(), u8> {
    let mut stream = connect(socket).await?;
    let resp = exchange(&mut stream, &Request::Status).await?;
    match resp {
        Response::Status(s) => {
            print_status(&s, json);
            Ok(())
        }
        Response::Error(e) => report_error(&e),
        other => unexpected(&other),
    }
}

async fn cmd_unlock(
    socket: &std::path::Path,
    server: Option<String>,
    email: Option<String>,
) -> Result<(), u8> {
    let server = resolve_arg(server, "VAULT_SERVER", "--server")?;
    let email = resolve_arg(email, "VAULT_EMAIL", "--email")?;
    let password = read_password()?;
    let mut stream = connect(socket).await?;
    let req = Request::Unlock {
        server,
        email,
        password,
    };
    let resp = exchange(&mut stream, &req).await?;
    // Wipe our copy of the request — the password field is now zero'd inside
    // the moved Request, but the wire buffer was already serialised. Drop is
    // best-effort beyond that point.
    drop(req);
    match resp {
        Response::Ok => Ok(()),
        Response::Error(e) => report_error(&e),
        other => unexpected(&other),
    }
}

async fn cmd_simple(socket: &std::path::Path, req: Request) -> Result<(), u8> {
    let mut stream = connect(socket).await?;
    let resp = exchange(&mut stream, &req).await?;
    match resp {
        Response::Ok | Response::Status(_) => Ok(()),
        Response::Error(e) => report_error(&e),
        other => unexpected(&other),
    }
}

async fn cmd_list(socket: &std::path::Path, json: bool) -> Result<(), u8> {
    let mut stream = connect(socket).await?;
    let resp = exchange(&mut stream, &Request::List).await?;
    match resp {
        Response::List(items) => {
            print_list(&items, json);
            Ok(())
        }
        Response::Error(e) => report_error(&e),
        other => unexpected(&other),
    }
}

async fn cmd_remove(
    socket: &std::path::Path,
    selector: String,
    force: bool,
    json: bool,
) -> Result<(), u8> {
    if !force {
        if !io::stdin().is_terminal() {
            eprintln!("vault: refusing to remove without --force when stdin is not a TTY");
            return Err(2);
        }
        let mut stderr = io::stderr();
        let _ = write!(
            stderr,
            "Remove '{selector}'? Type the item name to confirm: "
        );
        let _ = stderr.flush();
        let mut buf = String::new();
        if io::stdin().lock().read_line(&mut buf).is_err() {
            eprintln!("vault: failed to read confirmation");
            return Err(2);
        }
        if buf.trim() != selector {
            eprintln!("vault: confirmation did not match, aborting");
            return Err(2);
        }
    }
    let mut stream = connect(socket).await?;
    let req = Request::Remove { selector };
    let resp = exchange(&mut stream, &req).await?;
    match resp {
        Response::Removed(r) => {
            print_removed(&r, json);
            Ok(())
        }
        Response::Error(e) => report_error(&e),
        other => unexpected(&other),
    }
}

async fn cmd_get(
    socket: &std::path::Path,
    name: String,
    field: Field,
    json: bool,
) -> Result<(), u8> {
    let mut stream = connect(socket).await?;
    let req = Request::Get {
        name,
        field: Some(field),
    };
    let resp = exchange(&mut stream, &req).await?;
    match resp {
        Response::Item(item) => {
            print_item(&item, json);
            Ok(())
        }
        Response::Error(e) => report_error(&e),
        other => unexpected(&other),
    }
}

async fn connect(socket: &std::path::Path) -> Result<UnixStream, u8> {
    match UnixStream::connect(socket).await {
        Ok(s) => Ok(s),
        Err(e) => {
            eprintln!(
                "vault: could not connect to agent at {}: {e}\n\
                 hint: start the daemon with `vault-agent &` first.",
                socket.display()
            );
            Err(3)
        }
    }
}

async fn exchange(stream: &mut UnixStream, req: &Request) -> Result<Response, u8> {
    let (mut rd, mut wr) = stream.split();
    if let Err(e) = write_frame(&mut wr, req).await {
        eprintln!("vault: send failed: {e}");
        return Err(3);
    }
    match read_frame::<_, Response>(&mut rd).await {
        Ok(r) => Ok(r),
        Err(e) => {
            eprintln!("vault: receive failed: {e}");
            Err(3)
        }
    }
}

fn report_error(e: &IpcError) -> Result<(), u8> {
    let code = match e {
        IpcError::Locked => 4,
        IpcError::BadPassword => 5,
        IpcError::TwoFactorRequired => 6,
        IpcError::NoSuchItem(_) => 7,
        IpcError::NoSuchField { .. } => 8,
        IpcError::AmbiguousItem { .. } => 10,
        IpcError::Network(_) | IpcError::Internal(_) | IpcError::Decrypt(_) => 9,
    };
    eprintln!("vault: {e}");
    Err(code)
}

fn unexpected(other: &Response) -> Result<(), u8> {
    eprintln!("vault: unexpected response from agent: {other:?}");
    Err(9)
}

fn resolve_arg(cli: Option<String>, env_key: &str, flag: &str) -> Result<String, u8> {
    if let Some(v) = cli {
        return Ok(v);
    }
    if let Ok(v) = std::env::var(env_key)
        && !v.is_empty()
    {
        return Ok(v);
    }
    eprintln!("vault: missing {flag} (or ${env_key})");
    Err(2)
}

/// Read the master password. Prompts on a TTY with no echo guarantee yet
/// (M3 ships without `rpassword` to keep the dep tree slim — interactive
/// users should redirect from a tool like `pass` or `gpg --decrypt`).
fn read_password() -> Result<Vec<u8>, u8> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        let mut stderr = io::stderr();
        let _ = write!(stderr, "Master password: ");
        let _ = stderr.flush();
    }
    let mut buf = String::new();
    let read_res = stdin.lock().read_to_string(&mut buf);
    if let Err(e) = read_res {
        eprintln!("vault: failed to read password: {e}");
        return Err(2);
    }
    // Strip exactly one trailing newline (typical from terminals); preserve
    // any deliberate trailing whitespace beyond that.
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    if buf.is_empty() {
        eprintln!("vault: empty password");
        buf.zeroize();
        return Err(2);
    }
    let bytes = buf.as_bytes().to_vec();
    buf.zeroize();
    Ok(bytes)
}

fn print_status(s: &Status, json: bool) {
    if json {
        let v = serde_json::json!({
            "unlocked": s.unlocked,
            "server": s.server,
            "email": s.email,
            "items": s.items,
            "last_sync": s.last_sync,
            "agent_version": s.agent_version,
        });
        println!("{v}");
        return;
    }
    if s.unlocked {
        println!("unlocked");
    } else {
        println!("locked");
    }
    if let Some(v) = s.server.as_deref() {
        println!("server:        {v}");
    }
    if let Some(v) = s.email.as_deref() {
        println!("email:         {v}");
    }
    if let Some(v) = s.items {
        println!("items:         {v}");
    }
    if let Some(v) = s.last_sync.as_deref() {
        println!("last sync:     {v}");
    }
    println!("agent version: {}", s.agent_version);
}

fn print_list(items: &[ListEntry], json: bool) {
    if json {
        let v: Vec<_> = items
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "name": e.name,
                    "type": e.cipher_type,
                    "username": e.username,
                    "folder": e.folder,
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(v));
        return;
    }
    for e in items {
        let folder = e.folder.as_deref().unwrap_or("");
        let user = e.username.as_deref().unwrap_or("");
        println!("{}\t{}\t{}", e.name, user, folder);
    }
}

fn print_removed(r: &Removed, json: bool) {
    if json {
        let v = serde_json::json!({
            "id": r.id,
            "name": r.name,
            "removed": true,
        });
        println!("{v}");
    } else {
        println!("removed: {} ({})", r.name, r.id);
    }
}

fn print_item(item: &Item, json: bool) {
    if json {
        let v = serde_json::json!({
            "id": item.id,
            "name": item.name,
            "type": item.cipher_type,
            "field": format!("{:?}", item.field).to_lowercase(),
            "value": item.value,
        });
        println!("{v}");
        return;
    }
    // Plain output: print the field value followed by exactly one newline.
    // Matches the rbw convention so shell pipelines work unchanged.
    println!("{}", item.value);
}
