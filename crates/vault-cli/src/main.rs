// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault CLI — `vault` binary entry point.
//!
//! Every subcommand opens a fresh UDS connection to the agent, sends one
//! CBOR-framed request, and prints the response. When the socket is dead the
//! CLI auto-starts `vault-agent` first (PRD §7.3; disable with
//! `--no-auto-spawn`). The CLI never touches the master key directly — it is
//! only relayed to the agent during `unlock`.

#![forbid(unsafe_code)]

mod spawn;

use vault_config as config;

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use tokio::net::UnixStream;
use zeroize::{Zeroize, Zeroizing};

use vault_ipc::proto::{
    ApiKeyCreds, ApiKeyStatus, CardWrite, Error as IpcError, Field, IdentityWrite, Item, ListEntry,
    PinStatus, Removed, Request, Response, Saved, Status, TwoFactorCode,
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

    /// Do not auto-start `vault-agent` when the socket is dead.
    #[arg(long, global = true)]
    no_auto_spawn: bool,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

/// Resolved agent endpoint: where the socket lives and whether a dead socket
/// should auto-start `vault-agent` (PRD §7.3).
#[derive(Clone, Copy, Debug)]
struct Endpoint<'a> {
    /// Socket path the agent is (or will be) bound to.
    socket: &'a Path,
    /// Start the agent when nothing is accepting on `socket`.
    auto_spawn: bool,
}

impl Endpoint<'_> {
    /// The same endpoint with auto-spawn off — `stop-agent` must never start
    /// an agent just to stop it.
    const fn no_spawn(self) -> Self {
        Self {
            auto_spawn: false,
            ..self
        }
    }
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Show agent state (unlocked? bound to which account? item count?).
    Status {
        /// Emit JSON instead of a human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// Record the account (server + email) so later commands don't need the
    /// flags. Writes the `[account]` profile; no network.
    Register {
        /// Server origin, e.g. `https://vault.example.org`. Falls back to
        /// `$VAULT_SERVER`.
        #[arg(long)]
        server: Option<String>,
        /// Account email. Falls back to `$VAULT_EMAIL`.
        #[arg(long)]
        email: Option<String>,
        /// Emit JSON instead of a human-readable confirmation.
        #[arg(long)]
        json: bool,
    },
    /// Authenticate against the registered account and confirm a working sync.
    /// First-time counterpart to `unlock`; resolves server/email from the
    /// profile unless overridden.
    Login {
        /// Server origin override. Falls back to the profile, then `$VAULT_SERVER`.
        #[arg(long)]
        server: Option<String>,
        /// Account email override. Falls back to the profile, then `$VAULT_EMAIL`.
        #[arg(long)]
        email: Option<String>,
        /// Authenticate with a Bitwarden personal API key (the
        /// `client_credentials` grant, which skips an interactive 2FA prompt).
        /// Reads `$BW_CLIENTID` / `$BW_CLIENTSECRET`, else prompts. The master
        /// password is still required and the key is stored for later unlocks.
        #[arg(long = "api-key")]
        api_key: bool,
        /// Authenticator (TOTP) code for a 2FA-enabled account, supplied up
        /// front instead of being prompted. Falls back to `$BW_TOTP`.
        #[arg(long)]
        totp: Option<String>,
        /// Emit JSON instead of a human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// Derive the master key and hand it to the agent for the configured TTL.
    Unlock {
        /// Server origin. Falls back to the registered profile, then `$VAULT_SERVER`.
        #[arg(long)]
        server: Option<String>,
        /// Account email. Falls back to the registered profile, then `$VAULT_EMAIL`.
        #[arg(long)]
        email: Option<String>,
        /// Unlock with the enrolled PIN instead of the master password
        /// (read-only, offline session — sync/edits need a master unlock).
        #[arg(long)]
        pin: bool,
        /// Authenticator (TOTP) code for a 2FA-enabled account (master unlock
        /// only), supplied up front instead of being prompted. Falls back to
        /// `$BW_TOTP`.
        #[arg(long)]
        totp: Option<String>,
        /// Emit JSON instead of staying silent on success.
        #[arg(long)]
        json: bool,
    },
    /// Manage the unlock PIN (set / disable / status).
    Pin {
        #[command(subcommand)]
        action: PinAction,
    },
    /// Manage the stored Bitwarden API key (status / forget). Enroll one with
    /// `vault login --api-key`.
    Apikey {
        #[command(subcommand)]
        action: ApiKeyAction,
    },
    /// Wipe the in-memory key (the agent stays running).
    Lock {
        /// Emit JSON instead of staying silent on success.
        #[arg(long)]
        json: bool,
    },
    /// Refresh the item cache from the server (re-pull `/sync`).
    Sync {
        /// Emit JSON instead of staying silent on success.
        #[arg(long)]
        json: bool,
    },
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
    /// Create a new login or secure note.
    Add {
        /// Item name.
        name: String,
        /// Item kind.
        #[arg(long = "type", value_enum, default_value_t = KindArg::Login)]
        kind: KindArg,
        /// Username (login only).
        #[arg(long)]
        username: Option<String>,
        /// Primary URI (login only).
        #[arg(long)]
        uri: Option<String>,
        /// Folder to file under (name or id).
        #[arg(long)]
        folder: Option<String>,
        /// Notes text.
        #[arg(long)]
        notes: Option<String>,
        /// Generate the password locally (login only); optional length, default 20.
        /// Without this flag the password is read from stdin.
        #[arg(long, value_name = "LEN", num_args = 0..=1, default_missing_value = "20")]
        generate: Option<usize>,
        /// Cardholder name (card only).
        #[arg(long)]
        cardholder: Option<String>,
        /// Card brand, e.g. `Visa` (card only).
        #[arg(long)]
        brand: Option<String>,
        /// Card expiry as `MM/YYYY` or `MM/YY` (card only).
        #[arg(long)]
        expiry: Option<String>,
        /// Identity fields (identity only).
        #[command(flatten)]
        identity: IdentityArgs,
        /// Emit JSON instead of a human-readable confirmation.
        #[arg(long)]
        json: bool,
    },
    /// Edit fields of an existing login or secure note. Only the flags you pass
    /// change; everything else is left as-is.
    Edit {
        /// Cipher id (UUID) or decrypted item name (case-insensitive).
        selector: String,
        /// New name.
        #[arg(long)]
        name: Option<String>,
        /// New username.
        #[arg(long)]
        username: Option<String>,
        /// New primary URI.
        #[arg(long)]
        uri: Option<String>,
        /// New folder (name or id).
        #[arg(long)]
        folder: Option<String>,
        /// New notes text.
        #[arg(long)]
        notes: Option<String>,
        /// Replace the password — the new value is read from stdin.
        #[arg(long)]
        password: bool,
        /// Replace the password with a freshly generated one; optional length.
        #[arg(long, value_name = "LEN", num_args = 0..=1, default_missing_value = "20")]
        generate: Option<usize>,
        /// New cardholder name (card only).
        #[arg(long)]
        cardholder: Option<String>,
        /// New card brand (card only).
        #[arg(long)]
        brand: Option<String>,
        /// New card expiry `MM/YYYY` or `MM/YY` (card only).
        #[arg(long)]
        expiry: Option<String>,
        /// Replace the card number — the new value is prompted on the terminal.
        #[arg(long)]
        number: bool,
        /// Replace the card security code (CVV) — prompted on the terminal.
        #[arg(long)]
        code: bool,
        /// Identity fields to change (identity only).
        #[command(flatten)]
        identity: IdentityArgs,
        /// Emit JSON instead of a human-readable confirmation.
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
    StopAgent {
        /// Emit JSON instead of staying silent on success.
        #[arg(long)]
        json: bool,
    },
    /// Get, set, or unset a persistent configuration key.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Wipe the local item cache from disk (and lock a running agent).
    Purge {
        /// Skip the confirmation prompt. Required when stdin is not a TTY.
        #[arg(long, short = 'f')]
        force: bool,
        /// Emit JSON instead of a human-readable confirmation.
        #[arg(long)]
        json: bool,
    },
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

#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Print one key's value, or every known key when no key is given.
    Get {
        /// Dotted key, e.g. `clipboard.clear_secs`. Omit to list all.
        key: Option<String>,
        /// Emit JSON instead of a human-readable table.
        #[arg(long)]
        json: bool,
    },
    /// Set a key to a value (validated against the key's type).
    Set {
        /// Dotted key, e.g. `clipboard.clear_secs`.
        key: String,
        /// New value.
        value: String,
        /// Emit JSON instead of staying silent on success.
        #[arg(long)]
        json: bool,
    },
    /// Clear a key, reverting it to the consumer's default.
    Unset {
        /// Dotted key, e.g. `clipboard.clear_secs`.
        key: String,
        /// Emit JSON instead of staying silent on success.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum PinAction {
    /// Enroll a PIN (requires an unlocked agent); prompts twice.
    Set {
        /// Server origin. Falls back to the profile, then `$VAULT_SERVER`.
        #[arg(long)]
        server: Option<String>,
        /// Account email. Falls back to the profile, then `$VAULT_EMAIL`.
        #[arg(long)]
        email: Option<String>,
        /// Emit JSON instead of staying silent on success.
        #[arg(long)]
        json: bool,
    },
    /// Forget the enrolled PIN.
    Disable {
        /// Server origin. Falls back to the profile, then `$VAULT_SERVER`.
        #[arg(long)]
        server: Option<String>,
        /// Account email. Falls back to the profile, then `$VAULT_EMAIL`.
        #[arg(long)]
        email: Option<String>,
        /// Emit JSON instead of staying silent on success.
        #[arg(long)]
        json: bool,
    },
    /// Show whether a PIN is enrolled and how many attempts remain.
    Status {
        /// Server origin. Falls back to the profile, then `$VAULT_SERVER`.
        #[arg(long)]
        server: Option<String>,
        /// Account email. Falls back to the profile, then `$VAULT_EMAIL`.
        #[arg(long)]
        email: Option<String>,
        /// Emit JSON instead of a human-readable line.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ApiKeyAction {
    /// Show whether an API key is stored for the account.
    Status {
        /// Server origin. Falls back to the profile, then `$VAULT_SERVER`.
        #[arg(long)]
        server: Option<String>,
        /// Account email. Falls back to the profile, then `$VAULT_EMAIL`.
        #[arg(long)]
        email: Option<String>,
        /// Emit JSON instead of a human-readable line.
        #[arg(long)]
        json: bool,
    },
    /// Forget the stored API key (later logins use the password grant).
    Forget {
        /// Server origin. Falls back to the profile, then `$VAULT_SERVER`.
        #[arg(long)]
        server: Option<String>,
        /// Account email. Falls back to the profile, then `$VAULT_EMAIL`.
        #[arg(long)]
        email: Option<String>,
        /// Emit JSON instead of staying silent on success.
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
    CardCardholder,
    CardNumber,
    CardBrand,
    CardExpiry,
    CardCode,
    IdentityName,
    IdentityEmail,
    IdentityPhone,
    IdentityAddress,
}

impl From<FieldArg> for Field {
    fn from(f: FieldArg) -> Self {
        match f {
            FieldArg::Password => Self::Password,
            FieldArg::Username => Self::Username,
            FieldArg::Totp => Self::Totp,
            FieldArg::Notes => Self::Notes,
            FieldArg::Uri => Self::Uri,
            FieldArg::CardCardholder => Self::CardCardholder,
            FieldArg::CardNumber => Self::CardNumber,
            FieldArg::CardBrand => Self::CardBrand,
            FieldArg::CardExpiry => Self::CardExpiry,
            FieldArg::CardCode => Self::CardCode,
            FieldArg::IdentityName => Self::IdentityName,
            FieldArg::IdentityEmail => Self::IdentityEmail,
            FieldArg::IdentityPhone => Self::IdentityPhone,
            FieldArg::IdentityAddress => Self::IdentityAddress,
        }
    }
}

/// Cipher kind selectable on `vault add`.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum KindArg {
    /// Login item (type 1).
    Login,
    /// Secure note (type 2).
    Note,
    /// Payment card (type 3).
    Card,
    /// Identity (type 4).
    Identity,
}

impl KindArg {
    /// Bitwarden cipher-type discriminant.
    const fn cipher_type(self) -> u8 {
        match self {
            Self::Login => 1,
            Self::Note => 2,
            Self::Card => 3,
            Self::Identity => 4,
        }
    }
}

/// Identity (type 4) fields, shared by `add` and `edit` via `#[command(flatten)]`.
/// Non-secret fields are flags; ssn/passport/license are prompted on the
/// terminal when their bool flag is set (never argv — they'd leak to history).
#[derive(clap::Args, Debug, Default)]
struct IdentityArgs {
    /// Title, e.g. `Mr`/`Ms` (identity only).
    #[arg(long)]
    title: Option<String>,
    /// First name (identity only).
    #[arg(long)]
    first_name: Option<String>,
    /// Middle name (identity only).
    #[arg(long)]
    middle_name: Option<String>,
    /// Last name (identity only).
    #[arg(long)]
    last_name: Option<String>,
    /// Identity username (identity only; the login username is `--username`).
    #[arg(long = "identity-username")]
    username: Option<String>,
    /// Company (identity only).
    #[arg(long)]
    company: Option<String>,
    /// Email (identity only).
    #[arg(long)]
    email: Option<String>,
    /// Phone (identity only).
    #[arg(long)]
    phone: Option<String>,
    /// Address line 1 (identity only).
    #[arg(long)]
    address1: Option<String>,
    /// Address line 2 (identity only).
    #[arg(long)]
    address2: Option<String>,
    /// Address line 3 (identity only).
    #[arg(long)]
    address3: Option<String>,
    /// City (identity only).
    #[arg(long)]
    city: Option<String>,
    /// State / province (identity only).
    #[arg(long)]
    state: Option<String>,
    /// Postal code (identity only).
    #[arg(long)]
    postal_code: Option<String>,
    /// Country (identity only).
    #[arg(long)]
    country: Option<String>,
    /// Set the SSN / national id — prompted on the terminal (identity only).
    #[arg(long)]
    ssn: bool,
    /// Set the passport number — prompted on the terminal (identity only).
    #[arg(long)]
    passport: bool,
    /// Set the license number — prompted on the terminal (identity only).
    #[arg(long)]
    license: bool,
}

impl IdentityArgs {
    /// Whether any identity flag was passed (gates building an `IdentityWrite`
    /// on `edit`).
    const fn any_set(&self) -> bool {
        self.title.is_some()
            || self.first_name.is_some()
            || self.middle_name.is_some()
            || self.last_name.is_some()
            || self.username.is_some()
            || self.company.is_some()
            || self.email.is_some()
            || self.phone.is_some()
            || self.address1.is_some()
            || self.address2.is_some()
            || self.address3.is_some()
            || self.city.is_some()
            || self.state.is_some()
            || self.postal_code.is_some()
            || self.country.is_some()
            || self.ssn
            || self.passport
            || self.license
    }

    /// Build an `IdentityWrite`, prompting on the terminal for each sensitive
    /// field whose bool flag is set.
    fn into_write(self) -> IdentityWrite {
        IdentityWrite {
            title: self.title,
            first_name: self.first_name,
            middle_name: self.middle_name,
            last_name: self.last_name,
            username: self.username,
            company: self.company,
            ssn: self
                .ssn
                .then(|| read_tty_line("SSN / national id: ").map(String::into_bytes))
                .flatten(),
            passport_number: self
                .passport
                .then(|| read_tty_line("Passport number: ").map(String::into_bytes))
                .flatten(),
            license_number: self
                .license
                .then(|| read_tty_line("License number: ").map(String::into_bytes))
                .flatten(),
            email: self.email,
            phone: self.phone,
            address1: self.address1,
            address2: self.address2,
            address3: self.address3,
            city: self.city,
            state: self.state,
            postal_code: self.postal_code,
            country: self.country,
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
    let ep = Endpoint {
        socket: &socket,
        auto_spawn: !cli.no_auto_spawn,
    };
    match run(cmd, ep).await {
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

#[allow(clippy::too_many_lines)] // flat one-arm-per-subcommand dispatch reads best in one match
async fn run(cmd: Cmd, ep: Endpoint<'_>) -> Result<(), u8> {
    match cmd {
        Cmd::Status { json } => cmd_status(ep, json).await,
        Cmd::Register {
            server,
            email,
            json,
        } => cmd_register(server, email, json),
        Cmd::Login {
            server,
            email,
            api_key,
            totp,
            json,
        } => cmd_login(ep, server, email, api_key, totp, json).await,
        Cmd::Unlock {
            server,
            email,
            pin,
            totp,
            json,
        } => cmd_unlock(ep, server, email, pin, totp, json).await,
        Cmd::Pin { action } => cmd_pin(ep, action).await,
        Cmd::Apikey { action } => cmd_apikey(ep, action).await,
        Cmd::Lock { json } => cmd_ack(ep, Request::Lock, "locked", json).await,
        Cmd::Sync { json } => cmd_sync(ep, json).await,
        Cmd::List { json } => cmd_list(ep, json).await,
        Cmd::Get { name, field, json } => cmd_get(ep, name, field.into(), json).await,
        Cmd::Add {
            name,
            kind,
            username,
            uri,
            folder,
            notes,
            generate,
            cardholder,
            brand,
            expiry,
            identity,
            json,
        } => {
            cmd_add(
                ep,
                AddArgs {
                    name,
                    kind,
                    username,
                    uri,
                    folder,
                    notes,
                    generate,
                    cardholder,
                    brand,
                    expiry,
                    identity,
                    json,
                },
            )
            .await
        }
        Cmd::Edit {
            selector,
            name,
            username,
            uri,
            folder,
            notes,
            password,
            generate,
            cardholder,
            brand,
            expiry,
            number,
            code,
            identity,
            json,
        } => {
            cmd_edit(
                ep,
                EditArgs {
                    selector,
                    name,
                    username,
                    uri,
                    folder,
                    notes,
                    password,
                    generate,
                    cardholder,
                    brand,
                    expiry,
                    number,
                    code,
                    identity,
                    json,
                },
            )
            .await
        }
        Cmd::Remove {
            selector,
            force,
            json,
        } => cmd_remove(ep, selector, force, json).await,
        Cmd::StopAgent { json } => cmd_ack(ep.no_spawn(), Request::Quit, "stopped", json).await,
        Cmd::Config { action } => cmd_config(action),
        Cmd::Purge { force, json } => cmd_purge(ep, force, json).await,
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

async fn cmd_status(ep: Endpoint<'_>, json: bool) -> Result<(), u8> {
    let mut stream = connect(ep).await?;
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

/// A resolved account: where to authenticate, as whom, and with which stable
/// device id (from the profile, if registered).
struct Account {
    server: String,
    email: String,
    device_id: Option<String>,
}

/// Resolve the account for `login` / `unlock`: an explicit flag or env var
/// wins; otherwise the registered `[account]` profile supplies it. The
/// `device_id` only ever comes from the profile. Errors (exit 2) when a field
/// can be found nowhere.
fn resolve_account(server: Option<String>, email: Option<String>) -> Result<Account, u8> {
    let profile = load_config()?;
    let acct = profile.account();
    let server = server
        .or_else(|| std::env::var("VAULT_SERVER").ok())
        .or_else(|| acct.server.clone())
        .ok_or_else(|| {
            eprintln!(
                "vault: no server — pass --server, set $VAULT_SERVER, or run `vault register`"
            );
            2u8
        })?;
    let email = email
        .or_else(|| std::env::var("VAULT_EMAIL").ok())
        .or_else(|| acct.email.clone())
        .ok_or_else(|| {
            eprintln!("vault: no email — pass --email, set $VAULT_EMAIL, or run `vault register`");
            2u8
        })?;
    Ok(Account {
        server,
        email,
        device_id: acct.device_id.clone(),
    })
}

/// `vault register` — persist the account profile. No agent or network: a
/// light `http(s)://` check is all the validation done here; a real server
/// error surfaces on the first `login`.
fn cmd_register(server: Option<String>, email: Option<String>, json: bool) -> Result<(), u8> {
    let server = resolve_arg(server, "VAULT_SERVER", "--server")?;
    let email = resolve_arg(email, "VAULT_EMAIL", "--email")?;
    if !(server.starts_with("https://") || server.starts_with("http://")) {
        eprintln!("vault: server must be an http(s):// origin, got '{server}'");
        return Err(2);
    }
    let mut cfg = load_config()?;
    cfg.set_account(&server, &email);
    save_config(&cfg)?;
    let acct = cfg.account();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "server": acct.server,
                "email": acct.email,
                "device_id": acct.device_id,
            })
        );
    } else {
        println!(
            "registered {} at {}",
            acct.email.as_deref().unwrap_or(""),
            server
        );
    }
    Ok(())
}

/// `vault login` — authenticate against the registered account and report a
/// sync summary. Shares `Request::Unlock` with `unlock`; the difference is
/// profile resolution and the verbose, status-backed success message.
async fn cmd_login(
    ep: Endpoint<'_>,
    server: Option<String>,
    email: Option<String>,
    api_key: bool,
    totp: Option<String>,
    json: bool,
) -> Result<(), u8> {
    let acct = resolve_account(server, email)?;
    // Read the API key (env or interactive line) *before* the password, since
    // `read_password` consumes the rest of stdin.
    let api_creds = if api_key { Some(read_api_key()?) } else { None };
    let password = Zeroizing::new(read_password()?);
    password_unlock(ep, &acct, &password, api_creds, resolve_totp(totp)).await?;
    // Confirm with a status snapshot so login ends on a "working sync" note.
    let mut stream = connect(ep).await?;
    match exchange(&mut stream, &Request::Status).await? {
        Response::Status(s) => {
            print_login_summary(&acct.email, &s, json);
            Ok(())
        }
        Response::Error(e) => report_error(&e),
        other => unexpected(&other),
    }
}

async fn cmd_unlock(
    ep: Endpoint<'_>,
    server: Option<String>,
    email: Option<String>,
    pin: bool,
    totp: Option<String>,
    json: bool,
) -> Result<(), u8> {
    let acct = resolve_account(server, email)?;
    if pin {
        let pin = read_secret("PIN: ")?.ok_or_else(|| {
            eprintln!("vault: empty PIN");
            2u8
        })?;
        let req = Request::UnlockPin {
            server: acct.server,
            email: acct.email,
            pin,
        };
        let mut stream = connect(ep).await?;
        let resp = exchange(&mut stream, &req).await?;
        drop(req);
        return match resp {
            Response::Ok => {
                print_ack("unlocked", json);
                Ok(())
            }
            Response::Error(e) => report_error(&e),
            other => unexpected(&other),
        };
    }
    // A routine master unlock never re-supplies an API key (the agent auto-uses
    // any persisted one); it may need a TOTP code for a 2FA account.
    let password = Zeroizing::new(read_password()?);
    password_unlock(ep, &acct, &password, None, resolve_totp(totp)).await?;
    print_ack("unlocked", json);
    Ok(())
}

/// Resolve a TOTP code: the `--totp` flag, else `$BW_TOTP` (when non-empty).
fn resolve_totp(flag: Option<String>) -> Option<String> {
    flag.or_else(|| std::env::var("BW_TOTP").ok().filter(|s| !s.is_empty()))
}

/// Send a password `Unlock`, transparently handling a TOTP 2FA challenge: on
/// `TwoFactorRequired`, use `totp` (first time) else prompt on the controlling
/// terminal, then resubmit with the code. `Ok(())` on unlock; a terminal error
/// or an empty/declined code reports through the usual exit codes.
async fn password_unlock(
    ep: Endpoint<'_>,
    acct: &Account,
    password: &Zeroizing<Vec<u8>>,
    api_key: Option<ApiKeyCreds>,
    totp: Option<String>,
) -> Result<(), u8> {
    let mut two_factor: Option<TwoFactorCode> = None;
    let mut prompted = false;
    loop {
        let req = Request::Unlock {
            server: acct.server.clone(),
            email: acct.email.clone(),
            password: password.as_slice().to_vec(),
            device_id: acct.device_id.clone(),
            api_key: api_key.clone(),
            two_factor: two_factor.take(),
        };
        let mut stream = connect(ep).await?;
        let resp = exchange(&mut stream, &req).await?;
        drop(req);
        match resp {
            Response::Ok => return Ok(()),
            Response::Error(IpcError::TwoFactorRequired) => {
                // First challenge: prefer a supplied code; otherwise (and on any
                // re-prompt after a rejected code) read from the controlling
                // terminal, since stdin is exhausted by the password read.
                let code = if prompted {
                    read_tty_line("Authenticator code (retry): ")
                } else {
                    totp.clone()
                        .or_else(|| read_tty_line("Authenticator code: "))
                };
                prompted = true;
                match code {
                    Some(c) => two_factor = Some(TwoFactorCode { token: c }),
                    None => return report_error(&IpcError::TwoFactorRequired),
                }
            }
            Response::Error(e) => return report_error(&e),
            other => return unexpected(&other),
        }
    }
}

/// Prompt on the controlling terminal (`/dev/tty`) and read one line, so it
/// works even when stdin was piped/consumed (the password path). `None` if the
/// terminal can't be opened or the line is empty (treated as "abort").
fn read_tty_line(prompt: &str) -> Option<String> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    {
        let mut w = &tty;
        let _ = write!(w, "{prompt}");
        let _ = w.flush();
    }
    let mut line = String::new();
    BufReader::new(tty).read_line(&mut line).ok()?;
    let trimmed = line.trim_end_matches(['\n', '\r']).to_owned();
    line.zeroize();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// `vault pin set/disable/status`.
async fn cmd_pin(ep: Endpoint<'_>, action: PinAction) -> Result<(), u8> {
    match action {
        PinAction::Set {
            server,
            email,
            json,
        } => {
            // Ensure an account exists; the agent needs an unlocked vault.
            let _ = resolve_account(server, email)?;
            let pin = read_secret("New PIN (>= 4 chars): ")?.ok_or_else(|| {
                eprintln!("vault: empty PIN");
                2u8
            })?;
            if pin.len() < 4 {
                eprintln!("vault: PIN must be at least 4 characters");
                return Err(2);
            }
            cmd_ack(ep, Request::PinSet { pin }, "pin set", json).await
        }
        PinAction::Disable {
            server,
            email,
            json,
        } => {
            let acct = resolve_account(server, email)?;
            cmd_ack(
                ep,
                Request::PinDisable {
                    server: acct.server,
                    email: acct.email,
                },
                "pin disabled",
                json,
            )
            .await
        }
        PinAction::Status {
            server,
            email,
            json,
        } => {
            let acct = resolve_account(server, email)?;
            let mut stream = connect(ep).await?;
            let req = Request::PinStatus {
                server: acct.server,
                email: acct.email,
            };
            match exchange(&mut stream, &req).await? {
                Response::PinStatus(s) => {
                    print_pin_status(s, json);
                    Ok(())
                }
                Response::Error(e) => report_error(&e),
                other => unexpected(&other),
            }
        }
    }
}

/// Human / JSON rendering of `vault pin status`.
fn print_pin_status(s: PinStatus, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({ "enabled": s.enabled, "attempts_remaining": s.attempts_remaining })
        );
    } else if s.enabled {
        println!(
            "pin: enabled ({} attempt(s) remaining)",
            s.attempts_remaining
        );
    } else {
        println!("pin: disabled");
    }
}

/// `vault apikey status/forget`.
async fn cmd_apikey(ep: Endpoint<'_>, action: ApiKeyAction) -> Result<(), u8> {
    match action {
        ApiKeyAction::Status {
            server,
            email,
            json,
        } => {
            let acct = resolve_account(server, email)?;
            let mut stream = connect(ep).await?;
            let req = Request::ApiKeyStatus {
                server: acct.server,
                email: acct.email,
            };
            match exchange(&mut stream, &req).await? {
                Response::ApiKeyStatus(s) => {
                    print_apikey_status(&s, json);
                    Ok(())
                }
                Response::Error(e) => report_error(&e),
                other => unexpected(&other),
            }
        }
        ApiKeyAction::Forget {
            server,
            email,
            json,
        } => {
            let acct = resolve_account(server, email)?;
            cmd_ack(
                ep,
                Request::ApiKeyForget {
                    server: acct.server,
                    email: acct.email,
                },
                "api key forgotten",
                json,
            )
            .await
        }
    }
}

/// Human / JSON rendering of `vault apikey status`.
fn print_apikey_status(s: &ApiKeyStatus, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({ "configured": s.configured, "client_id": s.client_id })
        );
    } else if s.configured {
        let id = s.client_id.as_deref().unwrap_or("");
        println!("api key: configured ({id})");
    } else {
        println!("api key: not configured");
    }
}

/// Read a Bitwarden API key for `vault login --api-key`: `$BW_CLIENTID` /
/// `$BW_CLIENTSECRET` if set (matching the official `bw` CLI), else an
/// interactive single-line prompt. Read before the master password, since
/// `read_password` consumes the rest of stdin.
fn read_api_key() -> Result<ApiKeyCreds, u8> {
    let client_id = resolve_api_field("BW_CLIENTID", "API key client_id (user.…): ")?;
    let mut client_secret = resolve_api_field("BW_CLIENTSECRET", "API key client_secret: ")?;
    let creds = ApiKeyCreds {
        client_id,
        client_secret: client_secret.as_bytes().to_vec(),
    };
    client_secret.zeroize();
    Ok(creds)
}

/// One API-key field: the env var when set and non-empty, else a single line
/// from an interactive stdin. Errors (with guidance) when neither is available.
fn resolve_api_field(env_var: &str, prompt: &str) -> Result<String, u8> {
    if let Ok(v) = std::env::var(env_var)
        && !v.is_empty()
    {
        return Ok(v);
    }
    if !io::stdin().is_terminal() {
        eprintln!("vault: set ${env_var} (or run interactively) to supply the API key");
        return Err(2);
    }
    let mut stderr = io::stderr();
    let _ = write!(stderr, "{prompt}");
    let _ = stderr.flush();
    let mut line = String::new();
    // Bind the read result before the `if let` so the `StdinLock` temporary
    // doesn't outlive the statement (clippy::significant_drop_in_scrutinee).
    let read_res = io::stdin().lock().read_line(&mut line);
    if let Err(e) = read_res {
        eprintln!("vault: failed to read input: {e}");
        return Err(2);
    }
    let trimmed = line.trim_end_matches(['\n', '\r']).to_owned();
    line.zeroize();
    if trimmed.is_empty() {
        eprintln!("vault: empty {env_var}");
        return Err(2);
    }
    Ok(trimmed)
}

/// Fire-and-acknowledge: send `req`, expect a bare `Ok`, and (only under
/// `--json`) print a `{ "<action>": true }` envelope. Human mode stays silent
/// on success, matching the pre-`--json` behaviour of `lock`/`stop-agent`.
async fn cmd_ack(ep: Endpoint<'_>, req: Request, action: &str, json: bool) -> Result<(), u8> {
    let mut stream = connect(ep).await?;
    let resp = exchange(&mut stream, &req).await?;
    match resp {
        Response::Ok => {
            print_ack(action, json);
            Ok(())
        }
        Response::Error(e) => report_error(&e),
        other => unexpected(&other),
    }
}

async fn cmd_sync(ep: Endpoint<'_>, json: bool) -> Result<(), u8> {
    let mut stream = connect(ep).await?;
    let resp = exchange(&mut stream, &Request::Sync).await?;
    match resp {
        // The agent answers a successful re-sync with a fresh Status snapshot.
        Response::Status(s) => {
            if json {
                let v = serde_json::json!({
                    "synced": true,
                    "items": s.items,
                    "last_sync": s.last_sync,
                });
                println!("{v}");
            }
            Ok(())
        }
        // Tolerate a bare Ok for forward-compat with an agent that hasn't
        // adopted the Status-returning Sync contract.
        Response::Ok => {
            print_ack("synced", json);
            Ok(())
        }
        Response::Error(e) => report_error(&e),
        other => unexpected(&other),
    }
}

async fn cmd_list(ep: Endpoint<'_>, json: bool) -> Result<(), u8> {
    let mut stream = connect(ep).await?;
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

async fn cmd_remove(ep: Endpoint<'_>, selector: String, force: bool, json: bool) -> Result<(), u8> {
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
    let mut stream = connect(ep).await?;
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

/// `vault config get/set/unset`. No agent or server interaction — pure local
/// file I/O against `$XDG_CONFIG_HOME/vault/config.toml`.
fn cmd_config(action: ConfigAction) -> Result<(), u8> {
    match action {
        ConfigAction::Get { key, json } => cmd_config_get(key.as_deref(), json),
        ConfigAction::Set { key, value, json } => {
            let mut cfg = load_config()?;
            if let Err(msg) = cfg.set(&key, &value) {
                eprintln!("vault: {msg}");
                return Err(2);
            }
            save_config(&cfg)?;
            if json {
                println!("{}", serde_json::json!({ "set": key, "value": value }));
            }
            Ok(())
        }
        ConfigAction::Unset { key, json } => {
            let mut cfg = load_config()?;
            if let Err(msg) = cfg.unset(&key) {
                eprintln!("vault: {msg}");
                return Err(2);
            }
            save_config(&cfg)?;
            if json {
                println!("{}", serde_json::json!({ "unset": key }));
            }
            Ok(())
        }
    }
}

fn cmd_config_get(key: Option<&str>, json: bool) -> Result<(), u8> {
    let cfg = load_config()?;
    if let Some(key) = key {
        let value = match cfg.get(key) {
            Ok(v) => v,
            Err(bad) => {
                eprintln!("vault: unknown config key '{bad}'");
                return Err(2);
            }
        };
        if json {
            println!("{}", serde_json::json!({ "key": key, "value": value }));
        } else if let Some(v) = value {
            println!("{v}");
        } else {
            println!("(unset)");
        }
        return Ok(());
    }
    // No key: list every known key with its effective value.
    if json {
        let map: serde_json::Map<String, serde_json::Value> = config::KNOWN_KEYS
            .iter()
            .map(|k| {
                let v = cfg.get(k).ok().flatten();
                (
                    (*k).to_owned(),
                    v.map_or(serde_json::Value::Null, Into::into),
                )
            })
            .collect();
        println!("{}", serde_json::Value::Object(map));
    } else {
        for k in config::KNOWN_KEYS {
            let v = cfg.get(k).ok().flatten();
            println!("{k} = {}", v.as_deref().unwrap_or("(unset)"));
        }
    }
    Ok(())
}

fn load_config() -> Result<config::Config, u8> {
    config::load().map_err(|msg| {
        eprintln!("vault: {msg}");
        2
    })
}

fn save_config(cfg: &config::Config) -> Result<(), u8> {
    config::save(cfg).map(|_| ()).map_err(|msg| {
        eprintln!("vault: {msg}");
        2
    })
}

/// `vault purge` — drop the agent's in-memory keys (best-effort, no spawn) and
/// remove the on-disk item cache. Confirmation-gated like `remove`.
async fn cmd_purge(ep: Endpoint<'_>, force: bool, json: bool) -> Result<(), u8> {
    let Some(dir) = vault_store::default_data_dir() else {
        eprintln!("vault: could not locate the data directory");
        return Err(2);
    };
    if !force {
        if !io::stdin().is_terminal() {
            eprintln!("vault: refusing to purge without --force when stdin is not a TTY");
            return Err(2);
        }
        let mut stderr = io::stderr();
        let _ = write!(stderr, "Purge local cache at {}? [y/N]: ", dir.display());
        let _ = stderr.flush();
        let mut buf = String::new();
        if io::stdin().lock().read_line(&mut buf).is_err() {
            eprintln!("vault: failed to read confirmation");
            return Err(2);
        }
        if !matches!(buf.trim(), "y" | "Y" | "yes") {
            eprintln!("vault: aborted");
            return Err(2);
        }
    }

    // Best-effort: drop in-memory keys if an agent is already up. Connect
    // directly (not via `connect`, which prints a start-the-daemon hint) so a
    // down agent stays silent; never auto-spawn one just to lock it.
    if let Ok(mut stream) = UnixStream::connect(ep.socket).await {
        let _ = exchange(&mut stream, &Request::Lock).await;
    }

    // Removing the cache dir is the actual purge; an absent dir is success.
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            eprintln!("vault: could not remove {}: {e}", dir.display());
            return Err(9);
        }
    }
    if json {
        println!(
            "{}",
            serde_json::json!({ "purged": true, "path": dir.display().to_string() })
        );
    } else {
        println!("purged {}", dir.display());
    }
    Ok(())
}

/// Parsed `vault add` arguments (bundled to keep the handler signature small).
struct AddArgs {
    name: String,
    kind: KindArg,
    username: Option<String>,
    uri: Option<String>,
    folder: Option<String>,
    notes: Option<String>,
    generate: Option<usize>,
    cardholder: Option<String>,
    brand: Option<String>,
    expiry: Option<String>,
    identity: IdentityArgs,
    json: bool,
}

async fn cmd_add(ep: Endpoint<'_>, args: AddArgs) -> Result<(), u8> {
    let cipher_type = args.kind.cipher_type();
    let is_login = matches!(args.kind, KindArg::Login);

    // Card (type 3): non-secret fields from flags; number/CVV prompted on the
    // controlling terminal (never argv — they'd leak to shell history / ps).
    let card = if matches!(args.kind, KindArg::Card) {
        let (exp_month, exp_year) = split_expiry(args.expiry.as_deref())?;
        Some(CardWrite {
            cardholder: args.cardholder,
            brand: args.brand,
            number: read_tty_line("Card number: ").map(String::into_bytes),
            exp_month,
            exp_year,
            code: read_tty_line("CVV (leave empty for none): ").map(String::into_bytes),
        })
    } else {
        None
    };

    // Identity (type 4): non-secret fields from flags; ssn/passport/license
    // prompted on the terminal when their bool flag is set.
    let identity = matches!(args.kind, KindArg::Identity).then(|| args.identity.into_write());

    // Password (login only): generate locally or read from stdin. Empty stdin
    // means "no password" — a login with just a username is valid.
    let mut generated: Option<Zeroizing<String>> = None;
    let password = if is_login {
        if let Some(len) = args.generate {
            let pw = generate_pw(len)?;
            let bytes = pw.as_bytes().to_vec();
            generated = Some(pw);
            Some(bytes)
        } else {
            read_secret("Password (leave empty for none): ")?
        }
    } else {
        None
    };
    let (username, uri) = if is_login {
        (args.username, args.uri)
    } else {
        (None, None)
    };

    let req = Request::Add {
        name: args.name,
        cipher_type,
        folder: args.folder,
        notes: args.notes,
        username,
        password,
        totp: None,
        uri,
        card,
        identity,
    };
    let mut stream = connect(ep).await?;
    let resp = exchange(&mut stream, &req).await?;
    match resp {
        Response::Saved(s) => {
            print_saved(&s, args.json, generated.as_ref().map(|z| z.as_str()));
            Ok(())
        }
        Response::Error(e) => report_error(&e),
        other => unexpected(&other),
    }
}

/// Parsed `vault edit` arguments.
#[allow(clippy::struct_excessive_bools)] // independent CLI flags (password/number/code/json), not a state enum
struct EditArgs {
    selector: String,
    name: Option<String>,
    username: Option<String>,
    uri: Option<String>,
    folder: Option<String>,
    notes: Option<String>,
    password: bool,
    generate: Option<usize>,
    cardholder: Option<String>,
    brand: Option<String>,
    expiry: Option<String>,
    number: bool,
    code: bool,
    identity: IdentityArgs,
    json: bool,
}

async fn cmd_edit(ep: Endpoint<'_>, args: EditArgs) -> Result<(), u8> {
    let mut generated: Option<Zeroizing<String>> = None;
    let password = if let Some(len) = args.generate {
        let pw = generate_pw(len)?;
        let bytes = pw.as_bytes().to_vec();
        generated = Some(pw);
        Some(bytes)
    } else if args.password {
        let Some(b) = read_secret("New password: ")? else {
            eprintln!("vault: empty password; nothing changed");
            return Err(2);
        };
        Some(b)
    } else {
        None
    };

    // Card edit: build a CardWrite if any card flag was passed. Secrets
    // (number/CVV) are prompted on the terminal when their bool flag is set.
    let card = if args.cardholder.is_some()
        || args.brand.is_some()
        || args.expiry.is_some()
        || args.number
        || args.code
    {
        let (exp_month, exp_year) = split_expiry(args.expiry.as_deref())?;
        Some(CardWrite {
            cardholder: args.cardholder,
            brand: args.brand,
            number: args
                .number
                .then(|| read_tty_line("New card number: ").map(String::into_bytes))
                .flatten(),
            exp_month,
            exp_year,
            code: args
                .code
                .then(|| read_tty_line("New CVV: ").map(String::into_bytes))
                .flatten(),
        })
    } else {
        None
    };

    // Identity edit: build a write if any identity flag was passed; sensitive
    // fields are prompted on the terminal when their bool flag is set.
    let identity = args.identity.any_set().then(|| args.identity.into_write());

    let req = Request::Edit {
        selector: args.selector,
        name: args.name,
        folder: args.folder,
        notes: args.notes,
        username: args.username,
        password,
        totp: None,
        uri: args.uri,
        card,
        identity,
    };
    let mut stream = connect(ep).await?;
    let resp = exchange(&mut stream, &req).await?;
    match resp {
        Response::Saved(s) => {
            print_saved(&s, args.json, generated.as_ref().map(|z| z.as_str()));
            Ok(())
        }
        Response::Error(e) => report_error(&e),
        other => unexpected(&other),
    }
}

/// Split a `MM/YYYY` or `MM/YY` expiry into `(month, year)` strings (month
/// normalized to no leading zero, two-digit year expanded to `20YY`). Returns
/// `(None, None)` when no expiry was given; exit code 2 on a malformed value.
fn split_expiry(expiry: Option<&str>) -> Result<(Option<String>, Option<String>), u8> {
    let Some(raw) = expiry else {
        return Ok((None, None));
    };
    let bad = || {
        eprintln!("vault: --expiry must be MM/YYYY or MM/YY, got '{raw}'");
        2u8
    };
    let (m, y) = raw.split_once('/').ok_or_else(bad)?;
    let month: u32 = m.trim().parse().map_err(|_| bad())?;
    if !(1..=12).contains(&month) {
        return Err(bad());
    }
    let y = y.trim();
    if y.is_empty() || !y.chars().all(|c| c.is_ascii_digit()) {
        return Err(bad());
    }
    let year = if y.len() == 2 {
        format!("20{y}")
    } else {
        y.to_owned()
    };
    Ok((Some(month.to_string()), Some(year)))
}

/// Generate a password locally, surfacing generator errors as exit code 2.
fn generate_pw(len: usize) -> Result<Zeroizing<String>, u8> {
    let opts = vault_core::GenerateOptions {
        length: len,
        ..vault_core::GenerateOptions::default()
    };
    vault_core::generate_password(&opts).map_err(|e| {
        eprintln!("vault: {e}");
        2
    })
}

/// Read an optional secret from stdin. Returns `None` for empty input (after a
/// single trailing newline). Prompts on a TTY; never echoes via argv.
fn read_secret(prompt: &str) -> Result<Option<Vec<u8>>, u8> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        let mut stderr = io::stderr();
        let _ = write!(stderr, "{prompt}");
        let _ = stderr.flush();
    }
    let mut buf = String::new();
    let read_res = stdin.lock().read_to_string(&mut buf);
    if let Err(e) = read_res {
        eprintln!("vault: failed to read input: {e}");
        return Err(2);
    }
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    if buf.is_empty() {
        buf.zeroize();
        return Ok(None);
    }
    let bytes = buf.as_bytes().to_vec();
    buf.zeroize();
    Ok(Some(bytes))
}

async fn cmd_get(ep: Endpoint<'_>, name: String, field: Field, json: bool) -> Result<(), u8> {
    let mut stream = connect(ep).await?;
    let req = Request::Get {
        // The CLI selects by name only; id-targeting is a TUI affordance.
        id: None,
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

async fn connect(ep: Endpoint<'_>) -> Result<UnixStream, u8> {
    match UnixStream::connect(ep.socket).await {
        Ok(s) => Ok(s),
        // A missing or stale socket means no live agent — start one (PRD
        // §7.3) unless the user opted out.
        Err(e) if ep.auto_spawn && spawn::socket_is_dead(&e) => {
            spawn::spawn_and_connect(ep.socket).await.map_err(|msg| {
                eprintln!(
                    "vault: {msg}\n\
                     vault: could not connect to agent at {}: {e}",
                    ep.socket.display()
                );
                3
            })
        }
        Err(e) => {
            eprintln!(
                "vault: could not connect to agent at {}: {e}\n\
                 hint: start the daemon with `vault-agent &` if it is not running.",
                ep.socket.display()
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
        IpcError::Offline => 11,
        IpcError::BadPin { .. } => 12,
        IpcError::PinLockedOut => 13,
        IpcError::PinNotSet => 14,
        IpcError::Network(_)
        | IpcError::Internal(_)
        | IpcError::Decrypt(_)
        | IpcError::ClipboardUnavailable => 9,
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

/// Print a `{ "<action>": true }` acknowledgement under `--json`; stay silent
/// otherwise. Used by `lock` / `unlock` / `stop-agent` (and `sync`'s
/// forward-compat path), all of which carry no payload on success.
fn print_ack(action: &str, json: bool) {
    if json {
        let mut map = serde_json::Map::new();
        map.insert(action.to_owned(), serde_json::Value::Bool(true));
        println!("{}", serde_json::Value::Object(map));
    }
}

/// Verbose `login` success: who we're authenticated as plus the post-sync
/// item count / timestamp from the agent's status snapshot.
fn print_login_summary(email: &str, s: &Status, json: bool) {
    use std::fmt::Write as _;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "logged_in": true,
                "email": email,
                "items": s.items,
                "last_sync": s.last_sync,
            })
        );
        return;
    }
    let mut line = format!("logged in as {email}");
    if let Some(n) = s.items {
        let _ = write!(line, " · {n} items");
    }
    if let Some(ts) = s.last_sync.as_deref() {
        let _ = write!(line, " · synced {ts}");
    }
    println!("{line}");
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
            "clipboard_backend": s.clipboard_backend,
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
    if let Some(v) = s.clipboard_backend.as_deref() {
        println!("clipboard:     {v}");
    }
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

fn print_saved(s: &Saved, json: bool, generated: Option<&str>) {
    if json {
        let mut v = serde_json::json!({
            "id": s.id,
            "name": s.name,
            "saved": true,
        });
        if let Some(pw) = generated {
            v["generated_password"] = serde_json::Value::String(pw.to_owned());
        }
        println!("{v}");
    } else {
        println!("saved: {} ({})", s.name, s.id);
        if let Some(pw) = generated {
            println!("generated password: {pw}");
        }
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

#[cfg(test)]
mod tests {
    use super::split_expiry;

    #[test]
    fn split_expiry_parses_and_normalizes() {
        assert_eq!(
            split_expiry(Some("04/2030")).unwrap(),
            (Some("4".into()), Some("2030".into()))
        );
        // Two-digit year expands; leading-zero month normalizes.
        assert_eq!(
            split_expiry(Some("4/30")).unwrap(),
            (Some("4".into()), Some("2030".into()))
        );
        // No expiry → both None.
        assert_eq!(split_expiry(None).unwrap(), (None, None));
        // Malformed → error.
        assert!(split_expiry(Some("2030")).is_err()); // no slash
        assert!(split_expiry(Some("13/2030")).is_err()); // bad month
        assert!(split_expiry(Some("04/abcd")).is_err()); // non-numeric year
    }
}
