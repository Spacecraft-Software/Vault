// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault TUI — `vault-tui` binary entry point.
//!
//! A cruxpass-style three-pane browser over the agent. It is just another UDS
//! client (the user key never crosses into it) and drives `Request::Status` +
//! `Request::List` for browsing, `Request::Get` for reveal-on-demand, and
//! `Request::Copy` / `Request::CopyText` for clipboard copies (the secret
//! stays in the agent on the `Copy` path; `CopyText` carries the locally
//! generated password the other way, like `Unlock`'s does). `/` filters the
//! item list live, `g` opens the password-generator overlay, and `:` opens a
//! small command line (`q` / `r` / `sync` / `lock`). Item editing lands in a
//! later slice. Requires a pre-unlocked agent; a locked or absent agent shows
//! a centered banner.

#![forbid(unsafe_code)]

mod app;
mod client;
mod ui;

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::mpsc;

use vault_ipc::proto::{Field, Request, Response};
use vault_ipc::{default_socket_path, sanitize_socket_path};

use app::{App, InputMode, RevealedSecret};

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Seconds the agent keeps a copied secret on the clipboard before wiping it.
/// Mirrors the agent's own default and is surfaced in the copy toast so the
/// user knows the window.
const COPY_CLEAR_SECS: u64 = 30;

/// Standard §13.2 attribution block — surfaced via `--version` and `--help`.
const ATTRIBUTION: &str = "\
Maintained by Mohamed Hammad <Mohamed.Hammad@SpacecraftSoftware.org>
Copyright (C) 2026 Mohamed Hammad & Spacecraft Software  |  License: GPL-3.0-or-later
https://Vault.SpacecraftSoftware.org/";

/// `--version` payload — clap surfaces `after_help` only on `--help`, so the
/// §13.2 block rides in `long_version` (mirrors `vault` / `vault-agent`).
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\n",
    "Maintained by Mohamed Hammad <Mohamed.Hammad@SpacecraftSoftware.org>\n",
    "Copyright (C) 2026 Mohamed Hammad & Spacecraft Software  |  License: GPL-3.0-or-later\n",
    "https://Vault.SpacecraftSoftware.org/",
);

#[derive(Parser, Debug)]
#[command(
    name = "vault-tui",
    version = PKG_VERSION,
    long_version = LONG_VERSION,
    about = "Vault TUI — terminal browser for your Bitwarden vault",
    after_help = ATTRIBUTION,
    after_long_help = ATTRIBUTION,
)]
struct Cli {
    /// Override the agent socket path. Defaults to `$VAULT_AGENT_SOCK` or
    /// `$XDG_RUNTIME_DIR/vault/agent.sock`.
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let socket = match resolve_socket(cli.socket) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vault-tui: {e}");
            return ExitCode::from(2);
        }
    };
    match run(&socket).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vault-tui: {e}");
            ExitCode::FAILURE
        }
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

/// Set up the terminal, run the event loop, and tear the terminal back down on
/// every exit path (including panic).
async fn run(socket: &Path) -> anyhow::Result<()> {
    let mut state = load_app(socket).await;

    install_panic_hook();
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let _restore = Restore; // RAII: restores the terminal on drop / unwind.
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    // Input runs on a dedicated OS thread (crossterm `read()` is blocking) and
    // is forwarded over an unbounded channel; the loop awaits it, so there's no
    // busy-poll. The thread is reaped when the process exits.
    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if tx.send(ev).is_err() {
                break;
            }
        }
    });

    loop {
        terminal.draw(|f| ui::render(f, &state))?;
        if state.should_quit {
            break;
        }
        match rx.recv().await {
            Some(Event::Key(key)) => handle_key(&mut state, key, socket).await,
            Some(_) => {}  // resize / mouse / focus — redraw on next iteration
            None => break, // input thread gone
        }
    }
    Ok(())
}

/// Query the agent and build the initial (or refreshed) [`App`].
async fn load_app(socket: &Path) -> App {
    match client::request(socket, &Request::Status).await {
        Err(e) => App::message("No agent", e.to_string(), None),
        Ok(Response::Status(s)) if s.unlocked => {
            match client::request(socket, &Request::List).await {
                Ok(Response::List(items)) => App::browsing(s, items),
                Ok(Response::Error(err)) => App::message("Error", err.to_string(), Some(s)),
                Ok(other) => {
                    App::message("Error", format!("unexpected response: {other:?}"), Some(s))
                }
                Err(e) => App::message("Error", e.to_string(), Some(s)),
            }
        }
        Ok(Response::Status(s)) => App::message(
            "Locked",
            "Run `vault unlock` to browse your vault, then press r.",
            Some(s),
        ),
        Ok(Response::Error(err)) => App::message("Error", err.to_string(), None),
        Ok(other) => App::message("Error", format!("unexpected response: {other:?}"), None),
    }
}

/// Translate one key press into an [`App`] action, routed by input mode.
/// Non-press events (key release on Windows) are ignored; unbound keys are
/// no-ops.
async fn handle_key(state: &mut App, key: KeyEvent, socket: &Path) {
    if key.kind != KeyEventKind::Press {
        return;
    }
    // Ctrl+C always quits, regardless of mode or which key carries it.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        state.quit();
        return;
    }
    // Each key press supersedes the previous transient message.
    state.clear_toast();
    match state.mode {
        InputMode::Normal => handle_normal_key(state, key, socket).await,
        InputMode::Search => handle_search_key(state, key),
        InputMode::Command => handle_command_key(state, key, socket).await,
        InputMode::Generate => handle_generate_key(state, key, socket).await,
    }
}

/// Normal-mode keys — navigation, reveal/copy, and mode entry.
async fn handle_normal_key(state: &mut App, key: KeyEvent, socket: &Path) {
    match key.code {
        KeyCode::Char('q') => state.quit(),
        // Esc peels back one layer: an active search filter first, then quit.
        KeyCode::Esc => {
            if state.has_search() {
                state.clear_search();
            } else {
                state.quit();
            }
        }
        KeyCode::Char('j') | KeyCode::Down => state.move_down(),
        KeyCode::Char('k') | KeyCode::Up => state.move_up(),
        KeyCode::Tab | KeyCode::Left | KeyCode::Right | KeyCode::Char('h' | 'l') => {
            state.focus_next();
        }
        KeyCode::Char('r') => *state = load_app(socket).await,
        KeyCode::Char(' ') => toggle_reveal(state, socket).await,
        KeyCode::Char('c') => copy_field(state, socket, Field::Password, "password").await,
        KeyCode::Char('u') => copy_field(state, socket, Field::Username, "username").await,
        KeyCode::Char('o') => copy_field(state, socket, Field::Uri, "URI").await,
        KeyCode::Char('/') => state.open_search(),
        KeyCode::Char(':') => state.open_command(),
        KeyCode::Char('g') => state.open_generator(),
        _ => {}
    }
}

/// Search-mode keys — live query editing; arrows still move the selection so
/// the user can pick a hit without leaving the mode.
fn handle_search_key(state: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => state.cancel_search(),
        KeyCode::Enter => state.accept_search(),
        KeyCode::Backspace => state.search_pop(),
        KeyCode::Down => state.move_down(),
        KeyCode::Up => state.move_up(),
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.search_push(c);
        }
        _ => {}
    }
}

/// Command-mode keys — edit the `:` buffer; Enter executes it.
async fn handle_command_key(state: &mut App, key: KeyEvent, socket: &Path) {
    match key.code {
        KeyCode::Esc => state.cancel_command(),
        KeyCode::Backspace => state.command_pop(),
        KeyCode::Enter => {
            let cmd = state.take_command();
            execute_command(state, socket, &cmd).await;
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.command_push(c);
        }
        _ => {}
    }
}

/// Generator-overlay keys.
async fn handle_generate_key(state: &mut App, key: KeyEvent, socket: &Path) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => state.close_generator(),
        KeyCode::Char('g' | 'r') => state.regenerate(),
        KeyCode::Char('+' | '=') => state.gen_adjust_length(1),
        KeyCode::Char('-') => state.gen_adjust_length(-1),
        KeyCode::Char('s') => state.gen_toggle_symbols(),
        KeyCode::Char('c') => copy_generated(state, socket).await,
        _ => {}
    }
}

/// Run one `:` command. The vocabulary is deliberately tiny — anything that
/// needs arguments or confirmation belongs to a dedicated key or later slice.
async fn execute_command(state: &mut App, socket: &Path, cmd: &str) {
    match cmd.trim() {
        "" => {}
        "q" | "quit" => state.quit(),
        "r" | "refresh" => {
            *state = load_app(socket).await;
            state.set_toast("refreshed");
        }
        "sync" => match client::request(socket, &Request::Sync).await {
            Ok(Response::Status(_)) => {
                *state = load_app(socket).await;
                state.set_toast("synced");
            }
            Ok(Response::Error(e)) => state.set_toast(format!("sync failed: {e}")),
            Ok(other) => state.set_toast(format!("unexpected response: {other:?}")),
            Err(e) => state.set_toast(e.to_string()),
        },
        "lock" => {
            match client::request(socket, &Request::Lock).await {
                // Reload so the screen flips to the Locked banner.
                Ok(Response::Ok) => *state = load_app(socket).await,
                Ok(Response::Error(e)) => state.set_toast(format!("lock failed: {e}")),
                Ok(other) => state.set_toast(format!("unexpected response: {other:?}")),
                Err(e) => state.set_toast(e.to_string()),
            }
        }
        other => state.set_toast(format!("unknown command: {other} (q · r · sync · lock)")),
    }
}

/// Ask the agent to put the overlay's generated password on the clipboard via
/// `CopyText`, with the same timed auto-clear as item copies. The value rides
/// the local UDS once, exactly like `Unlock`'s password does.
async fn copy_generated(state: &mut App, socket: &Path) {
    let Some(text) = state
        .generator
        .as_ref()
        .map(|g| g.password().as_bytes().to_vec())
    else {
        return;
    };
    let req = Request::CopyText {
        text,
        clear_after_secs: Some(COPY_CLEAR_SECS),
    };
    match client::request(socket, &req).await {
        Ok(Response::Ok) => {
            state.set_toast(format!(
                "copied generated password · clears in {COPY_CLEAR_SECS}s"
            ));
        }
        Ok(Response::Error(e)) => state.set_toast(format!("copy failed: {e}")),
        Ok(other) => state.set_toast(format!("unexpected response: {other:?}")),
        Err(e) => state.set_toast(e.to_string()),
    }
}

/// Toggle reveal of the selected item's password in the detail pane. The first
/// press fetches the plaintext from the agent (id-targeted, so duplicate names
/// can't mislead it); the second re-masks. No-op unless the item list is
/// focused and a row is selected.
async fn toggle_reveal(state: &mut App, socket: &Path) {
    if !state.items_focused() {
        return;
    }
    let Some(sel) = state.selected_entry() else {
        return;
    };
    if state.is_revealed(&sel.id, Field::Password) {
        state.hide_revealed();
        return;
    }
    let req = Request::Get {
        id: Some(sel.id.clone()),
        name: sel.name.clone(),
        field: Some(Field::Password),
    };
    match client::request(socket, &req).await {
        Ok(Response::Item(item)) => {
            state.reveal(RevealedSecret::new(
                sel.id,
                Field::Password,
                item.value.clone(),
            ));
        }
        Ok(Response::Error(e)) => state.set_toast(format!("reveal failed: {e}")),
        Ok(other) => state.set_toast(format!("unexpected response: {other:?}")),
        Err(e) => state.set_toast(e.to_string()),
    }
}

/// Ask the agent to copy `field` of the selected item to the clipboard, with a
/// timed auto-clear. The secret stays in the agent and never enters this
/// process. No-op unless the item list is focused and a row is selected.
async fn copy_field(state: &mut App, socket: &Path, field: Field, label: &str) {
    if !state.items_focused() {
        return;
    }
    let Some(sel) = state.selected_entry() else {
        return;
    };
    let req = Request::Copy {
        id: Some(sel.id),
        name: sel.name,
        field: Some(field),
        clear_after_secs: Some(COPY_CLEAR_SECS),
    };
    match client::request(socket, &req).await {
        Ok(Response::Ok) => {
            state.set_toast(format!("copied {label} · clears in {COPY_CLEAR_SECS}s"));
        }
        Ok(Response::Error(e)) => state.set_toast(format!("copy failed: {e}")),
        Ok(other) => state.set_toast(format!("unexpected response: {other:?}")),
        Err(e) => state.set_toast(e.to_string()),
    }
}

/// Restore the terminal to its cooked state. Best-effort: errors are ignored
/// because this also runs from the panic hook, where there's nothing to return
/// an error to.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

/// RAII terminal-restore guard.
struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Chain a terminal-restore in front of the default panic hook so a panic never
/// leaves the user staring at a raw-mode alternate screen.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        default(info);
    }));
}
