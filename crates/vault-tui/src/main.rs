// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault TUI — `vault-tui` binary entry point.
//!
//! M5 slice 1: a read-only, cruxpass-style three-pane browser over the agent.
//! It is just another UDS client (the user key never crosses into it) and drives
//! only `Request::Status` + `Request::List`. Search / copy / generate land in
//! later slices. Requires a pre-unlocked agent; a locked or absent agent shows a
//! centered banner.

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

use vault_ipc::proto::{Request, Response};
use vault_ipc::{default_socket_path, sanitize_socket_path};

use app::App;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

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

/// Translate one key press into an [`App`] action. Non-press events (key release
/// on Windows) are ignored; unbound keys are no-ops.
async fn handle_key(state: &mut App, key: KeyEvent, socket: &Path) {
    if key.kind != KeyEventKind::Press {
        return;
    }
    // Ctrl+C always quits, regardless of which character key carries it.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        state.quit();
        return;
    }
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => state.quit(),
        KeyCode::Char('j') | KeyCode::Down => state.move_down(),
        KeyCode::Char('k') | KeyCode::Up => state.move_up(),
        KeyCode::Tab | KeyCode::Left | KeyCode::Right | KeyCode::Char('h' | 'l') => {
            state.focus_next();
        }
        KeyCode::Char('r') => *state = load_app(socket).await,
        _ => {}
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
