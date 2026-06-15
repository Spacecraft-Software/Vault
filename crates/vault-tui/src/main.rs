// SPDX-License-Identifier: GPL-3.0-or-later

//! Vault TUI — `vault-tui` binary entry point.
//!
//! A cruxpass-style three-pane browser over the agent. It is just another UDS
//! client (the user key never crosses into it) and drives `Request::Status` +
//! `Request::List` for browsing, `Request::Get` for reveal-on-demand, and
//! `Request::Copy` / `Request::CopyText` for clipboard copies (the secret
//! stays in the agent on the `Copy` path; `CopyText` carries the locally
//! generated password the other way, like `Unlock`'s does). `/` filters the
//! item list live, `g` opens the password-generator overlay, `:` opens a
//! small command line (`q` / `r` / `sync` / `lock`), and `a` / `e` / `d`
//! drive `Request::Add` / `Edit` / `Remove` through a form overlay and a
//! delete confirm. Requires a pre-unlocked agent; a locked or absent agent
//! shows a centered banner.

#![forbid(unsafe_code)]

mod app;
mod client;
mod osc52;
mod ui;

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::mpsc;

use vault_ipc::proto::{Error as IpcError, Field, Request, Response, Status};
use vault_ipc::{default_socket_path, sanitize_socket_path};

use app::{App, FormKind, FormSubmit, InputMode, RevealedSecret, UnlockState};

pub(crate) const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Seconds before the TUI's own OSC52 fallback clear fires. Agent-side copies
/// use the agent's configured default (`--clipboard-clear-secs`, reported back
/// in `Response::Copied`); this constant only governs the terminal-clipboard
/// path, where the TUI runs the timer itself.
const COPY_CLEAR_SECS: u64 = 30;

/// Standard §13.2 attribution block — surfaced via `--version`, `--help`, and
/// the TUI About overlay (`?` / `:about`).
pub(crate) const ATTRIBUTION: &str = "\
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
    execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
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
        // Refresh the card/identity detail cache for the current selection
        // before drawing (cheap no-op unless the selection changed).
        ensure_detail(&mut state, socket).await;
        terminal.draw(|f| ui::render(f, &state))?;
        if state.should_quit {
            break;
        }
        // When an OSC52 fallback copy is pending its timed clear, race the
        // input channel against the deadline so the clear fires even while
        // the user is idle.
        let ev = if let Some(at) = state.osc52_clear_at {
            tokio::select! {
                ev = rx.recv() => ev,
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(at)) => {
                    let _ = osc52::clear();
                    state.osc52_clear_at = None;
                    state.set_toast("clipboard cleared (OSC52)");
                    continue;
                }
            }
        } else {
            rx.recv().await
        };
        match ev {
            Some(Event::Key(key)) => handle_key(&mut state, key, socket).await,
            Some(Event::Paste(s)) => state.input_insert_str(&s),
            Some(_) => {}  // resize / mouse / focus — redraw on next iteration
            None => break, // input thread gone
        }
    }
    // Quitting with an OSC52 clear still pending: sweep before the terminal
    // is restored — mirrors the agent's own clear-on-shutdown.
    if state.osc52_clear_at.is_some() {
        let _ = osc52::clear();
    }
    Ok(())
}

/// Query the agent and build the initial (or refreshed) [`App`].
async fn load_app(socket: &Path) -> App {
    let mut app = match client::request(socket, &Request::Status).await {
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
        Ok(Response::Status(s)) => locked_screen(socket, s).await,
        Ok(Response::Error(err)) => App::message("Error", err.to_string(), None),
        Ok(other) => App::message("Error", format!("unexpected response: {other:?}"), None),
    };
    // Apply TUI config preferences: `tui.vim` (vim motions) and the reserved
    // `ui.reduced_motion` flag. One load, both flags.
    if let Ok(cfg) = vault_config::load() {
        app.vim = cfg.tui_vim().unwrap_or(false);
        app.reduced_motion = cfg.reduced_motion().unwrap_or(false);
    }
    app
}

/// Build the locked screen: an interactive unlock prompt when an account is
/// registered, else a banner telling the user to register first.
async fn locked_screen(socket: &Path, s: Status) -> App {
    let cfg = vault_config::load().unwrap_or_default();
    let account = cfg.account();
    let (Some(server), Some(email)) = (account.server.clone(), account.email.clone()) else {
        return App::message(
            "Locked",
            "No account registered — run `vault register` (then `vault login`), then press r.",
            Some(s),
        );
    };
    // Whether a PIN is enrolled drives offering the Tab toggle (best-effort).
    let pin_enabled = matches!(
        client::request(socket, &Request::PinStatus { server: server.clone(), email: email.clone() }).await,
        Ok(Response::PinStatus(p)) if p.enabled
    );
    App::unlock_screen(
        s,
        app::UnlockState {
            server,
            email,
            device_id: account.device_id.clone(),
            secret: app::TextInput::default(),
            use_pin: false,
            pin_enabled,
            error: None,
            awaiting_2fa: false,
            password: zeroize::Zeroizing::new(Vec::new()),
        },
    )
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
        InputMode::Form => handle_form_key(state, key, socket).await,
        InputMode::ConfirmDelete => handle_confirm_key(state, key, socket).await,
        InputMode::Unlock => handle_unlock_key(state, key, socket).await,
        InputMode::About => handle_about_key(state, key),
    }
}

/// Unlock-screen keys — edit the secret, `Tab` toggles password/PIN, `Enter`
/// submits, `Esc` quits. On success the app reloads into the browser.
async fn handle_unlock_key(state: &mut App, key: KeyEvent, socket: &Path) {
    if handle_text_edit_key(state, key) {
        return;
    }
    match key.code {
        KeyCode::Esc => state.quit(),
        KeyCode::Tab | KeyCode::BackTab => state.toggle_pin(),
        KeyCode::Backspace => {
            if let Some(u) = state.unlock.as_mut() {
                u.secret.backspace();
            }
        }
        KeyCode::Enter => submit_unlock(state, socket).await,
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(u) = state.unlock.as_mut() {
                u.secret.insert(c);
            }
        }
        _ => {}
    }
}

/// Send the unlock request; on success reload into the browser, on error show
/// it under the field (and clear the secret).
async fn submit_unlock(state: &mut App, socket: &Path) {
    let Some(req) = state.unlock.as_ref().map(UnlockState::request) else {
        return;
    };
    let resp = client::request(socket, &req).await;
    drop(req);
    match resp {
        Ok(Response::Ok) => *state = load_app(socket).await,
        // A 2FA challenge isn't a failure: stash the password and switch the
        // field to the authenticator code (or show "wrong code" if already in
        // that step).
        Ok(Response::Error(IpcError::TwoFactorRequired)) => {
            if let Some(u) = state.unlock.as_mut() {
                if u.awaiting_2fa {
                    u.error = Some("incorrect code — try again".to_owned());
                    u.secret.clear();
                } else {
                    u.begin_2fa();
                }
            }
        }
        Ok(Response::Error(e)) => state.unlock_failed(e.to_string()),
        Ok(other) => state.unlock_failed(format!("unexpected response: {other:?}")),
        Err(e) => state.unlock_failed(e.to_string()),
    }
}

/// Normal-mode keys — navigation, reveal/copy, and mode entry.
async fn handle_normal_key(state: &mut App, key: KeyEvent, socket: &Path) {
    // Vim mode (`tui.vim`) adds jump motions and remaps the generator to Ctrl-g
    // so `g` can be the `gg` prefix. Intercept before the normal match (which
    // matches `g`/`u`/`d` without checking modifiers).
    if state.vim {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('g') if !ctrl => {
                if state.take_pending_g() {
                    state.move_top();
                } else {
                    state.arm_pending_g();
                }
                return;
            }
            KeyCode::Char('g') if ctrl => {
                state.clear_pending_g();
                state.open_generator();
                return;
            }
            KeyCode::Char('G') => {
                state.clear_pending_g();
                state.move_bottom();
                return;
            }
            KeyCode::Char('d') if ctrl => {
                state.clear_pending_g();
                state.page_down();
                return;
            }
            KeyCode::Char('u') if ctrl => {
                state.clear_pending_g();
                state.page_up();
                return;
            }
            // Any other key cancels a pending `g` and falls through.
            _ => state.clear_pending_g(),
        }
    }
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
        // `c` copies the primary field for the selected item's type: login
        // password / card number / identity email.
        KeyCode::Char('c') => {
            if let Some((field, label)) = state
                .selected_entry()
                .and_then(|e| app::primary_copy_field(e.cipher_type))
            {
                copy_field(state, socket, field, label).await;
            }
        }
        KeyCode::Char('u') => copy_field(state, socket, Field::Username, "username").await,
        KeyCode::Char('o') => copy_field(state, socket, Field::Uri, "URI").await,
        KeyCode::Char('t') => copy_field(state, socket, Field::Totp, "TOTP code").await,
        KeyCode::Char('/') => state.open_search(),
        KeyCode::Char(':') => state.open_command(),
        KeyCode::Char('g') => state.open_generator(),
        KeyCode::Char('a') => state.open_add_form(),
        KeyCode::Char('e') => state.open_edit_form(),
        KeyCode::Char('d') => state.open_confirm_delete(),
        KeyCode::Char('?') => state.open_about(),
        _ => {}
    }
}

/// About-overlay keys — read-only; any of these dismiss it.
const fn handle_about_key(state: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q' | '?') => state.close_about(),
        _ => {}
    }
}

/// Form-overlay keys — field navigation and editing; Enter submits.
async fn handle_form_key(state: &mut App, key: KeyEvent, socket: &Path) {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    // Form-specific Ctrl chords: generate into Pass, save (submit).
    if ctrl {
        match key.code {
            KeyCode::Char('g') => state.gen_into_password(),
            KeyCode::Char('s') => submit_form(state, socket).await,
            // Fall through to the shared editor for Ctrl+A/E/W/U/K/Y.
            _ if handle_text_edit_key(state, key) => {}
            _ => {}
        }
        return;
    }
    // On the Type row, ←/→/Space toggle login⇄note; in text fields the cursor
    // keys edit, so route them to the shared editor instead.
    if state.form_on_type_row() {
        match key.code {
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') => {
                state.form_toggle_type();
                return;
            }
            _ => {}
        }
    } else if handle_text_edit_key(state, key) {
        return;
    }
    match key.code {
        KeyCode::Esc => state.cancel_form(),
        KeyCode::Tab | KeyCode::Down => state.form_focus_next(),
        KeyCode::BackTab | KeyCode::Up => state.form_focus_prev(),
        KeyCode::Enter => submit_form(state, socket).await,
        KeyCode::Backspace => state.form_pop(),
        KeyCode::Char(c) => state.form_push(c),
        _ => {}
    }
}

/// Validate, diff, and send the open form as `Request::Add` / `Request::Edit`.
/// On success the vault is reloaded (the agent already patched its cache); on
/// any error the form stays open so nothing typed is lost.
async fn submit_form(state: &mut App, socket: &Path) {
    let data = match state.form_submit_data() {
        Ok(d) => d,
        Err(msg) => {
            state.set_toast(msg);
            return;
        }
    };
    let FormSubmit {
        kind,
        cipher_type,
        name,
        username,
        password,
        uri,
        folder,
        notes,
    } = data;
    let req = match kind {
        FormKind::Add => Request::Add {
            name: name.unwrap_or_default(),
            cipher_type,
            folder,
            notes,
            username,
            password: password.map(String::into_bytes),
            totp: None,
            uri,
            card: None,
        },
        FormKind::Edit { id, .. } => Request::Edit {
            selector: id,
            name,
            folder,
            notes,
            username,
            password: password.map(String::into_bytes),
            totp: None,
            uri,
            card: None,
        },
    };
    match client::request(socket, &req).await {
        Ok(Response::Saved(s)) => {
            *state = load_app(socket).await;
            state.set_toast(format!("saved '{}'", s.name));
        }
        Ok(Response::Error(e)) => state.set_toast(format!("save failed: {e}")),
        Ok(other) => state.set_toast(format!("unexpected response: {other:?}")),
        Err(e) => state.set_toast(e.to_string()),
    }
}

/// Delete-confirm keys — `y`/Enter deletes the captured target, `n`/Esc backs
/// out untouched.
async fn handle_confirm_key(state: &mut App, key: KeyEvent, socket: &Path) {
    match key.code {
        KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
            let Some((id, _)) = state.take_confirm_delete() else {
                return;
            };
            match client::request(socket, &Request::Remove { selector: id }).await {
                Ok(Response::Removed(r)) => {
                    *state = load_app(socket).await;
                    state.set_toast(format!("deleted '{}'", r.name));
                }
                Ok(Response::Error(e)) => state.set_toast(format!("delete failed: {e}")),
                Ok(other) => state.set_toast(format!("unexpected response: {other:?}")),
                Err(e) => state.set_toast(e.to_string()),
            }
        }
        KeyCode::Char('n' | 'N') | KeyCode::Esc => state.cancel_confirm(),
        _ => {}
    }
}

/// Shared readline editing keys for any text-input surface — cursor movement,
/// Delete, and the kill/yank chords. Returns `true` when it consumed the key.
/// `Ctrl+C` is intentionally absent: it stays the global quit, intercepted in
/// `handle_key` before mode dispatch.
fn handle_text_edit_key(state: &mut App, key: KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Left => state.input_left(),
        KeyCode::Right => state.input_right(),
        KeyCode::Home => state.input_home(),
        KeyCode::End => state.input_end(),
        KeyCode::Delete => state.input_delete(),
        KeyCode::Char('a') if ctrl => state.input_home(),
        KeyCode::Char('e') if ctrl => state.input_end(),
        KeyCode::Char('w') if ctrl => state.input_kill_word(),
        KeyCode::Char('u') if ctrl => state.input_kill_to_start(),
        KeyCode::Char('k') if ctrl => state.input_kill_to_end(),
        KeyCode::Char('y') if ctrl => state.input_yank(),
        _ => return false,
    }
    true
}

/// Search-mode keys — live query editing; arrows still move the selection so
/// the user can pick a hit without leaving the mode.
fn handle_search_key(state: &mut App, key: KeyEvent) {
    if handle_text_edit_key(state, key) {
        return;
    }
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
    if handle_text_edit_key(state, key) {
        return;
    }
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
        "about" => state.open_about(),
        other => state.set_toast(format!(
            "unknown command: {other} (q · r · sync · lock · about)"
        )),
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
        clear_after_secs: None,
    };
    match client::request(socket, &req).await {
        Ok(Response::Copied(c)) => {
            state.set_toast(copied_toast("generated password", c.clear_after_secs));
        }
        // No agent clipboard — the password is already local, so hand it
        // straight to the terminal.
        Ok(Response::Error(IpcError::ClipboardUnavailable)) => {
            let Some(pw) = state.generator.as_ref().map(|g| g.password().to_owned()) else {
                return;
            };
            osc52_copy(state, &pw, "generated password");
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
    // The masked secret depends on the cipher type: login password / card
    // number. Items without one (identity, secure note) can't be revealed.
    let Some(field) = app::primary_secret_field(sel.cipher_type) else {
        return;
    };
    if state.is_revealed(&sel.id, field) {
        state.hide_revealed();
        return;
    }
    let req = Request::Get {
        id: Some(sel.id.clone()),
        name: sel.name.clone(),
        field: Some(field),
    };
    match client::request(socket, &req).await {
        Ok(Response::Item(item)) => {
            state.reveal(RevealedSecret::new(sel.id, field, item.value.clone()));
        }
        Ok(Response::Error(e)) => state.set_toast(format!("reveal failed: {e}")),
        Ok(other) => state.set_toast(format!("unexpected response: {other:?}")),
        Err(e) => state.set_toast(e.to_string()),
    }
}

/// Fetch one field's value for an item, or `None` on a missing field / error.
async fn fetch_field(socket: &Path, id: &str, name: &str, field: Field) -> Option<String> {
    let req = Request::Get {
        id: Some(id.to_owned()),
        name: name.to_owned(),
        field: Some(field),
    };
    match client::request(socket, &req).await {
        Ok(Response::Item(item)) => Some(item.value.clone()),
        _ => None,
    }
}

/// Keep `state.detail` populated with the selected card/identity's non-sensitive
/// fields. A no-op when the selection is unchanged, a login/note, or absent —
/// run once per loop iteration before drawing. Sensitive fields (card number /
/// CVV) are never fetched here; they reveal on demand like passwords.
async fn ensure_detail(state: &mut App, socket: &Path) {
    let Some(sel) = state.selected_entry().filter(|_| state.items_focused()) else {
        state.detail = None;
        return;
    };
    if state.detail.as_ref().is_some_and(|d| d.id == sel.id) {
        return; // already cached for this item
    }
    let specs: &[(&str, Field)] = match sel.cipher_type {
        3 => &[("Brand", Field::CardBrand), ("Exp", Field::CardExpiry)],
        4 => &[
            ("Person", Field::IdentityName),
            ("Email", Field::IdentityEmail),
            ("Phone", Field::IdentityPhone),
            ("Address", Field::IdentityAddress),
        ],
        _ => {
            state.detail = None;
            return;
        }
    };
    let mut lines = Vec::new();
    for (label, field) in specs {
        if let Some(value) = fetch_field(socket, &sel.id, &sel.name, *field).await {
            lines.push(((*label).to_owned(), value));
        }
    }
    state.detail = Some(app::DetailView { id: sel.id, lines });
}

/// Ask the agent to copy `field` of the selected item to the clipboard, with a
/// timed auto-clear (the agent's configured default). The secret stays in the
/// agent and never enters this process — except on the OSC52 fallback, where
/// the agent has no clipboard and the TUI fetches the value to hand it to the
/// terminal instead. No-op unless the item list is focused and a row is
/// selected.
async fn copy_field(state: &mut App, socket: &Path, field: Field, label: &str) {
    if !state.items_focused() {
        return;
    }
    let Some(sel) = state.selected_entry() else {
        return;
    };
    let req = Request::Copy {
        id: Some(sel.id.clone()),
        name: sel.name.clone(),
        field: Some(field),
        clear_after_secs: None,
    };
    match client::request(socket, &req).await {
        Ok(Response::Copied(c)) => state.set_toast(copied_toast(label, c.clear_after_secs)),
        Ok(Response::Error(IpcError::ClipboardUnavailable)) => {
            osc52_field_fallback(state, socket, &sel.id, &sel.name, field, label).await;
        }
        Ok(Response::Error(e)) => state.set_toast(format!("copy failed: {e}")),
        Ok(other) => state.set_toast(format!("unexpected response: {other:?}")),
        Err(e) => state.set_toast(e.to_string()),
    }
}

/// Toast for a successful agent-side copy.
fn copied_toast(label: &str, clear_after_secs: u64) -> String {
    if clear_after_secs == 0 {
        format!("copied {label} · auto-clear off")
    } else {
        format!("copied {label} · clears in {clear_after_secs}s")
    }
}

/// OSC52 fallback for an item field: the agent has no clipboard, so fetch the
/// value (id-targeted `Get`) and hand it to the terminal, scheduling the
/// TUI-side timed clear.
async fn osc52_field_fallback(
    state: &mut App,
    socket: &Path,
    id: &str,
    name: &str,
    field: Field,
    label: &str,
) {
    let req = Request::Get {
        id: Some(id.to_owned()),
        name: name.to_owned(),
        field: Some(field),
    };
    match client::request(socket, &req).await {
        Ok(Response::Item(item)) => osc52_copy(state, &item.value, label),
        Ok(Response::Error(e)) => state.set_toast(format!("copy failed: {e}")),
        Ok(other) => state.set_toast(format!("unexpected response: {other:?}")),
        Err(e) => state.set_toast(e.to_string()),
    }
}

/// Emit an OSC52 copy and arm the TUI-side timed clear.
fn osc52_copy(state: &mut App, value: &str, label: &str) {
    match osc52::copy(value) {
        Ok(()) => {
            state.osc52_clear_at =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(COPY_CLEAR_SECS));
            state.set_toast(format!(
                "copied {label} via OSC52 · clears in {COPY_CLEAR_SECS}s"
            ));
        }
        Err(e) => state.set_toast(format!("OSC52 copy failed: {e}")),
    }
}

/// Restore the terminal to its cooked state. Best-effort: errors are ignored
/// because this also runs from the panic hook, where there's nothing to return
/// an error to.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), DisableBracketedPaste, LeaveAlternateScreen);
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
