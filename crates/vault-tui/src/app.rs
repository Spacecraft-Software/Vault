// SPDX-License-Identifier: GPL-3.0-or-later

//! TUI application state and pure navigation / filter logic.
//!
//! Everything here is synchronous and crossterm-free so it unit-tests without a
//! terminal: `main.rs` translates key events into calls on these methods (and
//! performs the agent I/O for reveal/copy), and `ui.rs` renders from this state.
//! The state holds the non-secret [`ListEntry`] metadata plus, transiently, a
//! single revealed secret ([`RevealedSecret`], zeroised on drop and re-masked
//! on any navigation), a live search query, a pending `:` command line, and
//! the password-generator overlay ([`GeneratorState`], zeroised on drop).

use std::collections::BTreeSet;
use std::fmt;

use zeroize::Zeroizing;

use vault_core::{GenerateOptions, generate_password};
use vault_ipc::proto::{Field, ListEntry, Status};

/// Smallest password the generator overlay will produce. Comfortably above the
/// four-character floor `generate_password` needs to seat one character from
/// every enabled class, and below it a generated password isn't worth copying.
const GEN_MIN_LEN: usize = 8;

/// Largest password the generator overlay will produce — matches Bitwarden's
/// own generator ceiling so saved values round-trip everywhere.
const GEN_MAX_LEN: usize = 128;

/// What keyboard input currently drives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InputMode {
    /// Normal browsing — keys are commands.
    #[default]
    Normal,
    /// `/` pressed — keys edit the live search query.
    Search,
    /// `:` pressed — keys edit a pending command line.
    Command,
    /// `g` pressed — the password-generator overlay is open.
    Generate,
}

/// Which pane currently takes navigation keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    /// Left folder pane.
    Folders,
    /// Center item list.
    Items,
}

/// What the whole screen is showing: the browser, or a centered banner (locked
/// agent / no agent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Screen {
    /// The three-pane browser is live.
    Browsing,
    /// A centered message — `title` over `body` (locked, disconnected, …).
    Message {
        /// Short heading.
        title: String,
        /// Explanatory line.
        body: String,
    },
}

/// How a folder entry filters the item list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FolderFilter {
    /// Every item.
    All,
    /// Items with no folder.
    Unfiled,
    /// Items whose folder name matches exactly.
    Named(String),
}

/// One row in the folder pane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderItem {
    /// Display label.
    pub label: String,
    /// The filter this row applies to the item list.
    pub filter: FolderFilter,
}

/// A secret currently shown in the detail pane: which item and field it
/// belongs to, plus the plaintext. The value is zeroised on drop and never
/// surfaced by `Debug`, so an `App` dump can't leak it.
#[derive(Clone)]
pub struct RevealedSecret {
    /// Id of the item the secret belongs to; reveal is dropped when the
    /// selection moves off this item.
    pub entry_id: String,
    /// Which field is revealed.
    pub field: Field,
    /// Plaintext value, held only while visible.
    value: Zeroizing<String>,
}

impl RevealedSecret {
    /// Wrap a freshly-fetched plaintext for display.
    #[must_use]
    pub fn new(entry_id: String, field: Field, value: String) -> Self {
        Self {
            entry_id,
            field,
            value: Zeroizing::new(value),
        }
    }

    /// The plaintext to render.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for RevealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevealedSecret")
            .field("entry_id", &self.entry_id)
            .field("field", &self.field)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// The password-generator overlay's state: the options in force and the
/// password generated under them. The password is zeroised on drop and never
/// surfaced by `Debug`.
#[derive(Clone)]
pub struct GeneratorState {
    /// Options the current password was generated under.
    pub opts: GenerateOptions,
    /// The freshly generated password.
    password: Zeroizing<String>,
}

impl GeneratorState {
    /// The generated password, for display and copy.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for GeneratorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratorState")
            .field("opts", &self.opts)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Top-level TUI state.
#[derive(Clone, Debug)]
pub struct App {
    /// What the screen shows.
    pub screen: Screen,
    /// Agent status snapshot (drives the status bar), if known.
    pub status: Option<Status>,
    /// All items returned by the agent (name-sorted agent-side).
    pub entries: Vec<ListEntry>,
    /// Folder pane rows, always led by `All`.
    pub folders: Vec<FolderItem>,
    /// Selected folder index (into `folders`).
    pub folder_sel: usize,
    /// Selected item index, into the *filtered* item list.
    pub item_sel: usize,
    /// Which pane has focus.
    pub focus: Focus,
    /// What keyboard input currently drives.
    pub mode: InputMode,
    /// Live search query, applied on top of the folder filter. Persists after
    /// the user accepts it with Enter; cleared by Esc.
    pub search: String,
    /// Pending `:` command-line buffer, only meaningful in
    /// [`InputMode::Command`].
    pub command: String,
    /// Generator overlay state, `Some` while [`InputMode::Generate`] is open.
    pub generator: Option<GeneratorState>,
    /// Secret currently revealed in the detail pane, if any.
    pub revealed: Option<RevealedSecret>,
    /// Transient status-bar message (copy feedback / errors). Cleared on the
    /// next key press.
    pub toast: Option<String>,
    /// Set when the user asks to quit.
    pub should_quit: bool,
}

impl App {
    /// Build a browsing state from an unlocked agent's status + item list.
    #[must_use]
    pub fn browsing(status: Status, entries: Vec<ListEntry>) -> Self {
        let folders = derive_folders(&entries);
        Self {
            screen: Screen::Browsing,
            status: Some(status),
            entries,
            folders,
            folder_sel: 0,
            item_sel: 0,
            focus: Focus::Items,
            mode: InputMode::Normal,
            search: String::new(),
            command: String::new(),
            generator: None,
            revealed: None,
            toast: None,
            should_quit: false,
        }
    }

    /// Build a banner state (locked agent, no agent, error).
    #[must_use]
    pub fn message(
        title: impl Into<String>,
        body: impl Into<String>,
        status: Option<Status>,
    ) -> Self {
        Self {
            screen: Screen::Message {
                title: title.into(),
                body: body.into(),
            },
            status,
            entries: Vec::new(),
            folders: Vec::new(),
            folder_sel: 0,
            item_sel: 0,
            focus: Focus::Items,
            mode: InputMode::Normal,
            search: String::new(),
            command: String::new(),
            generator: None,
            revealed: None,
            toast: None,
            should_quit: false,
        }
    }

    /// The filter for the currently-selected folder (`All` if the pane is empty).
    #[must_use]
    pub fn active_filter(&self) -> &FolderFilter {
        self.folders
            .get(self.folder_sel)
            .map_or(&FolderFilter::All, |f| &f.filter)
    }

    /// Items visible under the selected folder — and, when a search query is
    /// active, matching it — in `entries` order.
    #[must_use]
    pub fn filtered(&self) -> Vec<&ListEntry> {
        let filter = self.active_filter();
        let query = self.search.to_lowercase();
        self.entries
            .iter()
            .filter(|e| match filter {
                FolderFilter::All => true,
                FolderFilter::Unfiled => e.folder.is_none(),
                FolderFilter::Named(n) => e.folder.as_deref() == Some(n.as_str()),
            })
            .filter(|e| query.is_empty() || matches_search(e, &query))
            .collect()
    }

    /// The item currently selected in the filtered list, if any.
    #[must_use]
    pub fn selected_entry(&self) -> Option<ListEntry> {
        self.filtered().get(self.item_sel).map(|e| (*e).clone())
    }

    /// Move the selection down by one in the focused pane (saturating).
    pub fn move_down(&mut self) {
        // Any navigation re-masks: a revealed secret must never linger over a
        // row the user has moved away from.
        self.revealed = None;
        match self.focus {
            Focus::Folders => {
                if self.folder_sel + 1 < self.folders.len() {
                    self.folder_sel += 1;
                    self.item_sel = 0;
                }
            }
            Focus::Items => {
                let len = self.filtered().len();
                if len > 0 && self.item_sel + 1 < len {
                    self.item_sel += 1;
                }
            }
        }
    }

    /// Move the selection up by one in the focused pane (saturating).
    pub fn move_up(&mut self) {
        self.revealed = None;
        match self.focus {
            Focus::Folders => {
                if self.folder_sel > 0 {
                    self.folder_sel -= 1;
                    self.item_sel = 0;
                }
            }
            Focus::Items => self.item_sel = self.item_sel.saturating_sub(1),
        }
    }

    /// Toggle focus between the folder pane and the item list.
    pub fn focus_next(&mut self) {
        self.revealed = None;
        self.focus = match self.focus {
            Focus::Folders => Focus::Items,
            Focus::Items => Focus::Folders,
        };
    }

    /// Whether the item list currently has focus — the gate for copy / reveal
    /// actions, which target the selected item.
    #[must_use]
    pub const fn items_focused(&self) -> bool {
        matches!(self.focus, Focus::Items)
    }

    /// Whether `field` of the item with `entry_id` is currently revealed.
    #[must_use]
    pub fn is_revealed(&self, entry_id: &str, field: Field) -> bool {
        self.revealed
            .as_ref()
            .is_some_and(|r| r.entry_id == entry_id && r.field == field)
    }

    /// Reveal a freshly-fetched secret in the detail pane.
    pub fn reveal(&mut self, secret: RevealedSecret) {
        self.revealed = Some(secret);
    }

    /// Re-mask any revealed secret.
    pub fn hide_revealed(&mut self) {
        self.revealed = None;
    }

    /// Set the transient status-bar message.
    pub fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some(msg.into());
    }

    /// Clear the transient status-bar message (called before each key press).
    pub fn clear_toast(&mut self) {
        self.toast = None;
    }

    /// Request shutdown on the next loop iteration.
    pub const fn quit(&mut self) {
        self.should_quit = true;
    }

    // --- search ---------------------------------------------------------

    /// Enter search mode, editing the current query in place.
    pub const fn open_search(&mut self) {
        self.mode = InputMode::Search;
    }

    /// Append a character to the live search query.
    pub fn search_push(&mut self, c: char) {
        self.search.push(c);
        self.on_query_changed();
    }

    /// Delete the last character of the live search query.
    pub fn search_pop(&mut self) {
        self.search.pop();
        self.on_query_changed();
    }

    /// Accept the query as-is and return to normal mode; the filter stays
    /// applied until cleared.
    pub const fn accept_search(&mut self) {
        self.mode = InputMode::Normal;
    }

    /// Abandon search mode and drop the query entirely.
    pub fn cancel_search(&mut self) {
        self.mode = InputMode::Normal;
        self.clear_search();
    }

    /// Drop any active search query (also reachable from normal mode via Esc).
    pub fn clear_search(&mut self) {
        self.search.clear();
        self.on_query_changed();
    }

    /// Whether a search query is currently narrowing the item list.
    #[must_use]
    pub const fn has_search(&self) -> bool {
        !self.search.is_empty()
    }

    /// Every query edit re-anchors the selection at the top of the (new)
    /// filtered list and re-masks — the selected row just changed identity.
    fn on_query_changed(&mut self) {
        self.item_sel = 0;
        self.revealed = None;
    }

    // --- command line ----------------------------------------------------

    /// Enter command mode with an empty buffer.
    pub fn open_command(&mut self) {
        self.command.clear();
        self.mode = InputMode::Command;
    }

    /// Append a character to the pending command.
    pub fn command_push(&mut self, c: char) {
        self.command.push(c);
    }

    /// Delete the last character of the pending command.
    pub fn command_pop(&mut self) {
        self.command.pop();
    }

    /// Abandon the command line.
    pub fn cancel_command(&mut self) {
        self.command.clear();
        self.mode = InputMode::Normal;
    }

    /// Take the pending command for execution, leaving normal mode behind.
    #[must_use]
    pub fn take_command(&mut self) -> String {
        self.mode = InputMode::Normal;
        std::mem::take(&mut self.command)
    }

    // --- generator overlay -----------------------------------------------

    /// Open the generator overlay with a fresh default-options password.
    pub fn open_generator(&mut self) {
        let opts = GenerateOptions::default();
        match generate_password(&opts) {
            Ok(password) => {
                self.generator = Some(GeneratorState { opts, password });
                self.mode = InputMode::Generate;
            }
            Err(e) => self.set_toast(format!("generate failed: {e}")),
        }
    }

    /// Close the generator overlay, dropping (and zeroising) its password.
    pub fn close_generator(&mut self) {
        self.generator = None;
        self.mode = InputMode::Normal;
    }

    /// Replace the overlay's password with a fresh one under the same options.
    pub fn regenerate(&mut self) {
        if let Some(g) = self.generator.as_mut() {
            match generate_password(&g.opts) {
                Ok(password) => g.password = password,
                Err(e) => self.toast = Some(format!("generate failed: {e}")),
            }
        }
    }

    /// Grow or shrink the generated length by `delta`, clamped to
    /// [`GEN_MIN_LEN`]..=[`GEN_MAX_LEN`], regenerating on change.
    pub fn gen_adjust_length(&mut self, delta: isize) {
        if let Some(g) = self.generator.as_mut() {
            let len = g
                .opts
                .length
                .saturating_add_signed(delta)
                .clamp(GEN_MIN_LEN, GEN_MAX_LEN);
            if len != g.opts.length {
                g.opts.length = len;
                self.regenerate();
            }
        }
    }

    /// Toggle the symbol class on the generator, regenerating immediately.
    pub fn gen_toggle_symbols(&mut self) {
        if let Some(g) = self.generator.as_mut() {
            g.opts.symbols = !g.opts.symbols;
            self.regenerate();
        }
    }
}

/// Case-insensitive substring match of `query` (already lower-cased) against
/// an entry's name and username — the two columns the item list displays.
fn matches_search(e: &ListEntry, query: &str) -> bool {
    e.name.to_lowercase().contains(query)
        || e.username
            .as_deref()
            .is_some_and(|u| u.to_lowercase().contains(query))
}

/// Build the folder pane from a set of entries: a leading `All`, an `Unfiled`
/// row when any item has no folder, then each distinct folder name sorted
/// case-insensitively-stable (via `BTreeSet`).
#[must_use]
pub fn derive_folders(entries: &[ListEntry]) -> Vec<FolderItem> {
    let mut named: BTreeSet<String> = BTreeSet::new();
    let mut has_unfiled = false;
    for e in entries {
        match &e.folder {
            Some(f) => {
                named.insert(f.clone());
            }
            None => has_unfiled = true,
        }
    }

    let mut out = vec![FolderItem {
        label: "All".to_owned(),
        filter: FolderFilter::All,
    }];
    if has_unfiled {
        out.push(FolderItem {
            label: "Unfiled".to_owned(),
            filter: FolderFilter::Unfiled,
        });
    }
    for n in named {
        out.push(FolderItem {
            label: n.clone(),
            filter: FolderFilter::Named(n),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, folder: Option<&str>) -> ListEntry {
        ListEntry {
            id: format!("id-{name}"),
            name: name.to_owned(),
            cipher_type: 1,
            username: Some(format!("{name}@example.org")),
            folder: folder.map(ToOwned::to_owned),
        }
    }

    fn status() -> Status {
        Status {
            unlocked: true,
            server: Some("https://vault.example.org".into()),
            email: Some("alice@example.org".into()),
            items: Some(3),
            last_sync: Some("2026-06-04T00:00:00Z".into()),
            agent_version: "0.0.1".into(),
        }
    }

    #[test]
    fn derive_folders_leads_with_all_then_unfiled_then_sorted_names() {
        let entries = vec![
            entry("gitlab", Some("Work")),
            entry("github", Some("Work")),
            entry("bank", None),
            entry("email", Some("Personal")),
        ];
        let folders = derive_folders(&entries);
        let labels: Vec<&str> = folders.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(labels, ["All", "Unfiled", "Personal", "Work"]);
        assert_eq!(folders[0].filter, FolderFilter::All);
        assert_eq!(folders[1].filter, FolderFilter::Unfiled);
        assert_eq!(folders[3].filter, FolderFilter::Named("Work".to_owned()));
    }

    #[test]
    fn derive_folders_omits_unfiled_when_all_items_are_filed() {
        let entries = vec![entry("a", Some("X")), entry("b", Some("X"))];
        let folders = derive_folders(&entries);
        assert_eq!(folders.len(), 2); // All + X
        assert!(folders.iter().all(|f| f.filter != FolderFilter::Unfiled));
    }

    #[test]
    fn filtered_respects_selected_folder() {
        let entries = vec![
            entry("gitlab", Some("Work")),
            entry("bank", None),
            entry("email", Some("Personal")),
        ];
        let mut app = App::browsing(status(), entries);
        // folders: All, Unfiled, Personal, Work
        assert_eq!(app.filtered().len(), 3); // All

        app.focus = Focus::Folders;
        app.move_down(); // -> Unfiled
        assert_eq!(app.active_filter(), &FolderFilter::Unfiled);
        let unfiled = app.filtered();
        assert_eq!(unfiled.len(), 1);
        assert_eq!(unfiled[0].name, "bank");

        app.move_down(); // -> Personal
        assert_eq!(app.filtered()[0].name, "email");
    }

    #[test]
    fn item_navigation_clamps_at_bounds() {
        let entries = vec![entry("a", None), entry("b", None), entry("c", None)];
        let mut app = App::browsing(status(), entries);
        assert_eq!(app.focus, Focus::Items);
        assert_eq!(app.item_sel, 0);

        app.move_up(); // already at top — clamps
        assert_eq!(app.item_sel, 0);

        app.move_down();
        app.move_down();
        assert_eq!(app.item_sel, 2);
        app.move_down(); // at bottom — clamps
        assert_eq!(app.item_sel, 2);
        assert_eq!(app.selected_entry().unwrap().name, "c");
    }

    #[test]
    fn focus_next_cycles_folders_and_items() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        assert_eq!(app.focus, Focus::Items);
        app.focus_next();
        assert_eq!(app.focus, Focus::Folders);
        app.focus_next();
        assert_eq!(app.focus, Focus::Items);
    }

    #[test]
    fn changing_folder_resets_item_selection() {
        let entries = vec![
            entry("a", Some("X")),
            entry("b", Some("X")),
            entry("c", None),
        ];
        let mut app = App::browsing(status(), entries);
        app.move_down(); // item_sel -> 1 within All
        assert_eq!(app.item_sel, 1);
        app.focus = Focus::Folders;
        app.move_down(); // change folder -> item_sel reset
        assert_eq!(app.item_sel, 0);
    }

    #[test]
    fn reveal_is_tracked_per_item_and_field() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        assert!(!app.is_revealed("id-a", Field::Password));
        app.reveal(RevealedSecret::new(
            "id-a".to_owned(),
            Field::Password,
            "hunter2".to_owned(),
        ));
        assert!(app.is_revealed("id-a", Field::Password));
        // A different item or field is not considered revealed.
        assert!(!app.is_revealed("id-b", Field::Password));
        assert!(!app.is_revealed("id-a", Field::Username));
        app.hide_revealed();
        assert!(!app.is_revealed("id-a", Field::Password));
    }

    #[test]
    fn navigation_remasks_a_revealed_secret() {
        let entries = vec![entry("a", None), entry("b", None)];
        let mut app = App::browsing(status(), entries);
        app.reveal(RevealedSecret::new(
            "id-a".to_owned(),
            Field::Password,
            "secret".to_owned(),
        ));
        assert!(app.revealed.is_some());
        app.move_down();
        assert!(app.revealed.is_none(), "moving selection must re-mask");

        // Re-reveal, then a focus switch must also re-mask.
        app.reveal(RevealedSecret::new(
            "id-a".to_owned(),
            Field::Password,
            "secret".to_owned(),
        ));
        app.focus_next();
        assert!(app.revealed.is_none(), "switching panes must re-mask");
    }

    #[test]
    fn toast_set_and_clear() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        assert!(app.toast.is_none());
        app.set_toast("copied password");
        assert_eq!(app.toast.as_deref(), Some("copied password"));
        app.clear_toast();
        assert!(app.toast.is_none());
    }

    #[test]
    fn items_focused_gates_on_focus() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        assert!(app.items_focused()); // browsing starts on the item list
        app.focus_next();
        assert!(!app.items_focused());
    }

    #[test]
    fn search_matches_name_and_username_case_insensitively() {
        let entries = vec![
            entry("GitHub", None),
            entry("gitlab", None),
            entry("bank", None),
        ];
        let mut app = App::browsing(status(), entries);
        app.open_search();
        for c in "git".chars() {
            app.search_push(c);
        }
        let names: Vec<&str> = app.filtered().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["GitHub", "gitlab"]);

        // Username matches too: "bank@example.org" contains "bank@".
        app.cancel_search();
        app.open_search();
        for c in "BANK@".chars() {
            app.search_push(c);
        }
        let names: Vec<&str> = app.filtered().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["bank"]);
    }

    #[test]
    fn search_composes_with_folder_filter() {
        let entries = vec![
            entry("github", Some("Work")),
            entry("gitlab", None),
            entry("bank", None),
        ];
        let mut app = App::browsing(status(), entries);
        // Select Unfiled (folders: All, Unfiled, Work), then search "git".
        app.focus = Focus::Folders;
        app.move_down();
        assert_eq!(app.active_filter(), &FolderFilter::Unfiled);
        app.open_search();
        for c in "git".chars() {
            app.search_push(c);
        }
        let names: Vec<&str> = app.filtered().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["gitlab"], "search must apply within the folder");
    }

    #[test]
    fn query_edits_reset_selection_and_remask() {
        let entries = vec![entry("aa", None), entry("ab", None), entry("zz", None)];
        let mut app = App::browsing(status(), entries);
        app.move_down(); // item_sel -> 1
        app.reveal(RevealedSecret::new(
            "id-ab".to_owned(),
            Field::Password,
            "secret".to_owned(),
        ));
        app.open_search();
        app.search_push('a');
        assert_eq!(app.item_sel, 0, "query edit must re-anchor the selection");
        assert!(app.revealed.is_none(), "query edit must re-mask");
        app.search_pop();
        assert_eq!(app.item_sel, 0);
    }

    #[test]
    fn accept_keeps_query_cancel_and_clear_drop_it() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_search();
        app.search_push('a');
        app.accept_search();
        assert_eq!(app.mode, InputMode::Normal);
        assert!(app.has_search(), "Enter must keep the filter applied");

        app.clear_search(); // Esc from normal mode
        assert!(!app.has_search());

        app.open_search();
        app.search_push('a');
        app.cancel_search(); // Esc from search mode
        assert_eq!(app.mode, InputMode::Normal);
        assert!(!app.has_search(), "Esc must drop the query");
    }

    #[test]
    fn command_buffer_take_and_cancel() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_command();
        assert_eq!(app.mode, InputMode::Command);
        for c in "syncx".chars() {
            app.command_push(c);
        }
        app.command_pop();
        assert_eq!(app.command, "sync");
        assert_eq!(app.take_command(), "sync");
        assert_eq!(app.mode, InputMode::Normal);
        assert!(app.command.is_empty());

        app.open_command();
        app.command_push('q');
        app.cancel_command();
        assert_eq!(app.mode, InputMode::Normal);
        assert!(app.command.is_empty());
    }

    #[test]
    fn generator_opens_with_defaults_and_regenerates() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_generator();
        assert_eq!(app.mode, InputMode::Generate);
        let first = app
            .generator
            .as_ref()
            .map(|g| g.password().to_owned())
            .expect("generator open");
        assert_eq!(first.chars().count(), 20, "default length is 20");

        app.regenerate();
        let second = app
            .generator
            .as_ref()
            .map(|g| g.password().to_owned())
            .expect("generator still open");
        // 62^20 keyspace — a collision here means the RNG is broken.
        assert_ne!(first, second, "regenerate must draw a fresh password");

        app.close_generator();
        assert!(app.generator.is_none());
        assert_eq!(app.mode, InputMode::Normal);
    }

    #[test]
    fn generator_length_adjusts_and_clamps() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_generator();
        app.gen_adjust_length(1);
        assert_eq!(app.generator.as_ref().map(|g| g.opts.length), Some(21));
        assert_eq!(
            app.generator.as_ref().map(|g| g.password().chars().count()),
            Some(21)
        );
        app.gen_adjust_length(-1000);
        assert_eq!(
            app.generator.as_ref().map(|g| g.opts.length),
            Some(GEN_MIN_LEN),
            "length clamps at the floor"
        );
        app.gen_adjust_length(1000);
        assert_eq!(
            app.generator.as_ref().map(|g| g.opts.length),
            Some(GEN_MAX_LEN),
            "length clamps at the ceiling"
        );
    }

    #[test]
    fn generator_symbols_toggle_regenerates() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_generator();
        assert_eq!(app.generator.as_ref().map(|g| g.opts.symbols), Some(false));
        app.gen_toggle_symbols();
        let g = app.generator.as_ref().expect("generator open");
        assert!(g.opts.symbols);
        assert!(
            g.password().chars().any(|c| "!@#$%^&*".contains(c)),
            "an enabled class is guaranteed at least one character"
        );
    }

    #[test]
    fn generator_debug_redacts_password() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_generator();
        let g = app.generator.as_ref().expect("generator open");
        let pw = g.password().to_owned();
        let rendered = format!("{g:?}");
        assert!(rendered.contains("GeneratorState"));
        assert!(rendered.contains("<redacted>"));
        assert!(
            !rendered.contains(&pw),
            "Debug leaked the generated password: {rendered}"
        );
    }

    #[test]
    fn revealed_secret_debug_redacts_plaintext() {
        let secret = RevealedSecret::new(
            "id-a".to_owned(),
            Field::Password,
            "super-secret-value".to_owned(),
        );
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("RevealedSecret"));
        assert!(rendered.contains("<redacted>"));
        assert!(
            !rendered.contains("super-secret-value"),
            "Debug leaked the plaintext: {rendered}"
        );
    }
}
