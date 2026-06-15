// SPDX-License-Identifier: GPL-3.0-or-later

//! TUI application state and pure navigation / filter logic.
//!
//! Everything here is synchronous and crossterm-free so it unit-tests without a
//! terminal: `main.rs` translates key events into calls on these methods (and
//! performs the agent I/O for reveal/copy), and `ui.rs` renders from this state.
//! The state holds the non-secret [`ListEntry`] metadata plus, transiently, a
//! single revealed secret ([`RevealedSecret`], zeroised on drop and re-masked
//! on any navigation), a live search query, a pending `:` command line, the
//! password-generator overlay ([`GeneratorState`], zeroised on drop), the
//! add/edit form ([`FormState`], secrets redacted in `Debug`), and the
//! delete-confirm target.

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

/// A single-line editable text buffer with a cursor — the shared core behind
/// the `/` search, `:` command line, and every form field. Edits happen at the
/// cursor; `cursor` is a byte offset kept on a `char` boundary so all the
/// slicing below is UTF-8-safe. Kill methods return the removed text so the
/// caller can stash it in a kill-ring for `Ctrl+Y`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TextInput {
    buf: String,
    cursor: usize,
}

impl TextInput {
    /// The current text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.buf
    }

    /// Cursor byte offset (always on a char boundary, in `0..=len`).
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Clear the text and reset the cursor.
    pub fn clear(&mut self) {
        self.buf.clear();
        self.cursor = 0;
    }

    /// Take the text, leaving the input empty.
    #[must_use]
    pub fn take(&mut self) -> String {
        self.cursor = 0;
        std::mem::take(&mut self.buf)
    }

    /// Insert `c` at the cursor and step past it.
    pub fn insert(&mut self, c: char) {
        self.buf.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    /// Insert `s` at the cursor (paste / yank), leaving the cursor after it.
    pub fn insert_str(&mut self, s: &str) {
        self.buf.insert_str(self.cursor, s);
        self.cursor += s.len();
    }

    /// Delete the char before the cursor (Backspace).
    pub fn backspace(&mut self) {
        if let Some(prev) = self.prev_boundary() {
            self.buf.replace_range(prev..self.cursor, "");
            self.cursor = prev;
        }
    }

    /// Delete the char at the cursor (Delete).
    pub fn delete(&mut self) {
        if let Some(next) = self.next_boundary() {
            self.buf.replace_range(self.cursor..next, "");
        }
    }

    /// Move the cursor one char left.
    pub fn left(&mut self) {
        if let Some(prev) = self.prev_boundary() {
            self.cursor = prev;
        }
    }

    /// Move the cursor one char right.
    pub fn right(&mut self) {
        if let Some(next) = self.next_boundary() {
            self.cursor = next;
        }
    }

    /// Move the cursor to the start.
    pub const fn home(&mut self) {
        self.cursor = 0;
    }

    /// Move the cursor to the end.
    pub const fn end(&mut self) {
        self.cursor = self.buf.len();
    }

    /// Delete the word before the cursor (Ctrl+W): trailing spaces, then the
    /// run of non-spaces. Returns the removed text.
    pub fn kill_word_back(&mut self) -> String {
        let mut start = self.cursor;
        let take_while_back = |start: &mut usize, pred: &dyn Fn(char) -> bool| {
            while *start > 0 {
                let prev = self.buf[..*start]
                    .chars()
                    .next_back()
                    .map_or(*start, |c| *start - c.len_utf8());
                let c = self.buf[prev..*start].chars().next().unwrap_or(' ');
                if pred(c) {
                    *start = prev;
                } else {
                    break;
                }
            }
        };
        take_while_back(&mut start, &|c| c == ' ');
        take_while_back(&mut start, &|c| c != ' ');
        let removed = self.buf[start..self.cursor].to_owned();
        self.buf.replace_range(start..self.cursor, "");
        self.cursor = start;
        removed
    }

    /// Delete from the start of the line to the cursor (Ctrl+U). Returns it.
    pub fn kill_to_start(&mut self) -> String {
        let removed = self.buf[..self.cursor].to_owned();
        self.buf.replace_range(..self.cursor, "");
        self.cursor = 0;
        removed
    }

    /// Delete from the cursor to the end of the line (Ctrl+K). Returns it.
    pub fn kill_to_end(&mut self) -> String {
        let removed = self.buf[self.cursor..].to_owned();
        self.buf.truncate(self.cursor);
        removed
    }

    /// Byte offset of the char boundary before the cursor, if any.
    fn prev_boundary(&self) -> Option<usize> {
        (self.cursor > 0).then(|| {
            self.buf[..self.cursor]
                .chars()
                .next_back()
                .map_or(0, |c| self.cursor - c.len_utf8())
        })
    }

    /// Byte offset of the char boundary after the cursor, if any.
    fn next_boundary(&self) -> Option<usize> {
        self.buf[self.cursor..]
            .chars()
            .next()
            .map(|c| self.cursor + c.len_utf8())
    }
}

impl From<&str> for TextInput {
    fn from(s: &str) -> Self {
        Self {
            buf: s.to_owned(),
            cursor: s.len(),
        }
    }
}

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
    /// `a`/`e` pressed — the add/edit form overlay is open.
    Form,
    /// `d` pressed — the delete-confirm overlay is open.
    ConfirmDelete,
    /// The agent is locked — keys edit the master-password / PIN entry.
    Unlock,
    /// `?` pressed — the read-only About overlay is open.
    About,
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
    /// The locked agent + a registered account: an interactive unlock prompt.
    Unlock,
}

/// State for the in-TUI unlock prompt, shown when the agent is locked and an
/// account is registered. The typed secret is zeroised on drop (`TextInput`).
#[derive(Clone, Debug)]
pub struct UnlockState {
    /// Server origin from the registered profile.
    pub server: String,
    /// Account email from the profile.
    pub email: String,
    /// Stable device id from the profile (rides `Unlock`).
    pub device_id: Option<String>,
    /// The master password / PIN being typed (masked on screen).
    pub secret: TextInput,
    /// Whether the prompt is in PIN mode (vs master password).
    pub use_pin: bool,
    /// Whether a PIN is enrolled (drives offering the `Tab` toggle).
    pub pin_enabled: bool,
    /// Last failed-unlock message, shown under the field.
    pub error: Option<String>,
}

impl UnlockState {
    /// Build the unlock request for the current mode and typed secret.
    #[must_use]
    pub fn request(&self) -> vault_ipc::proto::Request {
        use vault_ipc::proto::Request;
        let secret = self.secret.as_str().as_bytes().to_vec();
        if self.use_pin {
            Request::UnlockPin {
                server: self.server.clone(),
                email: self.email.clone(),
                pin: secret,
            }
        } else {
            Request::Unlock {
                server: self.server.clone(),
                email: self.email.clone(),
                password: secret,
                device_id: self.device_id.clone(),
                // The agent auto-uses any API key persisted at
                // `vault login --api-key`; the TUI never re-supplies it.
                api_key: None,
            }
        }
    }
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

/// Index of each field in [`FormState::fields`]. All six fields always exist;
/// the *visible* subset depends on the cipher type, so values typed under one
/// type survive a toggle to the other.
const F_NAME: usize = 0;
const F_USER: usize = 1;
const F_PASS: usize = 2;
const F_URI: usize = 3;
const F_FOLDER: usize = 4;
const F_NOTES: usize = 5;

/// Which mutation the form drives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormKind {
    /// Create a new cipher; the form carries a Type row (login ⇄ secure note).
    Add,
    /// Edit an existing cipher. The type is fixed; `name` labels titles/toasts.
    Edit {
        /// Exact cipher id the edit targets.
        id: String,
        /// Decrypted name at the time the form opened.
        name: String,
    },
}

/// One editable row in the mutation form.
#[derive(Clone)]
pub struct FormField {
    /// Display label (`Name`, `User`, `Pass`, …).
    pub label: &'static str,
    /// Current text, with its own cursor.
    pub value: TextInput,
    /// Value the form opened with — submit sends only fields that differ.
    initial: String,
    /// Mask the value while the field is unfocused, redact it in `Debug`.
    pub secret: bool,
}

impl fmt::Debug for FormField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value: &dyn fmt::Debug = if self.secret {
            &"<redacted>"
        } else {
            &self.value
        };
        f.debug_struct("FormField")
            .field("label", &self.label)
            .field("value", value)
            .finish_non_exhaustive()
    }
}

/// One row of the form as the renderer sees it.
#[derive(Debug)]
pub struct FormRowView<'a> {
    /// Display label.
    pub label: &'static str,
    /// Text to show (for the Type row, the type's human name).
    pub value: &'a str,
    /// Mask this value while the row is unfocused.
    pub secret: bool,
    /// Whether this row currently has focus.
    pub focused: bool,
    /// Whether this is the Type toggle row rather than a text field.
    pub is_type: bool,
    /// Cursor byte offset within `value` — `Some` only for the focused text
    /// field, so the renderer draws the caret in exactly one place.
    pub cursor: Option<usize>,
}

/// The add/edit form overlay's state. Pure data + navigation/edit logic;
/// `main.rs` turns a submit into a `Request::Add` / `Request::Edit`.
#[derive(Clone, Debug)]
pub struct FormState {
    /// Add or edit, with the edit target baked in.
    pub kind: FormKind,
    /// Bitwarden cipher type the form is composing (1 = login, 2 = note).
    pub cipher_type: u8,
    /// All six fields, in [`F_NAME`]..=[`F_NOTES`] order.
    fields: Vec<FormField>,
    /// Focused row index — `0` is the Type row on add forms.
    pub focus: usize,
}

/// What a validated form submit carries; `None` fields ride as "unchanged"
/// (edit) or "not set" (add) on the wire.
pub struct FormSubmit {
    /// Add or edit, with the edit target baked in.
    pub kind: FormKind,
    /// Cipher type for `Request::Add`.
    pub cipher_type: u8,
    /// Display name.
    pub name: Option<String>,
    /// Login username.
    pub username: Option<String>,
    /// Login password (secret).
    pub password: Option<String>,
    /// Primary login URI.
    pub uri: Option<String>,
    /// Folder name (agent resolves to an id).
    pub folder: Option<String>,
    /// Free-form notes.
    pub notes: Option<String>,
}

impl fmt::Debug for FormSubmit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormSubmit")
            .field("kind", &self.kind)
            .field("cipher_type", &self.cipher_type)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("uri", &self.uri)
            .field("folder", &self.folder)
            .field("notes", &self.notes)
            .finish()
    }
}

impl FormState {
    /// Blank field set shared by both constructors.
    fn blank_fields() -> Vec<FormField> {
        ["Name", "User", "Pass", "URI", "Folder", "Notes"]
            .into_iter()
            .map(|label| FormField {
                label,
                value: TextInput::default(),
                initial: String::new(),
                secret: label == "Pass",
            })
            .collect()
    }

    /// An empty add form, composing a login by default.
    #[must_use]
    pub fn new_add() -> Self {
        Self {
            kind: FormKind::Add,
            cipher_type: 1,
            fields: Self::blank_fields(),
            focus: 0,
        }
    }

    /// An edit form for `entry`, prefilled with the metadata the list already
    /// carries (name / username / folder). Secrets stay blank — blank means
    /// "leave unchanged" on submit.
    #[must_use]
    pub fn new_edit(entry: &ListEntry) -> Self {
        let mut fields = Self::blank_fields();
        let mut prefill = |idx: usize, v: &str| {
            fields[idx].value = TextInput::from(v);
            v.clone_into(&mut fields[idx].initial);
        };
        prefill(F_NAME, &entry.name);
        if let Some(u) = entry.username.as_deref() {
            prefill(F_USER, u);
        }
        if let Some(fo) = entry.folder.as_deref() {
            prefill(F_FOLDER, fo);
        }
        Self {
            kind: FormKind::Edit {
                id: entry.id.clone(),
                name: entry.name.clone(),
            },
            cipher_type: entry.cipher_type,
            fields,
            focus: 0,
        }
    }

    /// Whether the form carries a Type toggle row (add forms only).
    #[must_use]
    pub const fn has_type_row(&self) -> bool {
        matches!(self.kind, FormKind::Add)
    }

    /// Whether the Type row currently has focus.
    #[must_use]
    pub const fn on_type_row(&self) -> bool {
        self.has_type_row() && self.focus == 0
    }

    /// Indices of the fields the current cipher type exposes.
    fn visible_fields(&self) -> Vec<usize> {
        if self.cipher_type == 1 {
            (F_NAME..=F_NOTES).collect()
        } else {
            // Secure notes (and anything that isn't a login) edit only the
            // metadata fields every cipher type carries.
            vec![F_NAME, F_FOLDER, F_NOTES]
        }
    }

    /// Total focusable rows (Type row + visible fields).
    fn row_count(&self) -> usize {
        usize::from(self.has_type_row()) + self.visible_fields().len()
    }

    /// Index into `fields` of the focused row, `None` on the Type row.
    fn focused_field_index(&self) -> Option<usize> {
        let off = usize::from(self.has_type_row());
        self.focus
            .checked_sub(off)
            .and_then(|i| self.visible_fields().get(i).copied())
    }

    /// Mutable handle on the focused text field, `None` on the Type row.
    fn focused_field_mut(&mut self) -> Option<&mut FormField> {
        self.focused_field_index().map(|i| &mut self.fields[i])
    }

    /// Move focus down one row, wrapping.
    pub fn focus_next(&mut self) {
        self.focus = (self.focus + 1) % self.row_count();
    }

    /// Move focus up one row, wrapping.
    pub fn focus_prev(&mut self) {
        self.focus = self
            .focus
            .checked_sub(1)
            .unwrap_or_else(|| self.row_count() - 1);
    }

    /// Flip login ⇄ secure note (no-op unless the Type row has focus).
    pub const fn toggle_type(&mut self) {
        if self.on_type_row() {
            self.cipher_type = if self.cipher_type == 1 { 2 } else { 1 };
        }
    }

    /// Human name of the cipher type being composed.
    #[must_use]
    pub const fn type_label(&self) -> &'static str {
        if self.cipher_type == 1 {
            "login"
        } else {
            "secure note"
        }
    }

    /// The rows in display order, ready to render.
    #[must_use]
    pub fn rows(&self) -> Vec<FormRowView<'_>> {
        let mut out = Vec::with_capacity(self.row_count());
        if self.has_type_row() {
            out.push(FormRowView {
                label: "Type",
                value: self.type_label(),
                secret: false,
                focused: self.focus == 0,
                is_type: true,
                cursor: None,
            });
        }
        let off = usize::from(self.has_type_row());
        for (row, idx) in self.visible_fields().into_iter().enumerate() {
            let f = &self.fields[idx];
            let focused = self.focus == off + row;
            out.push(FormRowView {
                label: f.label,
                value: f.value.as_str(),
                secret: f.secret,
                focused,
                is_type: false,
                cursor: focused.then(|| f.value.cursor()),
            });
        }
        out
    }

    /// Validate and diff the form into a [`FormSubmit`].
    ///
    /// A field is carried only when its value differs from what the form
    /// opened with, and only when the current type exposes it — so an edit
    /// leaves untouched fields alone on the wire, clearing a prefilled field
    /// submits an empty string, and login-only residue never leaks into a
    /// secure note.
    ///
    /// # Errors
    ///
    /// Returns a user-facing message when an add form has no name, or when an
    /// edit form has no changes to send.
    pub fn submit(&self) -> Result<FormSubmit, String> {
        let vis = self.visible_fields();
        let take = |idx: usize| -> Option<String> {
            let f = &self.fields[idx];
            (vis.contains(&idx) && f.value.as_str() != f.initial)
                .then(|| f.value.as_str().to_owned())
        };
        let name = take(F_NAME);
        let username = take(F_USER);
        let password = take(F_PASS);
        let uri = take(F_URI);
        let folder = take(F_FOLDER);
        let notes = take(F_NOTES);
        match self.kind {
            FormKind::Add => {
                if name.as_deref().is_none_or(str::is_empty) {
                    return Err("name is required".to_owned());
                }
            }
            FormKind::Edit { .. } => {
                if [&name, &username, &password, &uri, &folder, &notes]
                    .iter()
                    .all(|o| o.is_none())
                {
                    return Err("no changes to save".to_owned());
                }
            }
        }
        Ok(FormSubmit {
            kind: self.kind.clone(),
            cipher_type: self.cipher_type,
            name,
            username,
            password,
            uri,
            folder,
            notes,
        })
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
    pub search: TextInput,
    /// Pending `:` command-line buffer, only meaningful in
    /// [`InputMode::Command`].
    pub command: TextInput,
    /// Shared kill-ring for `Ctrl+W`/`Ctrl+U`/`Ctrl+K` cuts; `Ctrl+Y` yanks it.
    pub kill_ring: String,
    /// Generator overlay state, `Some` while [`InputMode::Generate`] is open.
    pub generator: Option<GeneratorState>,
    /// Add/edit form state, `Some` while [`InputMode::Form`] is open.
    pub form: Option<FormState>,
    /// Delete target `(id, name)`, `Some` while [`InputMode::ConfirmDelete`]
    /// is open.
    pub confirm_delete: Option<(String, String)>,
    /// Secret currently revealed in the detail pane, if any.
    pub revealed: Option<RevealedSecret>,
    /// When a pending OSC52 fallback copy should be cleared from the terminal
    /// clipboard. The TUI owns this timer (the agent can't — it has no
    /// terminal); the run loop races it against input.
    pub osc52_clear_at: Option<std::time::Instant>,
    /// Transient status-bar message (copy feedback / errors). Cleared on the
    /// next key press.
    pub toast: Option<String>,
    /// Interactive unlock state, `Some` while [`Screen::Unlock`] is shown.
    pub unlock: Option<UnlockState>,
    /// Suppress animated UI (`ui.reduced_motion`). Reserved: the TUI has no
    /// animations yet, so nothing reads this — it's populated from config so a
    /// future spinner / lock-countdown can honor it without re-plumbing.
    pub reduced_motion: bool,
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
            search: TextInput::default(),
            command: TextInput::default(),
            kill_ring: String::new(),
            generator: None,
            form: None,
            confirm_delete: None,
            revealed: None,
            osc52_clear_at: None,
            toast: None,
            unlock: None,
            reduced_motion: false,
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
            search: TextInput::default(),
            command: TextInput::default(),
            kill_ring: String::new(),
            generator: None,
            form: None,
            confirm_delete: None,
            revealed: None,
            osc52_clear_at: None,
            toast: None,
            unlock: None,
            reduced_motion: false,
            should_quit: false,
        }
    }

    /// Build the interactive unlock screen for a locked agent with a registered
    /// account.
    #[must_use]
    pub fn unlock_screen(status: Status, unlock: UnlockState) -> Self {
        let mut app = Self::message("", "", Some(status));
        app.screen = Screen::Unlock;
        app.mode = InputMode::Unlock;
        app.unlock = Some(unlock);
        app
    }

    /// Toggle between master-password and PIN entry (no-op unless a PIN is
    /// enrolled); clears the field and any error on switch.
    pub fn toggle_pin(&mut self) {
        if let Some(u) = self.unlock.as_mut()
            && u.pin_enabled
        {
            u.use_pin = !u.use_pin;
            u.secret.clear();
            u.error = None;
        }
    }

    /// Record a failed-unlock message and clear the typed secret.
    pub fn unlock_failed(&mut self, msg: impl Into<String>) {
        if let Some(u) = self.unlock.as_mut() {
            u.error = Some(msg.into());
            u.secret.clear();
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
        let query = self.search.as_str().to_lowercase();
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
        self.search.insert(c);
        self.on_query_changed();
    }

    /// Delete the character before the cursor in the live search query.
    pub fn search_pop(&mut self) {
        self.search.backspace();
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

    /// Insert a character at the cursor in the pending command.
    pub fn command_push(&mut self, c: char) {
        self.command.insert(c);
    }

    /// Delete the character before the cursor in the pending command.
    pub fn command_pop(&mut self) {
        self.command.backspace();
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
        self.command.take()
    }

    // --- shared text-input editing (search / command / focused form field) -

    /// The text input the current mode edits, if any. The single seam every
    /// readline-style key routes through.
    fn active_input_mut(&mut self) -> Option<&mut TextInput> {
        match self.mode {
            InputMode::Search => Some(&mut self.search),
            InputMode::Command => Some(&mut self.command),
            InputMode::Form => self
                .form
                .as_mut()
                .and_then(FormState::focused_field_mut)
                .map(|f| &mut f.value),
            InputMode::Unlock => self.unlock.as_mut().map(|u| &mut u.secret),
            InputMode::Normal
            | InputMode::Generate
            | InputMode::ConfirmDelete
            | InputMode::About => None,
        }
    }

    /// Run search's live-filter bookkeeping after a content edit; no-op in
    /// other modes. Cursor-only moves don't call this (the query is unchanged).
    fn after_input_edit(&mut self) {
        if self.mode == InputMode::Search {
            self.on_query_changed();
        }
    }

    /// Move the cursor left in the active input.
    pub fn input_left(&mut self) {
        if let Some(ti) = self.active_input_mut() {
            ti.left();
        }
    }

    /// Move the cursor right in the active input.
    pub fn input_right(&mut self) {
        if let Some(ti) = self.active_input_mut() {
            ti.right();
        }
    }

    /// Move the cursor to the start of the active input.
    pub fn input_home(&mut self) {
        if let Some(ti) = self.active_input_mut() {
            ti.home();
        }
    }

    /// Move the cursor to the end of the active input.
    pub fn input_end(&mut self) {
        if let Some(ti) = self.active_input_mut() {
            ti.end();
        }
    }

    /// Delete the character at the cursor (Delete key).
    pub fn input_delete(&mut self) {
        if let Some(ti) = self.active_input_mut() {
            ti.delete();
        }
        self.after_input_edit();
    }

    /// Insert text at the cursor — paste, with newlines stripped since every
    /// input is single-line.
    pub fn input_insert_str(&mut self, s: &str) {
        let cleaned: String = s.chars().filter(|c| *c != '\n' && *c != '\r').collect();
        if cleaned.is_empty() {
            return;
        }
        if let Some(ti) = self.active_input_mut() {
            ti.insert_str(&cleaned);
        }
        self.after_input_edit();
    }

    /// `Ctrl+W` — kill the word before the cursor into the kill-ring.
    pub fn input_kill_word(&mut self) {
        let killed = match self.active_input_mut() {
            Some(ti) => ti.kill_word_back(),
            None => return,
        };
        if !killed.is_empty() {
            self.kill_ring = killed;
        }
        self.after_input_edit();
    }

    /// `Ctrl+U` — kill from the line start to the cursor into the kill-ring.
    pub fn input_kill_to_start(&mut self) {
        let killed = match self.active_input_mut() {
            Some(ti) => ti.kill_to_start(),
            None => return,
        };
        if !killed.is_empty() {
            self.kill_ring = killed;
        }
        self.after_input_edit();
    }

    /// `Ctrl+K` — kill from the cursor to the line end into the kill-ring.
    pub fn input_kill_to_end(&mut self) {
        let killed = match self.active_input_mut() {
            Some(ti) => ti.kill_to_end(),
            None => return,
        };
        if !killed.is_empty() {
            self.kill_ring = killed;
        }
        self.after_input_edit();
    }

    /// `Ctrl+Y` — yank (insert) the kill-ring at the cursor.
    pub fn input_yank(&mut self) {
        let s = self.kill_ring.clone();
        if s.is_empty() {
            return;
        }
        if let Some(ti) = self.active_input_mut() {
            ti.insert_str(&s);
        }
        self.after_input_edit();
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

    /// Open the read-only About overlay (`?` / `:about`).
    pub const fn open_about(&mut self) {
        self.mode = InputMode::About;
    }

    /// Close the About overlay, back to browsing.
    pub const fn close_about(&mut self) {
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

    // --- mutation form -----------------------------------------------------

    /// Open an empty add form (login by default). Re-masks any revealed
    /// secret, like every other overlay/navigation.
    pub fn open_add_form(&mut self) {
        self.revealed = None;
        self.form = Some(FormState::new_add());
        self.mode = InputMode::Form;
    }

    /// Open an edit form prefilled from the selected item. No-op unless the
    /// item list is focused and a row is selected (same gate as copy/reveal).
    pub fn open_edit_form(&mut self) {
        if !self.items_focused() {
            return;
        }
        let Some(sel) = self.selected_entry() else {
            return;
        };
        self.revealed = None;
        self.form = Some(FormState::new_edit(&sel));
        self.mode = InputMode::Form;
    }

    /// Abandon the form, discarding everything typed into it.
    pub fn cancel_form(&mut self) {
        self.form = None;
        self.mode = InputMode::Normal;
    }

    /// Whether the form's Type toggle row has focus (drives Space routing:
    /// toggle there, type a literal space in text fields).
    #[must_use]
    pub fn form_on_type_row(&self) -> bool {
        self.form.as_ref().is_some_and(FormState::on_type_row)
    }

    /// Append a character to the focused form field (no-op on the Type row).
    pub fn form_push(&mut self, c: char) {
        if let Some(f) = self.form.as_mut().and_then(FormState::focused_field_mut) {
            f.value.insert(c);
        }
    }

    /// Delete the last character of the focused form field.
    pub fn form_pop(&mut self) {
        if let Some(f) = self.form.as_mut().and_then(FormState::focused_field_mut) {
            f.value.backspace();
        }
    }

    /// Move the form focus down one row, wrapping.
    pub fn form_focus_next(&mut self) {
        if let Some(form) = self.form.as_mut() {
            form.focus_next();
        }
    }

    /// Move the form focus up one row, wrapping.
    pub fn form_focus_prev(&mut self) {
        if let Some(form) = self.form.as_mut() {
            form.focus_prev();
        }
    }

    /// Flip the add form between login and secure note (Type row only).
    pub const fn form_toggle_type(&mut self) {
        if let Some(form) = self.form.as_mut() {
            form.toggle_type();
        }
    }

    /// Fill the focused Pass field with a freshly generated default-options
    /// password (Ctrl+G). No-op when any other row has focus.
    pub fn gen_into_password(&mut self) {
        let Some(form) = self.form.as_mut() else {
            return;
        };
        if form.focused_field_index() != Some(F_PASS) {
            return;
        }
        match generate_password(&GenerateOptions::default()) {
            Ok(pw) => {
                if let Some(f) = form.focused_field_mut() {
                    f.value = TextInput::from(pw.as_str());
                }
            }
            Err(e) => self.toast = Some(format!("generate failed: {e}")),
        }
    }

    /// Validate and diff the open form for submission.
    ///
    /// # Errors
    ///
    /// Returns the user-facing message to toast (no form open, missing name
    /// on add, or an edit with nothing changed); the form stays open.
    pub fn form_submit_data(&self) -> Result<FormSubmit, String> {
        self.form
            .as_ref()
            .ok_or_else(|| "no form open".to_owned())
            .and_then(FormState::submit)
    }

    // --- delete confirm ----------------------------------------------------

    /// Open the delete-confirm overlay for the selected item. Gated like
    /// edit: item list focused + a row selected.
    pub fn open_confirm_delete(&mut self) {
        if !self.items_focused() {
            return;
        }
        let Some(sel) = self.selected_entry() else {
            return;
        };
        self.revealed = None;
        self.confirm_delete = Some((sel.id, sel.name));
        self.mode = InputMode::ConfirmDelete;
    }

    /// Dismiss the delete confirm without deleting.
    pub fn cancel_confirm(&mut self) {
        self.confirm_delete = None;
        self.mode = InputMode::Normal;
    }

    /// Take the confirmed delete target `(id, name)`, closing the overlay.
    #[must_use]
    pub const fn take_confirm_delete(&mut self) -> Option<(String, String)> {
        self.mode = InputMode::Normal;
        self.confirm_delete.take()
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

    #[test]
    fn text_input_insert_and_delete_at_cursor() {
        let mut ti = TextInput::from("abd");
        // Cursor at end after From. Move left once → between 'b' and 'd'.
        ti.left();
        ti.insert('c'); // "abcd", cursor after 'c'
        assert_eq!(ti.as_str(), "abcd");
        assert_eq!(ti.cursor(), 3);
        ti.backspace(); // removes 'c' → "abd"
        assert_eq!(ti.as_str(), "abd");
        ti.home();
        ti.delete(); // removes 'a' → "bd"
        assert_eq!(ti.as_str(), "bd");
        assert_eq!(ti.cursor(), 0);
    }

    #[test]
    fn text_input_cursor_nav_clamps() {
        let mut ti = TextInput::from("hi");
        ti.right(); // already at end
        assert_eq!(ti.cursor(), 2);
        ti.home();
        ti.left(); // already at start
        assert_eq!(ti.cursor(), 0);
        ti.end();
        assert_eq!(ti.cursor(), 2);
    }

    #[test]
    fn text_input_kills_return_removed_text() {
        let mut ti = TextInput::from("foo bar");
        assert_eq!(ti.kill_word_back(), "bar"); // "foo "
        assert_eq!(ti.as_str(), "foo ");
        assert_eq!(ti.kill_to_start(), "foo "); // ""
        assert!(ti.is_empty());

        let mut ti = TextInput::from("keep cut");
        ti.home();
        for _ in 0..4 {
            ti.right();
        } // cursor after "keep"
        assert_eq!(ti.kill_to_end(), " cut");
        assert_eq!(ti.as_str(), "keep");
    }

    #[test]
    fn text_input_insert_str_lands_at_cursor() {
        let mut ti = TextInput::from("ad");
        ti.left(); // between 'a' and 'd'
        ti.insert_str("bc");
        assert_eq!(ti.as_str(), "abcd");
        assert_eq!(ti.cursor(), 3);
    }

    #[test]
    fn text_input_is_utf8_boundary_safe() {
        // "café" — 'é' is two bytes. Backspace must remove the whole char.
        let mut ti = TextInput::from("café");
        ti.backspace();
        assert_eq!(ti.as_str(), "caf");
        // Insert a multibyte char mid-string, then navigate across it.
        let mut ti = TextInput::from("ab");
        ti.left();
        ti.insert('é'); // "aéb"
        assert_eq!(ti.as_str(), "aéb");
        ti.left();
        assert_eq!(ti.cursor(), 1); // before 'é' (one byte in)
        ti.delete(); // removes 'é'
        assert_eq!(ti.as_str(), "ab");
    }

    #[test]
    fn kill_then_yank_round_trips_via_kill_ring() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_command();
        for c in "hello world".chars() {
            app.command_push(c);
        }
        app.input_kill_word(); // cuts "world" into the ring
        assert_eq!(app.command.as_str(), "hello ");
        app.input_yank(); // pastes it back
        assert_eq!(app.command.as_str(), "hello world");
    }

    #[test]
    fn paste_into_focused_form_field_only() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_add_form();
        app.form_focus_next(); // → Name field
        app.input_insert_str("git\nhub"); // newline stripped
        let name = app.form.as_ref().expect("form").rows()[1].value.to_owned();
        assert_eq!(name, "github");
    }

    #[test]
    fn search_edit_via_unified_path_reanchors_selection() {
        let entries = vec![entry("aa", None), entry("ab", None), entry("zz", None)];
        let mut app = App::browsing(status(), entries);
        app.open_search();
        for c in "a".chars() {
            app.search_push(c);
        }
        app.move_down(); // item_sel → 1 within the filtered list
        assert_eq!(app.item_sel, 1);
        app.input_kill_to_start(); // clears the query via the unified path
        assert_eq!(app.item_sel, 0, "a content edit must re-anchor");
        assert!(!app.has_search());
    }

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
            clipboard_backend: None,
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
        assert_eq!(app.command.as_str(), "sync");
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
    fn about_overlay_open_and_close() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_about();
        assert_eq!(app.mode, InputMode::About);
        app.close_about();
        assert_eq!(app.mode, InputMode::Normal);
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
    fn add_form_opens_with_login_defaults() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_add_form();
        assert_eq!(app.mode, InputMode::Form);
        let form = app.form.as_ref().expect("form open");
        assert_eq!(form.kind, FormKind::Add);
        assert_eq!(form.cipher_type, 1);
        let labels: Vec<&str> = form.rows().iter().map(|r| r.label).collect();
        assert_eq!(
            labels,
            ["Type", "Name", "User", "Pass", "URI", "Folder", "Notes"]
        );
        assert!(form.rows().iter().skip(1).all(|r| r.value.is_empty()));
    }

    #[test]
    fn edit_form_prefills_and_is_gated() {
        let mut app = App::browsing(status(), vec![entry("github", Some("Work"))]);
        // Gated: folders pane focus → no-op.
        app.focus = Focus::Folders;
        app.open_edit_form();
        assert!(app.form.is_none());

        app.focus = Focus::Items;
        app.open_edit_form();
        let form = app.form.as_ref().expect("form open");
        assert_eq!(
            form.kind,
            FormKind::Edit {
                id: "id-github".to_owned(),
                name: "github".to_owned()
            }
        );
        assert!(!form.has_type_row(), "edit forms can't change the type");
        let rows = form.rows();
        let value_of = |label: &str| {
            rows.iter()
                .find(|r| r.label == label)
                .map(|r| r.value.to_owned())
                .expect("row exists")
        };
        assert_eq!(value_of("Name"), "github");
        assert_eq!(value_of("User"), "github@example.org");
        assert_eq!(value_of("Folder"), "Work");
        assert_eq!(value_of("Pass"), "");
    }

    #[test]
    fn form_focus_wraps_both_directions() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_add_form();
        // 7 rows: Type + 6 fields.
        app.form_focus_prev();
        assert_eq!(app.form.as_ref().map(|f| f.focus), Some(6), "wraps up");
        app.form_focus_next();
        assert_eq!(app.form.as_ref().map(|f| f.focus), Some(0), "wraps down");
    }

    #[test]
    fn type_toggle_swaps_visible_fields_preserving_values() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_add_form();
        // Type a username under the login type (focus row 2 = User).
        app.form_focus_next();
        app.form_focus_next();
        app.form_push('u');
        // Back to the Type row and flip to secure note.
        app.form_focus_prev();
        app.form_focus_prev();
        assert!(app.form_on_type_row());
        app.form_toggle_type();
        let form = app.form.as_ref().expect("form open");
        assert_eq!(form.cipher_type, 2);
        let labels: Vec<&str> = form.rows().iter().map(|r| r.label).collect();
        assert_eq!(labels, ["Type", "Name", "Folder", "Notes"]);
        // Flip back — the typed username survived the round trip.
        app.form_toggle_type();
        let form = app.form.as_ref().expect("form open");
        let user = form
            .rows()
            .into_iter()
            .find(|r| r.label == "User")
            .map(|r| r.value.to_owned());
        assert_eq!(user.as_deref(), Some("u"));
    }

    #[test]
    fn ctrl_g_fills_only_the_pass_field() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_add_form();
        // On the Type row: no-op.
        app.gen_into_password();
        assert!(app.form.as_ref().expect("form").rows()[3].value.is_empty());
        // Focus Name: still a no-op.
        app.form_focus_next();
        app.gen_into_password();
        let name_val = app.form.as_ref().expect("form").rows()[1].value.to_owned();
        assert!(name_val.is_empty(), "Ctrl+G must not touch Name");
        // Focus Pass (Type → Name → User → Pass): fills 20 chars.
        app.form_focus_next();
        app.form_focus_next();
        app.gen_into_password();
        let pass_val = app.form.as_ref().expect("form").rows()[3].value.to_owned();
        assert_eq!(pass_val.chars().count(), 20);
    }

    #[test]
    fn submit_diff_carries_only_changed_fields() {
        let mut app = App::browsing(status(), vec![entry("github", Some("Work"))]);
        app.open_edit_form();
        // Edit rows: Name User Pass URI Folder Notes (no Type row).
        // Change User; clear Name; leave the rest untouched.
        app.form_focus_next(); // → User
        app.form_push('x');
        app.form_focus_prev(); // → Name
        for _ in 0.."github".len() {
            app.form_pop();
        }
        let data = app.form_submit_data().expect("valid edit");
        assert_eq!(
            data.name.as_deref(),
            Some(""),
            "cleared field submits empty"
        );
        assert_eq!(data.username.as_deref(), Some("github@example.orgx"));
        assert_eq!(data.password, None, "untouched secret stays unchanged");
        assert_eq!(data.folder, None, "untouched prefill stays unchanged");
    }

    #[test]
    fn add_requires_a_name_and_edit_requires_a_change() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_add_form();
        assert_eq!(
            app.form_submit_data().expect_err("add must be rejected"),
            "name is required"
        );

        app.cancel_form();
        assert_eq!(app.mode, InputMode::Normal);
        app.open_edit_form();
        assert_eq!(
            app.form_submit_data().expect_err("edit must be rejected"),
            "no changes to save"
        );
    }

    #[test]
    fn note_submit_excludes_login_field_residue() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_add_form();
        // Type into Pass under the login type…
        app.form_focus_next();
        app.form_push('n'); // Name (required)
        app.form_focus_next();
        app.form_focus_next();
        app.form_push('p'); // Pass
        // …then flip to secure note and submit.
        for _ in 0..3 {
            app.form_focus_prev();
        }
        app.form_toggle_type();
        let data = app.form_submit_data().expect("valid add");
        assert_eq!(data.cipher_type, 2);
        assert_eq!(data.name.as_deref(), Some("n"));
        assert_eq!(data.password, None, "hidden login fields must not leak");
    }

    #[test]
    fn confirm_delete_gates_takes_and_cancels() {
        let mut app = App::browsing(status(), vec![entry("github", None)]);
        app.focus = Focus::Folders;
        app.open_confirm_delete();
        assert!(app.confirm_delete.is_none(), "gated on items focus");

        app.focus = Focus::Items;
        app.open_confirm_delete();
        assert_eq!(app.mode, InputMode::ConfirmDelete);
        assert_eq!(
            app.confirm_delete,
            Some(("id-github".to_owned(), "github".to_owned()))
        );
        app.cancel_confirm();
        assert_eq!(app.mode, InputMode::Normal);
        assert!(app.confirm_delete.is_none());

        app.open_confirm_delete();
        let took = app.take_confirm_delete();
        assert_eq!(took, Some(("id-github".to_owned(), "github".to_owned())));
        assert_eq!(app.mode, InputMode::Normal);
        assert!(app.confirm_delete.is_none());
    }

    #[test]
    fn overlays_remask_revealed_secret() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        let reveal = |app: &mut App| {
            app.reveal(RevealedSecret::new(
                "id-a".to_owned(),
                Field::Password,
                "s".to_owned(),
            ));
        };
        reveal(&mut app);
        app.open_add_form();
        assert!(app.revealed.is_none(), "add form must re-mask");
        app.cancel_form();
        reveal(&mut app);
        app.open_edit_form();
        assert!(app.revealed.is_none(), "edit form must re-mask");
        app.cancel_form();
        reveal(&mut app);
        app.open_confirm_delete();
        assert!(app.revealed.is_none(), "delete confirm must re-mask");
    }

    #[test]
    fn form_debug_redacts_the_pass_value() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_add_form();
        for _ in 0..3 {
            app.form_focus_next(); // → Pass
        }
        for c in "hunter2".chars() {
            app.form_push(c);
        }
        let form = app.form.as_ref().expect("form open");
        let rendered = format!("{form:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(
            !rendered.contains("hunter2"),
            "Debug leaked the password: {rendered}"
        );
        let data = form.submit();
        let rendered = format!("{data:?}");
        assert!(
            !rendered.contains("hunter2"),
            "FormSubmit Debug leaked the password: {rendered}"
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

    fn unlock_state(pin_enabled: bool) -> UnlockState {
        UnlockState {
            server: "https://vault.example.org".into(),
            email: "me@example.org".into(),
            device_id: Some("dev-1".into()),
            secret: TextInput::default(),
            use_pin: false,
            pin_enabled,
            error: None,
        }
    }

    #[test]
    fn unlock_request_builds_password_or_pin_by_mode() {
        use vault_ipc::proto::Request;
        let mut app = App::unlock_screen(status(), unlock_state(true));
        app.input_insert_str("hunter2");
        match app.unlock.as_ref().unwrap().request() {
            Request::Unlock {
                server,
                email,
                password,
                device_id,
                api_key,
            } => {
                assert_eq!(server, "https://vault.example.org");
                assert_eq!(email, "me@example.org");
                assert_eq!(password, b"hunter2");
                assert_eq!(device_id.as_deref(), Some("dev-1"));
                assert!(api_key.is_none(), "TUI never supplies an API key");
            }
            other => panic!("expected Unlock, got {other:?}"),
        }

        // Toggle to PIN, re-type → UnlockPin (no device_id field).
        app.toggle_pin();
        app.input_insert_str("4321");
        match app.unlock.as_ref().unwrap().request() {
            Request::UnlockPin { server, email, pin } => {
                assert_eq!(server, "https://vault.example.org");
                assert_eq!(email, "me@example.org");
                assert_eq!(pin, b"4321");
            }
            other => panic!("expected UnlockPin, got {other:?}"),
        }
    }

    #[test]
    fn toggle_pin_is_noop_without_enrollment_and_clears_on_switch() {
        let mut app = App::unlock_screen(status(), unlock_state(false));
        app.toggle_pin();
        assert!(
            !app.unlock.as_ref().unwrap().use_pin,
            "no PIN enrolled → no switch"
        );

        let mut app = App::unlock_screen(status(), unlock_state(true));
        app.input_insert_str("abc");
        app.toggle_pin();
        let u = app.unlock.as_ref().unwrap();
        assert!(u.use_pin);
        assert!(u.secret.is_empty(), "switch clears the field");
    }

    #[test]
    fn unlock_failed_records_error_and_clears_secret() {
        let mut app = App::unlock_screen(status(), unlock_state(false));
        app.input_insert_str("wrong");
        app.unlock_failed("incorrect master password");
        let u = app.unlock.as_ref().unwrap();
        assert_eq!(u.error.as_deref(), Some("incorrect master password"));
        assert!(u.secret.is_empty());
    }
}
