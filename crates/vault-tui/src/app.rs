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

use vault_core::{GenerateOptions, PassphraseOptions, generate_passphrase, generate_password};
use vault_ipc::proto::{Field, ListEntry, Status};

/// Smallest password the generator overlay will produce. Comfortably above the
/// four-character floor `generate_password` needs to seat one character from
/// every enabled class, and below it a generated password isn't worth copying.
pub const GEN_MIN_LEN: usize = 8;

/// Largest password the generator overlay will produce — matches Bitwarden's
/// own generator ceiling so saved values round-trip everywhere.
pub const GEN_MAX_LEN: usize = 128;

/// Passphrase word-count bounds, matching `generate_passphrase`'s own `3..=20`.
pub const GEN_MIN_WORDS: usize = 3;
/// See [`GEN_MIN_WORDS`].
pub const GEN_MAX_WORDS: usize = 20;

/// Word separators the overlay cycles through with `e` in passphrase mode.
const SEPARATORS: &[&str] = &["-", "_", ".", ",", " "];

/// Rows a vim half-page motion (`Ctrl-d`/`Ctrl-u`) moves. A fixed approximation
/// of vim's "half the window": the pure-render `App` has no viewport height, so
/// a constant step keeps the motion useful without plumbing the pane geometry.
const VIM_PAGE: usize = 10;

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
    /// Right detail pane (per-field navigation: reveal/copy the selected field).
    Detail,
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
// The flags are independent screen state (chosen mode, which modes are
// available, the 2FA step) — a flag bag, not a state machine begging for an enum.
#[allow(clippy::struct_excessive_bools)]
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
    /// Whether the prompt is in fingerprint mode (touchless — `Enter` scans).
    pub use_fingerprint: bool,
    /// Whether fingerprint unlock is configured (drives offering it in the toggle).
    pub fingerprint_enabled: bool,
    /// Last failed-unlock message, shown under the field.
    pub error: Option<String>,
    /// In the second step of a 2FA unlock: the `secret` field now holds the
    /// authenticator code and `password` holds the stashed master password.
    pub awaiting_2fa: bool,
    /// Master password stashed after the first attempt 2FA-challenged, to
    /// resend with the code. Empty until then; zeroised on drop.
    pub password: Zeroizing<Vec<u8>>,
}

impl UnlockState {
    /// Build the unlock request for the current mode and typed secret.
    #[must_use]
    pub fn request(&self) -> vault_ipc::proto::Request {
        use vault_ipc::proto::Request;
        let secret = self.secret.as_str().as_bytes().to_vec();
        if self.use_fingerprint {
            // Touchless: the agent verifies the finger and resumes the keyring
            // session; no secret crosses the socket.
            Request::UnlockFingerprint {
                server: self.server.clone(),
                email: self.email.clone(),
            }
        } else if self.use_pin {
            Request::UnlockPin {
                server: self.server.clone(),
                email: self.email.clone(),
                pin: secret,
            }
        } else if self.awaiting_2fa {
            // Second step: `secret` is the authenticator code; resend the
            // stashed password with it.
            Request::Unlock {
                server: self.server.clone(),
                email: self.email.clone(),
                password: self.password.to_vec(),
                device_id: self.device_id.clone(),
                api_key: None,
                two_factor: Some(vault_ipc::proto::TwoFactorCode {
                    token: self.secret.as_str().to_owned(),
                }),
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
                two_factor: None,
            }
        }
    }

    /// Enter the 2FA code step: stash the typed master password, clear the field
    /// for the authenticator code, and drop any prior error.
    pub fn begin_2fa(&mut self) {
        self.password = Zeroizing::new(self.secret.as_str().as_bytes().to_vec());
        self.secret.clear();
        self.awaiting_2fa = true;
        self.error = None;
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
/// Cached non-sensitive display fields for the selected card/identity item,
/// fetched on selection. Sensitive fields (card number/CVV) are *not* here —
/// they stay masked and are fetched only via reveal, like passwords.
#[derive(Clone, Debug, Default)]
pub struct DetailView {
    /// Id of the item these fields belong to (cache key).
    pub id: String,
    /// Ordered `(label, value)` pairs to show in the detail pane.
    pub lines: Vec<(String, String)>,
}

/// The field `Space` reveals for a cipher type: a login's password or a card's
/// number. Identity and secure-note items have no masked secret (`None`).
#[must_use]
pub const fn primary_secret_field(cipher_type: u8) -> Option<Field> {
    match cipher_type {
        1 => Some(Field::Password),
        3 => Some(Field::CardNumber),
        _ => None,
    }
}

/// The field `c` copies for a cipher type, with its toast label: a login's
/// password, a card's number, or an identity's email.
#[must_use]
pub const fn primary_copy_field(cipher_type: u8) -> Option<(Field, &'static str)> {
    match cipher_type {
        1 => Some((Field::Password, "password")),
        3 => Some((Field::CardNumber, "card number")),
        4 => Some((Field::IdentityEmail, "email")),
        _ => None,
    }
}

/// One navigable field in the detail pane: its label, the agent selector to
/// reveal/copy it, and whether it renders masked until revealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetailField {
    /// Label shown in the detail pane.
    pub label: &'static str,
    /// Agent field selector for reveal/copy.
    pub field: Field,
    /// Hidden behind `MASK` until revealed (secrets).
    pub masked: bool,
}

const fn df(label: &'static str, field: Field, masked: bool) -> DetailField {
    DetailField {
        label,
        field,
        masked,
    }
}

/// The per-field-navigable fields the detail pane exposes for a cipher type, in
/// display order. Cards and identities only — logins already have dedicated
/// `c`/`u`/`o`/`t` copy keys and `Space` reveal; notes/anything else expose none.
#[must_use]
pub const fn detail_fields(cipher_type: u8) -> &'static [DetailField] {
    const CARD: &[DetailField] = &[
        df("Holder", Field::CardCardholder, false),
        df("Brand", Field::CardBrand, false),
        df("Number", Field::CardNumber, true),
        df("Exp", Field::CardExpiry, false),
        df("CVV", Field::CardCode, true),
    ];
    const IDENTITY: &[DetailField] = &[
        df("Title", Field::IdentityTitle, false),
        df("First", Field::IdentityFirstName, false),
        df("Middle", Field::IdentityMiddleName, false),
        df("Last", Field::IdentityLastName, false),
        df("IdUser", Field::IdentityUsername, false),
        df("Company", Field::IdentityCompany, false),
        df("Email", Field::IdentityEmail, false),
        df("Phone", Field::IdentityPhone, false),
        df("Addr1", Field::IdentityAddress1, false),
        df("Addr2", Field::IdentityAddress2, false),
        df("Addr3", Field::IdentityAddress3, false),
        df("City", Field::IdentityCity, false),
        df("State", Field::IdentityState, false),
        df("Postal", Field::IdentityPostal, false),
        df("Country", Field::IdentityCountry, false),
        df("SSN", Field::IdentitySsn, true),
        df("Passport", Field::IdentityPassport, true),
        df("License", Field::IdentityLicense, true),
    ];
    match cipher_type {
        3 => CARD,
        4 => IDENTITY,
        _ => &[],
    }
}

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

/// Whether the generator produces a character password or a diceware passphrase.
///
/// The active mode and both option sets live on [`App`] so they persist across
/// overlay open/close within a session; [`GeneratorState`] holds only the
/// freshly generated value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GeneratorMode {
    /// Character password — length plus class toggles.
    #[default]
    Password,
    /// Diceware passphrase — word count, separator, capitalize, number.
    Passphrase,
}

/// The generator overlay's live value (password or passphrase).
///
/// Zeroised on drop and never surfaced by `Debug`. The options it was generated
/// under live on [`App`] (`gen_mode` / `gen_pw` / `gen_pp`).
#[derive(Clone)]
pub struct GeneratorState {
    /// The freshly generated value.
    value: Zeroizing<String>,
}

impl GeneratorState {
    /// The generated value, for display and copy.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for GeneratorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratorState")
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Index of each field in [`FormState::fields`]. Every field always exists; the
/// *visible* subset depends on the cipher type, so values typed under one type
/// survive a toggle to another. `F_NAME`..=`F_NOTES` are the shared/login rows;
/// `F_CARDHOLDER`..=`F_CODE` are card-only; `F_TITLE`..=`F_COUNTRY` are the
/// curated identity rows.
const F_NAME: usize = 0;
const F_USER: usize = 1;
const F_PASS: usize = 2;
const F_URI: usize = 3;
const F_FOLDER: usize = 4;
const F_NOTES: usize = 5;
const F_CARDHOLDER: usize = 6;
const F_BRAND: usize = 7;
const F_NUMBER: usize = 8;
const F_EXPIRY: usize = 9;
const F_CODE: usize = 10;
const F_TITLE: usize = 11;
const F_FIRST: usize = 12;
const F_LAST: usize = 13;
const F_EMAIL: usize = 14;
const F_PHONE: usize = 15;
const F_ADDRESS: usize = 16;
const F_CITY: usize = 17;
const F_STATE: usize = 18;
const F_POSTAL: usize = 19;
const F_COUNTRY: usize = 20;
const F_MIDDLE: usize = 21;
const F_IDUSER: usize = 22;
const F_COMPANY: usize = 23;
const F_SSN: usize = 24;
const F_PASSPORT: usize = 25;
const F_LICENSE: usize = 26;
const F_ADDR2: usize = 27;
const F_ADDR3: usize = 28;

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
    /// Card cardholder name (card type).
    pub cardholder: Option<String>,
    /// Card brand (card type).
    pub brand: Option<String>,
    /// Card number (card type, secret).
    pub number: Option<String>,
    /// Card expiry month, split from the `MM/YYYY` field (card type).
    pub exp_month: Option<String>,
    /// Card expiry year, split from the `MM/YYYY` field (card type).
    pub exp_year: Option<String>,
    /// Card CVV/CVC (card type, secret).
    pub code: Option<String>,
    /// Curated identity fields (identity type) — all non-secret.
    pub identity: IdentityFields,
}

/// The identity fields the TUI form edits (the full set). `ssn`,
/// `passport_number`, and `license_number` are sensitive — masked in the form
/// and redacted in `Debug`.
#[derive(Clone, Default)]
pub struct IdentityFields {
    /// Title (`Mr`, `Ms`, …).
    pub title: Option<String>,
    /// First name.
    pub first_name: Option<String>,
    /// Middle name.
    pub middle_name: Option<String>,
    /// Last name.
    pub last_name: Option<String>,
    /// Identity username.
    pub username: Option<String>,
    /// Company.
    pub company: Option<String>,
    /// Email.
    pub email: Option<String>,
    /// Phone.
    pub phone: Option<String>,
    /// Address line 1.
    pub address1: Option<String>,
    /// Address line 2.
    pub address2: Option<String>,
    /// Address line 3.
    pub address3: Option<String>,
    /// City.
    pub city: Option<String>,
    /// State / province.
    pub state: Option<String>,
    /// Postal code.
    pub postal_code: Option<String>,
    /// Country.
    pub country: Option<String>,
    /// SSN / national id (sensitive).
    pub ssn: Option<String>,
    /// Passport number (sensitive).
    pub passport_number: Option<String>,
    /// License number (sensitive).
    pub license_number: Option<String>,
}

impl IdentityFields {
    /// Whether any identity field is set (drives the edit "no changes" gate
    /// without listing each field there).
    fn any_set(&self) -> bool {
        [
            &self.title,
            &self.first_name,
            &self.middle_name,
            &self.last_name,
            &self.username,
            &self.company,
            &self.email,
            &self.phone,
            &self.address1,
            &self.address2,
            &self.address3,
            &self.city,
            &self.state,
            &self.postal_code,
            &self.country,
            &self.ssn,
            &self.passport_number,
            &self.license_number,
        ]
        .iter()
        .any(|o| o.is_some())
    }
}

impl fmt::Debug for IdentityFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |o: &Option<String>| o.as_ref().map(|_| "<redacted>");
        f.debug_struct("IdentityFields")
            .field("title", &self.title)
            .field("first_name", &self.first_name)
            .field("middle_name", &self.middle_name)
            .field("last_name", &self.last_name)
            .field("username", &self.username)
            .field("company", &self.company)
            .field("email", &self.email)
            .field("phone", &self.phone)
            .field("address1", &self.address1)
            .field("address2", &self.address2)
            .field("address3", &self.address3)
            .field("city", &self.city)
            .field("state", &self.state)
            .field("postal_code", &self.postal_code)
            .field("country", &self.country)
            .field("ssn", &redact(&self.ssn))
            .field("passport_number", &redact(&self.passport_number))
            .field("license_number", &redact(&self.license_number))
            .finish()
    }
}

impl fmt::Debug for FormSubmit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |o: &Option<String>| o.as_ref().map(|_| "<redacted>");
        f.debug_struct("FormSubmit")
            .field("kind", &self.kind)
            .field("cipher_type", &self.cipher_type)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &redact(&self.password))
            .field("uri", &self.uri)
            .field("folder", &self.folder)
            .field("notes", &self.notes)
            .field("cardholder", &self.cardholder)
            .field("brand", &self.brand)
            .field("number", &redact(&self.number))
            .field("exp_month", &self.exp_month)
            .field("exp_year", &self.exp_year)
            .field("code", &redact(&self.code))
            .field("identity", &self.identity)
            .finish()
    }
}

impl FormState {
    /// Blank field set shared by both constructors. Labels are kept ≤8 chars to
    /// fit the `{:<8}` column the renderer uses (so `Holder`/`CVV`, not
    /// `Cardholder`/`Code`). `Pass`/`Number`/`CVV` mask while unfocused.
    fn blank_fields() -> Vec<FormField> {
        [
            "Name", "User", "Pass", "URI", "Folder", "Notes", // shared / login
            "Holder", "Brand", "Number", "Expiry", "CVV", // card
            "Title", "First", "Last", "Email", "Phone", "Addr1", "City", "State", "Postal",
            "Country", // identity
            "Middle", "IdUser", "Company", "SSN", "Passport", "License", "Addr2",
            "Addr3", // identity (long-tail + secrets)
        ]
        .into_iter()
        .map(|label| FormField {
            label,
            value: TextInput::default(),
            initial: String::new(),
            secret: matches!(
                label,
                "Pass" | "Number" | "CVV" | "SSN" | "Passport" | "License"
            ),
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
    /// carries (name / username / folder). For a card, `detail` (the pane's
    /// on-select fetch) prefills `Holder`/`Brand`/`Expiry`. Secrets stay blank —
    /// blank means "leave unchanged" on submit.
    #[must_use]
    pub fn new_edit(entry: &ListEntry, detail: Option<&DetailView>) -> Self {
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
        if let Some(d) = detail.filter(|d| d.id == entry.id) {
            for (label, value) in &d.lines {
                // Only fields that map 1:1 to a form row prefill. The identity
                // pane's `Person`/`Address` are composites that can't be split
                // back, so those rows start blank = leave-unchanged.
                match (entry.cipher_type, label.as_str()) {
                    (3, "Holder") => prefill(F_CARDHOLDER, value),
                    (3, "Brand") => prefill(F_BRAND, value),
                    (3, "Exp") => prefill(F_EXPIRY, value),
                    (4, "Email") => prefill(F_EMAIL, value),
                    (4, "Phone") => prefill(F_PHONE, value),
                    _ => {}
                }
            }
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
        match self.cipher_type {
            1 => (F_NAME..=F_NOTES).collect(),
            3 => vec![
                F_NAME,
                F_CARDHOLDER,
                F_BRAND,
                F_NUMBER,
                F_EXPIRY,
                F_CODE,
                F_FOLDER,
                F_NOTES,
            ],
            // Identity exposes its full field set (the form scrolls). SSN /
            // passport / license are secret rows (masked while unfocused).
            4 => vec![
                F_NAME, F_TITLE, F_FIRST, F_MIDDLE, F_LAST, F_IDUSER, F_COMPANY, F_EMAIL, F_PHONE,
                F_ADDRESS, F_ADDR2, F_ADDR3, F_CITY, F_STATE, F_POSTAL, F_COUNTRY, F_SSN,
                F_PASSPORT, F_LICENSE, F_FOLDER, F_NOTES,
            ],
            // Secure notes (and anything else) edit only the metadata fields
            // every cipher type carries.
            _ => vec![F_NAME, F_FOLDER, F_NOTES],
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

    /// Cycle login → secure note → card → identity → login (no-op unless the
    /// Type row has focus). Focus stays on row 0, so the row count change can't
    /// overflow it.
    pub const fn toggle_type(&mut self) {
        if self.on_type_row() {
            self.cipher_type = match self.cipher_type {
                1 => 2,
                2 => 3,
                3 => 4,
                _ => 1,
            };
        }
    }

    /// Human name of the cipher type being composed.
    #[must_use]
    pub const fn type_label(&self) -> &'static str {
        match self.cipher_type {
            1 => "login",
            3 => "card",
            4 => "identity",
            _ => "secure note",
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
        let cardholder = take(F_CARDHOLDER);
        let brand = take(F_BRAND);
        let number = take(F_NUMBER);
        let code = take(F_CODE);
        // The form carries one `MM/YYYY` field; split it for the wire. A change
        // to an empty string (cleared field) carries no expiry rather than
        // erroring — only a non-empty, malformed value is rejected.
        let expiry = take(F_EXPIRY);
        let (exp_month, exp_year) = match expiry.as_deref() {
            Some(s) if !s.is_empty() => {
                let (m, y) = parse_expiry(s).map_err(|()| "expiry must be MM/YYYY".to_owned())?;
                (Some(m), Some(y))
            }
            _ => (None, None),
        };
        let identity = IdentityFields {
            title: take(F_TITLE),
            first_name: take(F_FIRST),
            middle_name: take(F_MIDDLE),
            last_name: take(F_LAST),
            username: take(F_IDUSER),
            company: take(F_COMPANY),
            email: take(F_EMAIL),
            phone: take(F_PHONE),
            address1: take(F_ADDRESS),
            address2: take(F_ADDR2),
            address3: take(F_ADDR3),
            city: take(F_CITY),
            state: take(F_STATE),
            postal_code: take(F_POSTAL),
            country: take(F_COUNTRY),
            ssn: take(F_SSN),
            passport_number: take(F_PASSPORT),
            license_number: take(F_LICENSE),
        };
        match self.kind {
            FormKind::Add => {
                if name.as_deref().is_none_or(str::is_empty) {
                    return Err("name is required".to_owned());
                }
            }
            FormKind::Edit { .. } => {
                let metadata_unchanged = [
                    &name,
                    &username,
                    &password,
                    &uri,
                    &folder,
                    &notes,
                    &cardholder,
                    &brand,
                    &number,
                    &code,
                    &expiry,
                ]
                .iter()
                .all(|o| o.is_none());
                if metadata_unchanged && !identity.any_set() {
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
            cardholder,
            brand,
            number,
            exp_month,
            exp_year,
            code,
            identity,
        })
    }
}

/// Split an `MM/YYYY` (or `MM/YY`, expanded to `20YY`) expiry into
/// `(month, year)` strings; month is validated `1..=12` and emitted unpadded
/// (the agent zero-pads on display). Mirrors the CLI's `split_expiry`.
fn parse_expiry(raw: &str) -> Result<(String, String), ()> {
    let (m, y) = raw.split_once('/').ok_or(())?;
    let month: u32 = m.trim().parse().map_err(|_| ())?;
    if !(1..=12).contains(&month) {
        return Err(());
    }
    let y = y.trim();
    if y.is_empty() || !y.chars().all(|c| c.is_ascii_digit()) {
        return Err(());
    }
    let year = if y.len() == 2 {
        format!("20{y}")
    } else {
        y.to_owned()
    };
    Ok((month.to_string(), year))
}

/// Vertical scroll offset (in rows) that keeps the `focused` row visible in a
/// viewport `height` rows tall: 0 until focus passes the bottom, then just
/// enough to pin it to the last visible line. Pure, so the renderer stays
/// stateless. `height == 0` falls back to no scroll.
#[must_use]
pub const fn scroll_offset(focused: usize, height: usize) -> usize {
    focused.saturating_sub(height.saturating_sub(1))
}

/// Top-level TUI state.
#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "App is the TUI's flat UI-state aggregate; these are independent toggles (config prefs + transient flags), not a state machine to fold into an enum"
)]
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
    /// Generator overlay value, `Some` while [`InputMode::Generate`] is open.
    pub generator: Option<GeneratorState>,
    /// Active generator mode (`generate.mode`); persists across overlay reopen.
    pub gen_mode: GeneratorMode,
    /// Character-password options for the generator (`generate.length` / classes).
    pub gen_pw: GenerateOptions,
    /// Passphrase options for the generator (`generate.words` / separator / …).
    pub gen_pp: PassphraseOptions,
    /// Add/edit form state, `Some` while [`InputMode::Form`] is open.
    pub form: Option<FormState>,
    /// Delete target `(id, name)`, `Some` while [`InputMode::ConfirmDelete`]
    /// is open.
    pub confirm_delete: Option<(String, String)>,
    /// Secret currently revealed in the detail pane, if any.
    pub revealed: Option<RevealedSecret>,
    /// Cached non-sensitive fields for the selected card/identity, `Some` while
    /// such an item is selected (populated on select; `None` for logins/notes).
    pub detail: Option<DetailView>,
    /// Cursor into [`detail_fields`] for the selected item, used while the
    /// detail pane is focused (per-field reveal/copy). Reset when the selection
    /// changes or the detail pane is (re-)focused.
    pub detail_field: usize,
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
    /// Vim-style jump motions enabled (`tui.vim`): `gg`/`G`/`Ctrl-d`/`Ctrl-u`,
    /// with the generator moved from `g` to `Ctrl-g`.
    pub vim: bool,
    /// Whether a `g` is pending the second `g` of a `gg` (vim mode only).
    pub pending_g: bool,
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
            gen_mode: GeneratorMode::Password,
            gen_pw: GenerateOptions::default(),
            gen_pp: PassphraseOptions::default(),
            form: None,
            confirm_delete: None,
            revealed: None,
            detail: None,
            detail_field: 0,
            osc52_clear_at: None,
            toast: None,
            unlock: None,
            reduced_motion: false,
            vim: false,
            pending_g: false,
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
            gen_mode: GeneratorMode::Password,
            gen_pw: GenerateOptions::default(),
            gen_pp: PassphraseOptions::default(),
            form: None,
            confirm_delete: None,
            revealed: None,
            detail: None,
            detail_field: 0,
            osc52_clear_at: None,
            toast: None,
            unlock: None,
            reduced_motion: false,
            vim: false,
            pending_g: false,
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

    /// Cycle the unlock mode: master password → PIN (if enrolled) → fingerprint
    /// (if configured) → … . A no-op when no alternative is available or mid-2FA.
    /// Clears the field and any error on switch.
    pub fn cycle_unlock_mode(&mut self) {
        let Some(u) = self.unlock.as_mut() else {
            return;
        };
        if u.awaiting_2fa {
            return;
        }
        // `(use_pin, use_fingerprint)` for each available mode, in cycle order.
        let mut modes = vec![(false, false)]; // master password — always present
        if u.pin_enabled {
            modes.push((true, false));
        }
        if u.fingerprint_enabled {
            modes.push((false, true));
        }
        if modes.len() < 2 {
            return; // nothing to switch to
        }
        let cur = (u.use_pin, u.use_fingerprint);
        let idx = modes.iter().position(|m| *m == cur).unwrap_or(0);
        let (next_pin, next_fp) = modes[(idx + 1) % modes.len()];
        u.use_pin = next_pin;
        u.use_fingerprint = next_fp;
        u.secret.clear();
        u.error = None;
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
                    self.detail_field = 0;
                }
            }
            Focus::Items => {
                let len = self.filtered().len();
                if len > 0 && self.item_sel + 1 < len {
                    self.item_sel += 1;
                    self.detail_field = 0;
                }
            }
            Focus::Detail => {
                let n = self.detail_field_count();
                if n > 0 && self.detail_field + 1 < n {
                    self.detail_field += 1;
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
                    self.detail_field = 0;
                }
            }
            Focus::Items => {
                let prev = self.item_sel;
                self.item_sel = self.item_sel.saturating_sub(1);
                if self.item_sel != prev {
                    self.detail_field = 0;
                }
            }
            Focus::Detail => self.detail_field = self.detail_field.saturating_sub(1),
        }
    }

    /// Jump to the first row of the focused pane (vim `gg`).
    pub fn move_top(&mut self) {
        self.revealed = None;
        match self.focus {
            Focus::Folders => {
                self.folder_sel = 0;
                self.item_sel = 0;
                self.detail_field = 0;
            }
            Focus::Items => {
                self.item_sel = 0;
                self.detail_field = 0;
            }
            Focus::Detail => self.detail_field = 0,
        }
    }

    /// Jump to the last row of the focused pane (vim `G`); no-op when empty.
    pub fn move_bottom(&mut self) {
        self.revealed = None;
        match self.focus {
            Focus::Folders => {
                self.folder_sel = self.folders.len().saturating_sub(1);
                self.item_sel = 0;
                self.detail_field = 0;
            }
            Focus::Items => {
                self.item_sel = self.filtered().len().saturating_sub(1);
                self.detail_field = 0;
            }
            Focus::Detail => self.detail_field = self.detail_field_count().saturating_sub(1),
        }
    }

    /// Move the focused selection down by a half-page (vim `Ctrl-d`), clamped.
    pub fn page_down(&mut self) {
        for _ in 0..VIM_PAGE {
            self.move_down();
        }
    }

    /// Move the focused selection up by a half-page (vim `Ctrl-u`), clamped.
    pub fn page_up(&mut self) {
        for _ in 0..VIM_PAGE {
            self.move_up();
        }
    }

    /// Arm the `gg` prefix: the next `g` jumps to the top.
    pub const fn arm_pending_g(&mut self) {
        self.pending_g = true;
    }

    /// Consume the `gg` prefix, returning whether a `g` was pending (and
    /// clearing it either way).
    pub const fn take_pending_g(&mut self) -> bool {
        let was = self.pending_g;
        self.pending_g = false;
        was
    }

    /// Cancel any pending `gg` prefix (a non-`g` key was pressed).
    pub const fn clear_pending_g(&mut self) {
        self.pending_g = false;
    }

    /// Cycle focus folders → items → detail → folders.
    pub fn focus_next(&mut self) {
        self.revealed = None;
        self.focus = match self.focus {
            Focus::Folders => Focus::Items,
            Focus::Items => Focus::Detail,
            Focus::Detail => Focus::Folders,
        };
        // Start at the first field each time the detail pane takes focus.
        if matches!(self.focus, Focus::Detail) {
            self.detail_field = 0;
        }
    }

    /// Whether the item list currently has focus — the gate for copy / reveal
    /// actions, which target the selected item.
    #[must_use]
    pub const fn items_focused(&self) -> bool {
        matches!(self.focus, Focus::Items)
    }

    /// Whether the detail pane currently has focus (per-field reveal/copy).
    #[must_use]
    pub const fn detail_focused(&self) -> bool {
        matches!(self.focus, Focus::Detail)
    }

    /// Number of per-field-navigable fields for the selected item (0 if none).
    fn detail_field_count(&self) -> usize {
        self.selected_entry()
            .map_or(0, |e| detail_fields(e.cipher_type).len())
    }

    /// The detail field the cursor currently points at, if any.
    #[must_use]
    pub fn selected_detail_field(&self) -> Option<DetailField> {
        let e = self.selected_entry()?;
        detail_fields(e.cipher_type).get(self.detail_field).cloned()
    }

    /// The `(id, name, field)` that `Space` should reveal given the current
    /// focus and selection, or `None` when nothing is revealable.
    ///
    /// Cards and identities reveal the cursor-selected **masked** detail field
    /// when the detail pane is focused. Logins and secure notes have no per-field
    /// detail rows, so in the detail pane they fall back to the type's primary
    /// secret — without this, `Space` did nothing on a login while the detail
    /// pane was focused. The item list and the folder pane both reveal the
    /// selected item's primary secret, so `Space` works from any of the three
    /// panes.
    #[must_use]
    pub fn reveal_target(&self) -> Option<(String, String, Field)> {
        let sel = self.selected_entry()?;
        let field = if self.detail_focused() {
            self.selected_detail_field()
                .filter(|d| d.masked)
                .map(|d| d.field)
                .or_else(|| {
                    detail_fields(sel.cipher_type)
                        .is_empty()
                        .then(|| primary_secret_field(sel.cipher_type))
                        .flatten()
                })?
        } else {
            // Item list or folder pane: the selected item's primary secret.
            primary_secret_field(sel.cipher_type)?
        };
        Some((sel.id, sel.name, field))
    }

    /// Whether `field` of the item with `entry_id` is currently revealed.
    #[must_use]
    pub fn is_revealed(&self, entry_id: &str, field: &Field) -> bool {
        self.revealed
            .as_ref()
            .is_some_and(|r| r.entry_id == entry_id && &r.field == field)
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
        self.generator = Some(GeneratorState {
            value: Zeroizing::new(String::new()),
        });
        self.mode = InputMode::Generate;
        self.regenerate();
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

    /// Replace the overlay's value with a fresh one under the current mode and
    /// options. No-op when the overlay is closed.
    pub fn regenerate(&mut self) {
        if self.generator.is_none() {
            return;
        }
        let result = match self.gen_mode {
            GeneratorMode::Password => generate_password(&self.gen_pw),
            GeneratorMode::Passphrase => generate_passphrase(&self.gen_pp),
        };
        match result {
            Ok(value) => {
                if let Some(g) = self.generator.as_mut() {
                    g.value = value;
                }
            }
            Err(e) => self.toast = Some(format!("generate failed: {e}")),
        }
    }

    /// Toggle between password and passphrase mode, regenerating immediately.
    pub fn gen_toggle_mode(&mut self) {
        self.gen_mode = match self.gen_mode {
            GeneratorMode::Password => GeneratorMode::Passphrase,
            GeneratorMode::Passphrase => GeneratorMode::Password,
        };
        self.regenerate();
    }

    /// Grow or shrink the primary count by `delta` — password length or
    /// passphrase word count, each clamped to its bounds — regenerating on
    /// change.
    pub fn gen_adjust_count(&mut self, delta: isize) {
        let changed = match self.gen_mode {
            GeneratorMode::Password => {
                let len = self
                    .gen_pw
                    .length
                    .saturating_add_signed(delta)
                    .clamp(GEN_MIN_LEN, GEN_MAX_LEN);
                let changed = len != self.gen_pw.length;
                self.gen_pw.length = len;
                changed
            }
            GeneratorMode::Passphrase => {
                let words = self
                    .gen_pp
                    .words
                    .saturating_add_signed(delta)
                    .clamp(GEN_MIN_WORDS, GEN_MAX_WORDS);
                let changed = words != self.gen_pp.words;
                self.gen_pp.words = words;
                changed
            }
        };
        if changed {
            self.regenerate();
        }
    }

    /// Toggle the symbol class (password mode only), regenerating immediately.
    pub fn gen_toggle_symbols(&mut self) {
        if self.gen_mode == GeneratorMode::Password {
            self.gen_pw.symbols = !self.gen_pw.symbols;
            self.regenerate();
        }
    }

    /// Toggle word capitalization (passphrase mode only), regenerating.
    pub fn gen_toggle_capitalize(&mut self) {
        if self.gen_mode == GeneratorMode::Passphrase {
            self.gen_pp.capitalize = !self.gen_pp.capitalize;
            self.regenerate();
        }
    }

    /// Toggle the appended digit (passphrase mode only), regenerating.
    pub fn gen_toggle_include_number(&mut self) {
        if self.gen_mode == GeneratorMode::Passphrase {
            self.gen_pp.include_number = !self.gen_pp.include_number;
            self.regenerate();
        }
    }

    /// Cycle the word separator through [`SEPARATORS`] (passphrase mode only),
    /// regenerating. An off-list separator (e.g. from config) restarts at the
    /// front of the list.
    pub fn gen_cycle_separator(&mut self) {
        if self.gen_mode != GeneratorMode::Passphrase {
            return;
        }
        let next = SEPARATORS
            .iter()
            .position(|s| *s == self.gen_pp.separator)
            .map_or(0, |i| (i + 1) % SEPARATORS.len());
        SEPARATORS[next].clone_into(&mut self.gen_pp.separator);
        self.regenerate();
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
        self.form = Some(FormState::new_edit(&sel, self.detail.as_ref()));
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
    fn vim_motions_jump_and_clamp() {
        let entries: Vec<ListEntry> = (0..25).map(|i| entry(&format!("e{i}"), None)).collect();
        let mut app = App::browsing(status(), entries);
        assert_eq!(app.item_sel, 0);
        app.move_bottom();
        assert_eq!(app.item_sel, 24, "G lands on the last row");
        app.move_top();
        assert_eq!(app.item_sel, 0, "gg lands on the first row");
        app.page_down();
        assert_eq!(app.item_sel, VIM_PAGE, "Ctrl-d moves a half-page");
        app.page_up();
        assert_eq!(app.item_sel, 0, "Ctrl-u clamps at the top");
        // page motions clamp at the bottom.
        app.move_bottom();
        app.page_down();
        assert_eq!(app.item_sel, 24, "Ctrl-d clamps at the last row");
    }

    #[test]
    fn move_bottom_on_empty_list_is_a_noop() {
        let mut app = App::browsing(status(), vec![]);
        app.move_bottom();
        assert_eq!(app.item_sel, 0);
    }

    #[test]
    fn pending_g_arms_once_then_fires() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        assert!(!app.take_pending_g(), "nothing pending initially");
        app.arm_pending_g();
        assert!(app.take_pending_g(), "first take after arm fires gg");
        assert!(!app.take_pending_g(), "and is cleared afterwards");
        app.arm_pending_g();
        app.clear_pending_g();
        assert!(!app.take_pending_g(), "a non-g key cancels the prefix");
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
    fn focus_next_cycles_folders_items_detail() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        assert_eq!(app.focus, Focus::Items);
        app.focus_next();
        assert_eq!(app.focus, Focus::Detail);
        app.focus_next();
        assert_eq!(app.focus, Focus::Folders);
        app.focus_next();
        assert_eq!(app.focus, Focus::Items);
    }

    #[test]
    fn detail_fields_cover_card_and_identity() {
        assert!(detail_fields(1).is_empty(), "login uses its own copy keys");
        assert!(detail_fields(2).is_empty(), "note has no per-field nav");
        let card: Vec<&str> = detail_fields(3).iter().map(|f| f.label).collect();
        assert_eq!(card, ["Holder", "Brand", "Number", "Exp", "CVV"]);
        let cvv = detail_fields(3)
            .iter()
            .find(|f| f.label == "CVV")
            .expect("card has a CVV field");
        assert_eq!(cvv.field, Field::CardCode);
        assert!(cvv.masked, "CVV is masked until revealed");
        // Identity exposes its full granular set; the three sensitive fields are
        // masked.
        let id = detail_fields(4);
        assert_eq!(id.len(), 18);
        for label in ["SSN", "Passport", "License"] {
            let f = id.iter().find(|f| f.label == label).expect("field present");
            assert!(f.masked, "{label} must be masked");
        }
        assert_eq!(
            id.iter()
                .find(|f| f.label == "SSN")
                .map(|f| f.field.clone()),
            Some(Field::IdentitySsn)
        );
    }

    #[test]
    fn detail_cursor_navigates_and_clamps() {
        let mut app = App::browsing(status(), vec![card_entry()]);
        app.focus = Focus::Detail;
        assert_eq!(app.selected_detail_field().map(|f| f.label), Some("Holder"));
        for _ in 0..10 {
            app.move_down(); // clamps at the last card field
        }
        assert_eq!(app.detail_field, 4);
        assert_eq!(app.selected_detail_field().map(|f| f.label), Some("CVV"));
        for _ in 0..10 {
            app.move_up();
        }
        assert_eq!(app.detail_field, 0);
    }

    #[test]
    fn detail_field_resets_when_item_selection_changes() {
        let mut app = App::browsing(status(), vec![card_entry(), entry("b", None)]);
        app.focus = Focus::Detail;
        app.move_down();
        assert_eq!(app.detail_field, 1);
        // Moving the item selection re-zeroes the field cursor.
        app.focus = Focus::Items;
        app.move_down();
        assert_eq!(app.detail_field, 0);
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
        assert!(!app.is_revealed("id-a", &Field::Password));
        app.reveal(RevealedSecret::new(
            "id-a".to_owned(),
            Field::Password,
            "hunter2".to_owned(),
        ));
        assert!(app.is_revealed("id-a", &Field::Password));
        // A different item or field is not considered revealed.
        assert!(!app.is_revealed("id-b", &Field::Password));
        assert!(!app.is_revealed("id-a", &Field::Username));
        app.hide_revealed();
        assert!(!app.is_revealed("id-a", &Field::Password));
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
    fn reveal_target_reveals_login_password_in_detail_pane() {
        let mut app = App::browsing(status(), vec![entry("site", None)]); // login
        // Item list → the login's primary secret.
        assert!(app.items_focused());
        assert_eq!(
            app.reveal_target().map(|(_, _, f)| f),
            Some(Field::Password)
        );
        // Detail pane on a login (no per-field rows): Space must still reveal the
        // password — the bug this fixes was `Space` doing nothing here.
        app.focus = Focus::Detail;
        assert_eq!(
            app.reveal_target().map(|(_, _, f)| f),
            Some(Field::Password)
        );
        // Folder pane (left) also reveals the selected item's primary secret.
        app.focus = Focus::Folders;
        assert_eq!(
            app.reveal_target().map(|(_, _, f)| f),
            Some(Field::Password)
        );
    }

    #[test]
    fn reveal_target_uses_cursor_masked_field_for_cards() {
        let card = ListEntry {
            id: "id-card".into(),
            name: "card".into(),
            cipher_type: 3,
            username: None,
            folder: None,
        };
        let mut app = App::browsing(status(), vec![card]);
        app.focus = Focus::Detail;
        // Card detail rows: [Holder, Brand, Number(masked), Exp, CVV(masked)].
        app.detail_field = 0; // Holder — not masked → nothing to reveal.
        assert!(app.reveal_target().is_none());
        app.detail_field = 2; // Number — masked → the card number.
        assert_eq!(
            app.reveal_target().map(|(_, _, f)| f),
            Some(Field::CardNumber)
        );
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
    fn primary_fields_by_cipher_type() {
        use super::{Field, primary_copy_field, primary_secret_field};
        assert_eq!(primary_secret_field(1), Some(Field::Password));
        assert_eq!(primary_secret_field(3), Some(Field::CardNumber));
        assert_eq!(primary_secret_field(4), None); // identity: no masked secret
        assert_eq!(primary_secret_field(2), None); // secure note
        assert_eq!(primary_copy_field(1), Some((Field::Password, "password")));
        assert_eq!(
            primary_copy_field(3),
            Some((Field::CardNumber, "card number"))
        );
        assert_eq!(primary_copy_field(4), Some((Field::IdentityEmail, "email")));
        assert_eq!(primary_copy_field(2), None);
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
        assert_eq!(app.gen_mode, GeneratorMode::Password);
        let first = app
            .generator
            .as_ref()
            .map(|g| g.value().to_owned())
            .expect("generator open");
        assert_eq!(first.chars().count(), 20, "default length is 20");

        app.regenerate();
        let second = app
            .generator
            .as_ref()
            .map(|g| g.value().to_owned())
            .expect("generator still open");
        // 62^20 keyspace — a collision here means the RNG is broken.
        assert_ne!(first, second, "regenerate must draw a fresh value");

        app.close_generator();
        assert!(app.generator.is_none());
        assert_eq!(app.mode, InputMode::Normal);
    }

    #[test]
    fn generator_count_adjusts_and_clamps() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_generator();
        app.gen_adjust_count(1);
        assert_eq!(app.gen_pw.length, 21);
        assert_eq!(
            app.generator.as_ref().map(|g| g.value().chars().count()),
            Some(21)
        );
        app.gen_adjust_count(-1000);
        assert_eq!(app.gen_pw.length, GEN_MIN_LEN, "length clamps at the floor");
        app.gen_adjust_count(1000);
        assert_eq!(
            app.gen_pw.length, GEN_MAX_LEN,
            "length clamps at the ceiling"
        );
    }

    #[test]
    fn generator_symbols_toggle_regenerates() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_generator();
        assert!(!app.gen_pw.symbols);
        app.gen_toggle_symbols();
        assert!(app.gen_pw.symbols);
        let g = app.generator.as_ref().expect("generator open");
        assert!(
            g.value().chars().any(|c| "!@#$%^&*".contains(c)),
            "an enabled class is guaranteed at least one character"
        );
    }

    #[test]
    fn generator_passphrase_mode_words_separator_and_toggles() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_generator();
        app.gen_toggle_mode();
        assert_eq!(app.gen_mode, GeneratorMode::Passphrase);
        // Cycle to "_" (never appears in EFF words) so word-splitting is exact.
        app.gen_cycle_separator();
        assert_eq!(app.gen_pp.separator, "_");
        let v = app
            .generator
            .as_ref()
            .map(|g| g.value().to_owned())
            .expect("open");
        assert_eq!(v.split('_').count(), 3, "default is 3 words: {v}");
        // `+`/`-` adjust the word count in passphrase mode.
        app.gen_adjust_count(2);
        assert_eq!(app.gen_pp.words, 5);
        // Capitalize + include-number toggles take effect.
        app.gen_toggle_capitalize();
        app.gen_toggle_include_number();
        assert!(app.gen_pp.capitalize && app.gen_pp.include_number);
        let v = app
            .generator
            .as_ref()
            .map(|g| g.value().to_owned())
            .expect("open");
        assert_eq!(v.split('_').count(), 5);
        assert!(
            v.chars().any(|c| c.is_ascii_uppercase()),
            "capitalized: {v}"
        );
        assert!(v.chars().any(|c| c.is_ascii_digit()), "has a number: {v}");
        // Symbols toggle is password-only — a no-op here.
        let before = app.gen_pw.symbols;
        app.gen_toggle_symbols();
        assert_eq!(
            app.gen_pw.symbols, before,
            "symbols toggle is password-only"
        );
    }

    #[test]
    fn generator_debug_redacts_value() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_generator();
        let g = app.generator.as_ref().expect("generator open");
        let v = g.value().to_owned();
        let rendered = format!("{g:?}");
        assert!(rendered.contains("GeneratorState"));
        assert!(rendered.contains("<redacted>"));
        assert!(
            !rendered.contains(&v),
            "Debug leaked the generated value: {rendered}"
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
        // Next steps are card, then identity.
        app.form_toggle_type();
        assert_eq!(app.form.as_ref().expect("form open").cipher_type, 3);
        app.form_toggle_type();
        assert_eq!(app.form.as_ref().expect("form open").cipher_type, 4);
        // A fourth wraps back to login — the typed username survived the cycle.
        app.form_toggle_type();
        let form = app.form.as_ref().expect("form open");
        assert_eq!(form.cipher_type, 1);
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

    /// A type-3 list entry for the card form tests.
    fn card_entry() -> ListEntry {
        ListEntry {
            id: "id-visa".to_owned(),
            name: "Visa".to_owned(),
            cipher_type: 3,
            username: None,
            folder: None,
        }
    }

    #[test]
    fn add_card_form_carries_split_expiry_and_redacts_secrets() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_add_form();
        app.form_toggle_type(); // login → secure note
        app.form_toggle_type(); // secure note → card
        let form = app.form.as_ref().expect("form open");
        assert_eq!(form.cipher_type, 3);
        let labels: Vec<&str> = form.rows().iter().map(|r| r.label).collect();
        assert_eq!(
            labels,
            [
                "Type", "Name", "Holder", "Brand", "Number", "Expiry", "CVV", "Folder", "Notes"
            ]
        );
        // Fill rows in order: Name, (skip Holder), Brand, Number, Expiry, CVV.
        let type_into = |app: &mut App, s: &str| {
            for c in s.chars() {
                app.form_push(c);
            }
        };
        app.form_focus_next(); // → Name
        type_into(&mut app, "My Visa");
        app.form_focus_next(); // → Holder (left blank)
        app.form_focus_next(); // → Brand
        type_into(&mut app, "Visa");
        app.form_focus_next(); // → Number
        type_into(&mut app, "4111111111111111");
        app.form_focus_next(); // → Expiry
        type_into(&mut app, "04/2030");
        app.form_focus_next(); // → CVV
        type_into(&mut app, "123");

        let data = app.form_submit_data().expect("valid card add");
        assert_eq!(data.cipher_type, 3);
        assert_eq!(data.name.as_deref(), Some("My Visa"));
        assert_eq!(data.brand.as_deref(), Some("Visa"));
        assert_eq!(data.number.as_deref(), Some("4111111111111111"));
        assert_eq!(data.exp_month.as_deref(), Some("4"));
        assert_eq!(data.exp_year.as_deref(), Some("2030"));
        assert_eq!(data.code.as_deref(), Some("123"));
        assert_eq!(data.cardholder, None, "blank cardholder rides as unset");

        let rendered = format!("{data:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(
            !rendered.contains("4111111111111111") && !rendered.contains("123"),
            "Debug leaked a card secret: {rendered}"
        );
    }

    #[test]
    fn edit_card_prefills_from_detail_and_diffs_expiry() {
        let mut app = App::browsing(status(), vec![card_entry()]);
        // The detail pane's on-select fetch (Brand + Exp) prefills the form.
        app.detail = Some(DetailView {
            id: "id-visa".to_owned(),
            lines: vec![
                ("Holder".to_owned(), "A. Cardholder".to_owned()),
                ("Brand".to_owned(), "Visa".to_owned()),
                ("Exp".to_owned(), "04/2030".to_owned()),
            ],
        });
        app.open_edit_form();
        let form = app.form.as_ref().expect("form open");
        assert!(!form.has_type_row(), "edit can't change the type");
        let rows = form.rows();
        let value_of = |label: &str| {
            rows.iter()
                .find(|r| r.label == label)
                .map(|r| r.value.to_owned())
                .expect("row exists")
        };
        assert_eq!(value_of("Holder"), "A. Cardholder");
        assert_eq!(value_of("Brand"), "Visa");
        assert_eq!(value_of("Expiry"), "04/2030");
        assert_eq!(value_of("Number"), "", "secrets are never prefilled");

        // Edit rows: Name Holder Brand Number Expiry CVV Folder Notes.
        // Walk to Expiry (index 4), clear it, and type a new value.
        for _ in 0..4 {
            app.form_focus_next();
        }
        for _ in 0.."04/2030".len() {
            app.form_pop();
        }
        for c in "05/2031".chars() {
            app.form_push(c);
        }
        let data = app.form_submit_data().expect("valid card edit");
        assert_eq!(data.exp_month.as_deref(), Some("5"));
        assert_eq!(data.exp_year.as_deref(), Some("2031"));
        assert_eq!(data.brand, None, "untouched prefill stays unchanged");
        assert_eq!(data.number, None, "untouched secret stays unchanged");
        assert_eq!(data.name, None);
    }

    #[test]
    fn parse_expiry_accepts_both_year_widths_and_rejects_garbage() {
        assert_eq!(
            parse_expiry("04/2030"),
            Ok(("4".to_owned(), "2030".to_owned()))
        );
        assert_eq!(
            parse_expiry("4/30"),
            Ok(("4".to_owned(), "2030".to_owned()))
        );
        assert!(parse_expiry("2030").is_err(), "no slash");
        assert!(parse_expiry("13/2030").is_err(), "month out of range");
        assert!(parse_expiry("04/").is_err(), "empty year");
        assert!(parse_expiry("ab/2030").is_err(), "non-numeric month");
    }

    #[test]
    fn scroll_offset_keeps_focus_visible() {
        // Within the viewport: no scroll.
        assert_eq!(scroll_offset(0, 10), 0);
        assert_eq!(scroll_offset(9, 10), 0, "last visible row, still no scroll");
        // Past the bottom: scroll just enough to pin focus to the last line.
        assert_eq!(scroll_offset(10, 10), 1);
        assert_eq!(scroll_offset(21, 10), 12);
        // Degenerate viewport heights don't panic.
        assert_eq!(scroll_offset(5, 0), 5);
        assert_eq!(scroll_offset(5, 1), 5);
    }

    /// A type-4 list entry for the identity form tests.
    fn identity_entry() -> ListEntry {
        ListEntry {
            id: "id-jane".to_owned(),
            name: "Jane Doe".to_owned(),
            cipher_type: 4,
            username: None,
            folder: None,
        }
    }

    #[test]
    fn add_identity_form_carries_full_field_set_and_redacts_secrets() {
        let mut app = App::browsing(status(), vec![entry("a", None)]);
        app.open_add_form();
        app.form_toggle_type(); // login → secure note
        app.form_toggle_type(); // secure note → card
        app.form_toggle_type(); // card → identity
        let form = app.form.as_ref().expect("form open");
        assert_eq!(form.cipher_type, 4);
        let labels: Vec<&str> = form.rows().iter().map(|r| r.label).collect();
        assert_eq!(
            labels,
            [
                "Type", "Name", "Title", "First", "Middle", "Last", "IdUser", "Company", "Email",
                "Phone", "Addr1", "Addr2", "Addr3", "City", "State", "Postal", "Country", "SSN",
                "Passport", "License", "Folder", "Notes"
            ]
        );
        let type_into = |app: &mut App, s: &str| {
            for c in s.chars() {
                app.form_push(c);
            }
        };
        // Fill a spread of rows by walking to each (Type row is index 0).
        app.form_focus_next(); // 1 Name
        type_into(&mut app, "Jane Doe");
        for _ in 1..3 {
            app.form_focus_next(); // → 3 First
        }
        type_into(&mut app, "Jane");
        for _ in 3..8 {
            app.form_focus_next(); // → 8 Email
        }
        type_into(&mut app, "jane@example.org");
        for _ in 8..17 {
            app.form_focus_next(); // → 17 SSN (a secret row)
        }
        type_into(&mut app, "123-45-6789");

        let data = app.form_submit_data().expect("valid identity add");
        assert_eq!(data.cipher_type, 4);
        assert_eq!(data.name.as_deref(), Some("Jane Doe"));
        assert_eq!(data.identity.first_name.as_deref(), Some("Jane"));
        assert_eq!(data.identity.email.as_deref(), Some("jane@example.org"));
        assert_eq!(data.identity.ssn.as_deref(), Some("123-45-6789"));
        assert_eq!(data.identity.title, None, "blank field rides as unset");

        // The SSN must never appear in a Debug rendering.
        let rendered = format!("{data:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("123-45"), "ssn leaked: {rendered}");
    }

    #[test]
    fn edit_identity_prefills_email_phone_and_diffs_city() {
        let mut app = App::browsing(status(), vec![identity_entry()]);
        // The detail pane's on-select fetch — Person/Address are composites that
        // can't be split back, so only Email/Phone prefill.
        app.detail = Some(DetailView {
            id: "id-jane".to_owned(),
            lines: vec![
                ("Person".to_owned(), "Jane Doe".to_owned()),
                ("Email".to_owned(), "jane@example.org".to_owned()),
                ("Phone".to_owned(), "+1 555 0100".to_owned()),
                ("Address".to_owned(), "1 Void Navy Way, Amber".to_owned()),
            ],
        });
        app.open_edit_form();
        let form = app.form.as_ref().expect("form open");
        let rows = form.rows();
        let value_of = |label: &str| {
            rows.iter()
                .find(|r| r.label == label)
                .map(|r| r.value.to_owned())
                .expect("row exists")
        };
        assert_eq!(value_of("Email"), "jane@example.org");
        assert_eq!(value_of("Phone"), "+1 555 0100");
        assert_eq!(value_of("First"), "", "composite name not prefilled");

        // Edit rows (no Type row): Name Title First Middle Last IdUser Company
        // Email Phone Addr1 Addr2 Addr3 City … — City is index 12.
        for _ in 0..12 {
            app.form_focus_next();
        }
        for c in "Amber".chars() {
            app.form_push(c);
        }
        let data = app.form_submit_data().expect("valid identity edit");
        assert_eq!(data.identity.city.as_deref(), Some("Amber"));
        assert_eq!(
            data.identity.email, None,
            "untouched prefill stays unchanged"
        );
        assert_eq!(data.identity.first_name, None);
        assert_eq!(data.name, None);
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
            use_fingerprint: false,
            fingerprint_enabled: false,
            error: None,
            awaiting_2fa: false,
            password: Zeroizing::new(Vec::new()),
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
                two_factor,
            } => {
                assert_eq!(server, "https://vault.example.org");
                assert_eq!(email, "me@example.org");
                assert_eq!(password, b"hunter2");
                assert_eq!(device_id.as_deref(), Some("dev-1"));
                assert!(api_key.is_none(), "TUI never supplies an API key");
                assert!(two_factor.is_none(), "no 2FA before a challenge");
            }
            other => panic!("expected Unlock, got {other:?}"),
        }

        // Toggle to PIN, re-type → UnlockPin (no device_id field).
        app.cycle_unlock_mode();
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
    fn begin_2fa_stashes_password_and_request_carries_the_code() {
        use vault_ipc::proto::Request;
        let mut app = App::unlock_screen(status(), unlock_state(true));
        app.input_insert_str("hunter2"); // master password
        if let Some(u) = app.unlock.as_mut() {
            u.begin_2fa();
        }
        let u = app.unlock.as_ref().unwrap();
        assert!(u.awaiting_2fa);
        assert_eq!(u.password.as_slice(), b"hunter2", "password stashed");
        assert!(u.secret.as_str().is_empty(), "field cleared for the code");
        // Type the authenticator code → Unlock carries the stashed password +
        // the code as two_factor.
        app.input_insert_str("123456");
        match app.unlock.as_ref().unwrap().request() {
            Request::Unlock {
                password,
                two_factor,
                ..
            } => {
                assert_eq!(password, b"hunter2");
                assert_eq!(two_factor.expect("2fa code").token, "123456");
            }
            other => panic!("expected Unlock, got {other:?}"),
        }
        // Tab must not switch to PIN mid-2FA even with a PIN enrolled.
        app.cycle_unlock_mode();
        assert!(app.unlock.as_ref().unwrap().awaiting_2fa);
        assert!(!app.unlock.as_ref().unwrap().use_pin);
    }

    #[test]
    fn toggle_pin_is_noop_without_enrollment_and_clears_on_switch() {
        let mut app = App::unlock_screen(status(), unlock_state(false));
        app.cycle_unlock_mode();
        assert!(
            !app.unlock.as_ref().unwrap().use_pin,
            "no PIN enrolled → no switch"
        );

        let mut app = App::unlock_screen(status(), unlock_state(true));
        app.input_insert_str("abc");
        app.cycle_unlock_mode();
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
