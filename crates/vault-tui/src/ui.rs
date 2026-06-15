// SPDX-License-Identifier: GPL-3.0-or-later

//! Rendering — a cruxpass-style three-pane layout (PRD §7.2) over the
//! Steelbore palette (Standard §9). Pure function of [`App`] state; no IO.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use vault_ipc::proto::Field;
use vault_theme::steelbore;

use crate::app::{App, Focus, FormKind, InputMode, Screen};

/// Mask shown for a secret field that has not been revealed.
const MASK: &str = "••••••••";

/// Render `buf` with a block caret (`▌`) at `cursor` (a byte offset on a char
/// boundary). `None`, or a cursor at the end, draws a trailing caret (`buf▌`);
/// mid-string draws it inline (`va▌lue`). Used for the search / command line
/// echo and the focused form field.
fn with_cursor(buf: &str, cursor: Option<usize>) -> String {
    let at = cursor.unwrap_or(buf.len()).min(buf.len());
    let mut out = String::with_capacity(buf.len() + "\u{258c}".len());
    out.push_str(&buf[..at]);
    out.push('\u{258c}');
    out.push_str(&buf[at..]);
    out
}

/// Parse a `#RRGGBB` palette constant into a ratatui [`Color`]; falls back to
/// the terminal default on anything malformed.
#[must_use]
fn hex(s: &str) -> Color {
    let s = s.strip_prefix('#').unwrap_or(s);
    if s.len() == 6
        && let Ok(r) = u8::from_str_radix(&s[0..2], 16)
        && let Ok(g) = u8::from_str_radix(&s[2..4], 16)
        && let Ok(b) = u8::from_str_radix(&s[4..6], 16)
    {
        Color::Rgb(r, g, b)
    } else {
        Color::Reset
    }
}

/// Human label for a Bitwarden cipher type.
const fn type_label(t: u8) -> &'static str {
    match t {
        1 => "login",
        2 => "secure note",
        3 => "card",
        4 => "identity",
        _ => "item",
    }
}

/// Draw one frame of the whole UI.
pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let bg = hex(steelbore::VOID_NAVY);
    // Paint the backdrop Void Navy so unused cells aren't terminal-default.
    frame.render_widget(Block::default().style(Style::default().bg(bg)), area);

    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(area);
    let body = rows[0];
    let status_bar = rows[1];

    match &app.screen {
        Screen::Message { title, body: text } => render_message(frame, body, title, text),
        Screen::Browsing => render_browser(frame, app, body),
        Screen::Unlock => render_unlock(frame, app, body),
    }
    match app.mode {
        InputMode::Generate => render_generator(frame, app, body),
        InputMode::Form => render_form(frame, app, body),
        InputMode::ConfirmDelete => render_confirm(frame, app, body),
        InputMode::About => render_about(frame, body),
        InputMode::Normal | InputMode::Search | InputMode::Command | InputMode::Unlock => {}
    }
    render_status_bar(frame, app, status_bar);
}

/// Centered banner for the locked / disconnected states.
fn render_message(frame: &mut Frame, area: Rect, title: &str, body: &str) {
    let amber = hex(steelbore::MOLTEN_AMBER);
    let lines = vec![
        Line::from(Span::styled(
            title.to_owned(),
            Style::default().fg(amber).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            body.to_owned(),
            Style::default().fg(hex(steelbore::INFO)),
        )),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(amber))
        .title(" vault ");
    let para = Paragraph::new(lines)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(block);
    frame.render_widget(para, centered(area, 60, 30));
}

/// Centered interactive unlock prompt (master password / PIN).
fn render_unlock(frame: &mut Frame, app: &App, area: Rect) {
    let Some(u) = app.unlock.as_ref() else {
        return;
    };
    let amber = hex(steelbore::MOLTEN_AMBER);
    let steel = hex(steelbore::STEEL_BLUE);
    let label = if u.use_pin { "PIN" } else { "Password" };
    // Mask the secret, with the caret at the cursor position.
    let masked = "•".repeat(u.secret.as_str().chars().count());
    let field = with_cursor(&masked, Some(masked.len()));

    let mut lines = vec![
        Line::from(Span::styled(
            format!("Unlock {}", u.email),
            Style::default().fg(amber).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("{label}: "), Style::default().fg(steel)),
            Span::styled(field, Style::default().fg(amber)),
        ]),
    ];
    if let Some(err) = u.error.as_deref() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            err.to_owned(),
            Style::default().fg(hex(steelbore::ERROR)),
        )));
    }
    lines.push(Line::from(""));
    let hint = if u.pin_enabled {
        "Enter unlock · Tab password/PIN · Esc quit"
    } else {
        "Enter unlock · Esc quit"
    };
    lines.push(Line::from(Span::styled(
        hint,
        Style::default().fg(steel).add_modifier(Modifier::ITALIC),
    )));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(amber))
        .title(" Locked ")
        .style(Style::default().bg(hex(steelbore::VOID_NAVY)));
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(block),
        centered(area, 60, 40),
    );
}

/// The three-pane browser: folders | items | detail.
fn render_browser(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::horizontal([
        Constraint::Percentage(22),
        Constraint::Percentage(38),
        Constraint::Percentage(40),
    ])
    .split(area);

    render_folders(frame, app, cols[0]);
    render_items(frame, app, cols[1]);
    render_detail(frame, app, cols[2]);
}

fn render_folders(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .folders
        .iter()
        .map(|f| ListItem::new(f.label.clone()))
        .collect();
    let list = List::new(items)
        .block(pane_block("Folders", app.focus == Focus::Folders))
        .highlight_style(highlight(app.focus == Focus::Folders));
    let mut state = ListState::default().with_selected(Some(app.folder_sel));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_items(frame: &mut Frame, app: &App, area: Rect) {
    let filtered = app.filtered();
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|e| {
            let marker = if e.cipher_type == 2 { "≣ " } else { "● " };
            ListItem::new(format!("{marker}{}", e.name))
        })
        .collect();
    // Surface an active search query in the pane title so a narrowed list is
    // never mistaken for the full vault.
    let title = if app.search.is_empty() {
        format!("Items ({})", filtered.len())
    } else {
        format!("Items ({}) /{}", filtered.len(), app.search.as_str())
    };
    let list = List::new(items)
        .block(pane_block(&title, app.focus == Focus::Items))
        .highlight_style(highlight(app.focus == Focus::Items));
    let mut state = ListState::default().with_selected(Some(app.item_sel));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_detail(frame: &mut Frame, app: &App, area: Rect) {
    let amber = hex(steelbore::MOLTEN_AMBER);
    let info = hex(steelbore::INFO);
    let lines: Vec<Line> = app.selected_entry().map_or_else(
        || {
            vec![Line::from(Span::styled(
                "no item selected",
                Style::default().fg(info),
            ))]
        },
        |e| {
            let folder = e.folder.clone().unwrap_or_else(|| "(unfiled)".to_owned());
            let username = e.username.clone().unwrap_or_else(|| "—".to_owned());
            let mut lines = vec![
                field_line("Name", &e.name, amber),
                field_line("Type", type_label(e.cipher_type), info),
                field_line("User", &username, info),
                field_line("Folder", &folder, info),
                field_line("Id", &e.id, info),
            ];
            // Logins carry a password; show it masked, revealed on demand.
            if e.cipher_type == 1 {
                if app.is_revealed(&e.id, Field::Password) {
                    let value = app.revealed.as_ref().map_or(MASK, |r| r.value());
                    lines.push(field_line("Pass", value, amber));
                } else {
                    lines.push(field_line("Pass", MASK, hex(steelbore::STEEL_BLUE)));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Space reveal · c/u/o copy",
                Style::default()
                    .fg(hex(steelbore::STEEL_BLUE))
                    .add_modifier(Modifier::ITALIC),
            )));
            lines
        },
    );
    let para = Paragraph::new(lines)
        .block(pane_block("Detail", false))
        .wrap(Wrap { trim: true });
    frame.render_widget(para, area);
}

/// Centered password-generator overlay, drawn over the browser.
fn render_generator(frame: &mut Frame, app: &App, area: Rect) {
    let Some(g) = app.generator.as_ref() else {
        return;
    };
    let amber = hex(steelbore::MOLTEN_AMBER);
    let info = hex(steelbore::INFO);
    let classes = format!(
        "Length {:<4} a-z {}  A-Z {}  0-9 {}  !@# {}",
        g.opts.length,
        onoff(g.opts.lowercase),
        onoff(g.opts.uppercase),
        onoff(g.opts.digits),
        onoff(g.opts.symbols),
    );
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            g.password().to_owned(),
            Style::default().fg(amber).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(classes, Style::default().fg(info))),
        Line::from(""),
        Line::from(Span::styled(
            "g regen · +/- length · s symbols · c copy · Esc close",
            Style::default()
                .fg(hex(steelbore::STEEL_BLUE))
                .add_modifier(Modifier::ITALIC),
        )),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(amber))
        .title(" Generate ")
        .style(Style::default().bg(hex(steelbore::VOID_NAVY)));
    let overlay = centered(area, 70, 40);
    // Clear whatever the browser drew underneath so the overlay reads cleanly.
    frame.render_widget(ratatui::widgets::Clear, overlay);
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(block),
        overlay,
    );
}

/// `on` / `off` chip text for a generator class toggle.
const fn onoff(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

/// Centered read-only About overlay (Standard §13.2), drawn over the browser.
/// Renders from `crate::PKG_VERSION` + `crate::ATTRIBUTION` so it can't drift
/// from `vault-tui --version`.
fn render_about(frame: &mut Frame, area: Rect) {
    let amber = hex(steelbore::MOLTEN_AMBER);
    let steel = hex(steelbore::STEEL_BLUE);
    let info = hex(steelbore::INFO);
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("Vault v{}", crate::PKG_VERSION),
            Style::default().fg(amber).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    lines.extend(
        crate::ATTRIBUTION
            .lines()
            .map(|l| Line::from(Span::styled(l.to_owned(), Style::default().fg(info)))),
    );
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Esc close",
        Style::default().fg(steel).add_modifier(Modifier::ITALIC),
    )));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(amber))
        .title(" About ")
        .style(Style::default().bg(hex(steelbore::VOID_NAVY)));
    // Wider/taller than the generator overlay so the long §13.2 lines fit
    // without clipping the URL or hint.
    let overlay = centered(area, 80, 60);
    frame.render_widget(ratatui::widgets::Clear, overlay);
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(block),
        overlay,
    );
}

/// Centered add/edit form overlay, drawn over the browser.
fn render_form(frame: &mut Frame, app: &App, area: Rect) {
    let Some(form) = app.form.as_ref() else {
        return;
    };
    let amber = hex(steelbore::MOLTEN_AMBER);
    let info = hex(steelbore::INFO);
    let steel = hex(steelbore::STEEL_BLUE);
    let title = match &form.kind {
        FormKind::Add => " Add ".to_owned(),
        FormKind::Edit { name, .. } => format!(" Edit '{name}' "),
    };
    let mut lines = vec![Line::from("")];
    for row in form.rows() {
        let (value_txt, value_color) = if row.is_type {
            (format!("\u{25b8} {} \u{25c2}", row.value), amber)
        } else if row.secret && !row.focused && !row.value.is_empty() {
            // Compose secrets visibly only while their field has focus.
            (MASK.to_owned(), steel)
        } else if row.focused {
            (with_cursor(row.value, row.cursor), amber)
        } else {
            (row.value.to_owned(), info)
        };
        let label_color = if row.focused { amber } else { steel };
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {:<8}", row.label),
                Style::default()
                    .fg(label_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(value_txt, Style::default().fg(value_color)),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " Enter save · Tab next · Space type · Ctrl+G gen · Esc cancel",
        Style::default().fg(steel).add_modifier(Modifier::ITALIC),
    )));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(amber))
        .title(title)
        .style(Style::default().bg(hex(steelbore::VOID_NAVY)));
    let overlay = centered(area, 70, 70);
    frame.render_widget(ratatui::widgets::Clear, overlay);
    frame.render_widget(Paragraph::new(lines).block(block), overlay);
}

/// Small centered delete-confirm overlay.
fn render_confirm(frame: &mut Frame, app: &App, area: Rect) {
    let Some((_, name)) = app.confirm_delete.as_ref() else {
        return;
    };
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("Delete '{name}'?"),
            Style::default()
                .fg(hex(steelbore::MOLTEN_AMBER))
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "y delete · n cancel",
            Style::default()
                .fg(hex(steelbore::STEEL_BLUE))
                .add_modifier(Modifier::ITALIC),
        )),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(hex(steelbore::ERROR)))
        .title(" Delete ")
        .style(Style::default().bg(hex(steelbore::VOID_NAVY)));
    let overlay = centered(area, 44, 28);
    frame.render_widget(ratatui::widgets::Clear, overlay);
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(block),
        overlay,
    );
}

fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let amber = hex(steelbore::MOLTEN_AMBER);
    let (state_txt, state_color) = app.status.as_ref().map_or_else(
        || ("no agent", hex(steelbore::ERROR)),
        |s| {
            if s.unlocked {
                ("unlocked", hex(steelbore::SUCCESS))
            } else {
                ("locked", hex(steelbore::ERROR))
            }
        },
    );
    let mut spans = vec![
        Span::styled(
            format!(" {state_txt} "),
            Style::default()
                .fg(hex(steelbore::VOID_NAVY))
                .bg(state_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
    ];
    if let Some(s) = app.status.as_ref() {
        if let Some(n) = s.items {
            spans.push(Span::styled(
                format!("{n} items"),
                Style::default().fg(amber),
            ));
            spans.push(Span::raw("  "));
        }
        if let Some(ls) = s.last_sync.as_deref() {
            spans.push(Span::styled(
                format!("synced {ls}"),
                Style::default().fg(hex(steelbore::STEEL_BLUE)),
            ));
            spans.push(Span::raw("  "));
        }
    }
    // The trailing slot shows, in priority order: the line being edited
    // (search / command input), a transient toast, or the key hints.
    let editing = match app.mode {
        InputMode::Search => Some(format!(
            "/{}",
            with_cursor(app.search.as_str(), Some(app.search.cursor()))
        )),
        InputMode::Command => Some(format!(
            ":{}",
            with_cursor(app.command.as_str(), Some(app.command.cursor()))
        )),
        InputMode::Normal
        | InputMode::Generate
        | InputMode::Form
        | InputMode::ConfirmDelete
        | InputMode::Unlock
        | InputMode::About => None,
    };
    if let Some(input) = editing {
        spans.push(Span::styled(
            input,
            Style::default().fg(amber).add_modifier(Modifier::BOLD),
        ));
    } else if let Some(toast) = app.toast.as_deref() {
        spans.push(Span::styled(
            toast.to_owned(),
            Style::default()
                .fg(hex(steelbore::MOLTEN_AMBER))
                .add_modifier(Modifier::BOLD),
        ));
    } else {
        spans.push(Span::styled(
            "q quit  j/k move  Space reveal  c/u/o copy  / search  g gen  a/e/d edit  : cmd  r refresh",
            Style::default().fg(hex(steelbore::STEEL_BLUE)),
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(hex(steelbore::VOID_NAVY))),
        area,
    );
}

/// `Label: value` detail row with an amber-ish label and plain value. Both
/// spans own their text, so the row is `'static` and never borrows the entry.
fn field_line(label: &str, value: &str, value_color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:<7}"),
            Style::default()
                .fg(hex(steelbore::MOLTEN_AMBER))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(value.to_owned(), Style::default().fg(value_color)),
    ])
}

/// A bordered pane block whose border brightens to amber when focused.
fn pane_block(title: &str, focused: bool) -> Block<'static> {
    let border = if focused {
        hex(steelbore::MOLTEN_AMBER)
    } else {
        hex(steelbore::STEEL_BLUE)
    };
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border))
        .title(format!(" {title} "))
}

/// Selection highlight: amber bar when the pane is focused, dimmer otherwise.
fn highlight(focused: bool) -> Style {
    if focused {
        Style::default()
            .bg(hex(steelbore::MOLTEN_AMBER))
            .fg(hex(steelbore::VOID_NAVY))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::REVERSED)
    }
}

/// Rect centered within `area` at the given percentage of width/height.
fn centered(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let h = Layout::horizontal([Constraint::Percentage(percent_x)])
        .flex(Flex::Center)
        .split(area)[0];
    Layout::vertical([Constraint::Percentage(percent_y)])
        .flex(Flex::Center)
        .split(h)[0]
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;

    use super::*;
    use crate::app::RevealedSecret;
    use vault_ipc::proto::{ListEntry, Status};

    fn login_entry() -> ListEntry {
        ListEntry {
            id: "c1".into(),
            name: "github.com".into(),
            cipher_type: 1,
            username: Some("octocat".into()),
            folder: Some("Work".into()),
        }
    }

    fn buffer_text(buf: &Buffer) -> String {
        let area = buf.area;
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    fn draw(app: &App) -> String {
        let backend = TestBackend::new(90, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal.draw(|f| render(f, app)).expect("draw");
        buffer_text(terminal.backend().buffer())
    }

    fn status() -> Status {
        Status {
            unlocked: true,
            server: Some("https://vault.example.org".into()),
            email: Some("alice@example.org".into()),
            items: Some(2),
            last_sync: Some("2026-06-04T00:00:00Z".into()),
            agent_version: "0.0.1".into(),
            clipboard_backend: None,
        }
    }

    #[test]
    fn browsing_frame_shows_items_and_unlocked_bar() {
        let entries = vec![
            ListEntry {
                id: "c1".into(),
                name: "github.com".into(),
                cipher_type: 1,
                username: Some("octocat".into()),
                folder: Some("Work".into()),
            },
            ListEntry {
                id: "c2".into(),
                name: "bank-note".into(),
                cipher_type: 2,
                username: None,
                folder: None,
            },
        ];
        let app = App::browsing(status(), entries);
        let text = draw(&app);
        assert!(text.contains("github.com"), "item name missing:\n{text}");
        assert!(text.contains("Folders"), "folder pane missing");
        assert!(text.contains("Detail"), "detail pane missing");
        assert!(text.contains("unlocked"), "status bar state missing");
    }

    #[test]
    fn locked_frame_shows_banner() {
        let app = App::message("Locked", "Run `vault unlock` to browse.", None);
        let text = draw(&app);
        assert!(text.contains("Locked"), "banner title missing:\n{text}");
        assert!(text.contains("no agent") || text.contains("locked"));
    }

    #[test]
    fn detail_masks_login_password_by_default() {
        let app = App::browsing(status(), vec![login_entry()]);
        let text = draw(&app);
        assert!(text.contains(MASK), "password not masked:\n{text}");
        assert!(!text.contains("hunter2"));
    }

    #[test]
    fn detail_reveals_password_when_set() {
        let mut app = App::browsing(status(), vec![login_entry()]);
        app.reveal(RevealedSecret::new(
            "c1".to_owned(),
            Field::Password,
            "hunter2".to_owned(),
        ));
        let text = draw(&app);
        assert!(text.contains("hunter2"), "revealed value missing:\n{text}");
    }

    #[test]
    fn toast_renders_in_status_bar() {
        let mut app = App::browsing(status(), vec![login_entry()]);
        app.set_toast("copied password · clears in 30s");
        let text = draw(&app);
        assert!(
            text.contains("copied password"),
            "toast missing from status bar:\n{text}"
        );
    }

    #[test]
    fn search_query_renders_in_title_and_status_bar() {
        let mut app = App::browsing(status(), vec![login_entry()]);
        app.open_search();
        for c in "git".chars() {
            app.search_push(c);
        }
        let text = draw(&app);
        assert!(
            text.contains("Items (1) /git"),
            "query missing from items title:\n{text}"
        );
        assert!(
            text.contains("/git\u{258c}"),
            "live query missing from status bar:\n{text}"
        );
    }

    #[test]
    fn cursor_renders_mid_string_after_moving_left() {
        let mut app = App::browsing(status(), vec![login_entry()]);
        app.open_search();
        for c in "git".chars() {
            app.search_push(c);
        }
        app.input_left(); // cursor between 'gi' and 't'
        let text = draw(&app);
        assert!(
            text.contains("/gi\u{258c}t"),
            "mid-string caret missing:\n{text}"
        );
    }

    #[test]
    fn command_line_renders_in_status_bar() {
        let mut app = App::browsing(status(), vec![login_entry()]);
        app.open_command();
        for c in "sync".chars() {
            app.command_push(c);
        }
        let text = draw(&app);
        assert!(
            text.contains(":sync\u{258c}"),
            "command line missing from status bar:\n{text}"
        );
    }

    #[test]
    fn form_overlay_renders_rows_and_masks_unfocused_pass() {
        let mut app = App::browsing(status(), vec![login_entry()]);
        app.open_add_form();
        // Focus Pass (Type → Name → User → Pass), type a secret, focus away.
        for _ in 0..3 {
            app.form_focus_next();
        }
        for c in "hunter2".chars() {
            app.form_push(c);
        }
        app.form_focus_next(); // → URI; Pass is now unfocused
        let text = draw(&app);
        assert!(text.contains(" Add "), "form title missing:\n{text}");
        assert!(
            text.contains("\u{25b8} login \u{25c2}"),
            "type row missing:\n{text}"
        );
        assert!(text.contains(MASK), "unfocused Pass not masked:\n{text}");
        assert!(
            !text.contains("hunter2"),
            "unfocused Pass leaked plaintext:\n{text}"
        );
        assert!(
            text.contains('\u{258c}'),
            "focused-field cursor missing:\n{text}"
        );
    }

    #[test]
    fn confirm_overlay_renders_target_name() {
        let mut app = App::browsing(status(), vec![login_entry()]);
        app.open_confirm_delete();
        let text = draw(&app);
        assert!(
            text.contains("Delete 'github.com'?"),
            "confirm prompt missing:\n{text}"
        );
        assert!(text.contains("y delete"), "confirm hint missing:\n{text}");
    }

    #[test]
    fn unlock_screen_masks_secret_and_shows_account() {
        use crate::app::{TextInput, UnlockState};
        let mut u = UnlockState {
            server: "https://vault.example.org".into(),
            email: "me@example.org".into(),
            device_id: None,
            secret: TextInput::default(),
            use_pin: false,
            pin_enabled: true,
            error: None,
        };
        u.secret = TextInput::from("hunter2");
        let app = App::unlock_screen(status(), u);
        let text = draw(&app);
        assert!(
            text.contains("Unlock me@example.org"),
            "account missing:\n{text}"
        );
        assert!(text.contains('•'), "secret not masked:\n{text}");
        assert!(!text.contains("hunter2"), "secret leaked:\n{text}");
        assert!(
            text.contains("Tab"),
            "PIN toggle hint missing when enrolled:\n{text}"
        );
    }

    #[test]
    fn generator_overlay_renders_password_and_options() {
        let mut app = App::browsing(status(), vec![login_entry()]);
        app.open_generator();
        let pw = app
            .generator
            .as_ref()
            .map(|g| g.password().to_owned())
            .expect("generator open");
        let text = draw(&app);
        assert!(text.contains("Generate"), "overlay title missing:\n{text}");
        assert!(text.contains(&pw), "generated password missing:\n{text}");
        assert!(text.contains("Length 20"), "options line missing:\n{text}");
    }

    #[test]
    fn about_overlay_renders_attribution() {
        let mut app = App::browsing(status(), vec![login_entry()]);
        app.open_about();
        let text = draw(&app);
        assert!(text.contains("About"), "overlay title missing:\n{text}");
        assert!(
            text.contains(&format!("v{}", crate::PKG_VERSION)),
            "version missing:\n{text}"
        );
        assert!(
            text.contains("Mohamed Hammad"),
            "maintainer missing:\n{text}"
        );
        assert!(
            text.contains("GPL-3.0-or-later"),
            "license missing:\n{text}"
        );
        assert!(
            text.contains("SpacecraftSoftware.org"),
            "URL missing:\n{text}"
        );
    }
}
