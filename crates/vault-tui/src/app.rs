// SPDX-License-Identifier: GPL-3.0-or-later

//! TUI application state and pure navigation / filter logic.
//!
//! Everything here is synchronous and crossterm-free so it unit-tests without a
//! terminal: `main.rs` translates key events into calls on these methods, and
//! `ui.rs` renders from this state. Slice 1 is read-only — the state holds only
//! the non-secret [`ListEntry`] metadata the agent already returned.

use std::collections::BTreeSet;

use vault_ipc::proto::{ListEntry, Status};

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

    /// Items visible under the selected folder, in `entries` order.
    #[must_use]
    pub fn filtered(&self) -> Vec<&ListEntry> {
        let filter = self.active_filter();
        self.entries
            .iter()
            .filter(|e| match filter {
                FolderFilter::All => true,
                FolderFilter::Unfiled => e.folder.is_none(),
                FolderFilter::Named(n) => e.folder.as_deref() == Some(n.as_str()),
            })
            .collect()
    }

    /// The item currently selected in the filtered list, if any.
    #[must_use]
    pub fn selected_entry(&self) -> Option<ListEntry> {
        self.filtered().get(self.item_sel).map(|e| (*e).clone())
    }

    /// Move the selection down by one in the focused pane (saturating).
    pub fn move_down(&mut self) {
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
    pub const fn move_up(&mut self) {
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
    pub const fn focus_next(&mut self) {
        self.focus = match self.focus {
            Focus::Folders => Focus::Items,
            Focus::Items => Focus::Folders,
        };
    }

    /// Request shutdown on the next loop iteration.
    pub const fn quit(&mut self) {
        self.should_quit = true;
    }
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
}
