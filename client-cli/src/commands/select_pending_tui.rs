use std::io::{self, Stdout};

use ansi_to_tui::IntoText;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
use rest_api_types::models::{ClientPendingFile, PendingFile};

use crate::{error::ClientCliError, utils::bishop_art};

// Restores the terminal state when dropped, so panics and early returns
// cannot leave the user in raw mode or the alternate screen.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

struct FilterInput {
    value: String,
    // byte index into value; always on a char boundary
    cursor: usize,
}

impl FilterInput {
    fn new() -> Self {
        Self {
            value: String::new(),
            cursor: 0,
        }
    }

    fn insert(&mut self, c: char) {
        self.value.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            let start = self.value[..self.cursor]
                .char_indices()
                .next_back()
                .map_or(0, |(i, _)| i);
            self.value.drain(start..self.cursor);
            self.cursor = start;
        }
    }

    fn delete(&mut self) {
        if self.cursor < self.value.len() {
            let end = self.value[self.cursor..]
                .char_indices()
                .nth(1)
                .map_or(self.value.len(), |(i, _)| self.cursor + i);
            self.value.drain(self.cursor..end);
        }
    }

    fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor = self.value[..self.cursor]
                .char_indices()
                .next_back()
                .map_or(0, |(i, _)| i);
        }
    }

    fn move_right(&mut self) {
        if self.cursor < self.value.len() {
            self.cursor = self.value[self.cursor..]
                .char_indices()
                .nth(1)
                .map_or(self.value.len(), |(i, _)| self.cursor + i);
        }
    }

    fn home(&mut self) {
        self.cursor = 0;
    }

    fn end(&mut self) {
        self.cursor = self.value.len();
    }

    fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }

    fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    fn as_str(&self) -> &str {
        &self.value
    }

    fn to_line(&self) -> Line<'static> {
        let before = self.value[..self.cursor].to_owned();
        let (cursor_str, after) = if self.cursor < self.value.len() {
            let end = self.value[self.cursor..]
                .char_indices()
                .nth(1)
                .map_or(self.value.len(), |(i, _)| self.cursor + i);
            (
                self.value[self.cursor..end].to_owned(),
                self.value[end..].to_owned(),
            )
        } else {
            (" ".to_owned(), String::new())
        };
        Line::from(vec![
            Span::raw(before),
            Span::styled(
                cursor_str,
                Style::default().add_modifier(Modifier::REVERSED),
            ),
            Span::raw(after),
        ])
    }
}

fn filtered_indices(files: &[PendingFile], filter: &str) -> Vec<usize> {
    if filter.is_empty() {
        return (0..files.len()).collect();
    }
    let lower = filter.to_lowercase();
    files
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            f.path().to_lowercase().contains(&lower)
                || f.digest().to_string().to_lowercase().contains(&lower)
        })
        .map(|(i, _)| i)
        .collect()
}

fn draw(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    files: &[PendingFile],
    filter: &FilterInput,
    list_state: &mut ListState,
) -> io::Result<()> {
    let indices = filtered_indices(files, filter.as_str());
    let file_index = indices.get(list_state.selected().unwrap_or(0)).copied();

    terminal.draw(|f| {
        let outer = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(f.area());
        let panels = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(outer[0]);

        let left = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(panels[0]);

        let filter_para =
            Paragraph::new(filter.to_line()).block(Block::bordered().title(" Filter "));
        f.render_widget(filter_para, left[0]);

        let items: Vec<ListItem> = indices
            .iter()
            .map(|&i| ListItem::new(files[i].path()))
            .collect();
        let list_title = format!(" Pending files ({}/{}) ", indices.len(), files.len());
        let list = List::new(items)
            .block(Block::bordered().title(list_title))
            .highlight_symbol("> ")
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        f.render_stateful_widget(list, left[1], list_state);

        let art_text: Text<'static> = if let Some(idx) = file_index {
            let mut t = bishop_art(files[idx].digest())
                .into_text()
                .unwrap_or_default();
            t.push_line(String::new());
            t.push_line(files[idx].digest().to_string());
            t
        } else {
            Text::from("No matches")
        };
        let art_para = Paragraph::new(art_text)
            .block(Block::bordered().title(" Bishop fingerprint "))
            .wrap(Wrap { trim: false });
        f.render_widget(art_para, panels[1]);

        let hints = Paragraph::new(
            "  type to filter   ←/→ cursor   ↑/↓ select   enter confirm   esc clear/cancel",
        );
        f.render_widget(hints, outer[1]);
    })?;
    Ok(())
}

pub fn select_pending_file(files: Vec<PendingFile>) -> Result<ClientPendingFile, ClientCliError> {
    if files.is_empty() {
        return Err(ClientCliError::NoPendingSignature);
    }

    execute!(io::stdout(), EnterAlternateScreen)
        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
    let _guard = TerminalGuard;
    terminal::enable_raw_mode().map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal =
        Terminal::new(backend).map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;

    let mut filter = FilterInput::new();
    let mut list_state = ListState::default();
    list_state.select(Some(0));

    draw(&mut terminal, &files, &filter, &mut list_state)
        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;

    loop {
        match event::read() {
            Ok(Event::Key(key)) => match key.code {
                KeyCode::Up => {
                    let indices = filtered_indices(&files, filter.as_str());
                    let count = indices.len();
                    if count > 0 {
                        let i = list_state.selected().unwrap_or(0);
                        list_state.select(Some((i + count - 1) % count));
                    }
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Down => {
                    let indices = filtered_indices(&files, filter.as_str());
                    let count = indices.len();
                    if count > 0 {
                        let i = list_state.selected().unwrap_or(0);
                        list_state.select(Some((i + 1) % count));
                    }
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Left => {
                    filter.move_left();
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Right => {
                    filter.move_right();
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Home => {
                    filter.home();
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::End => {
                    filter.end();
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Delete => {
                    filter.delete();
                    list_state.select(Some(0));
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Backspace => {
                    filter.backspace();
                    list_state.select(Some(0));
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Enter => {
                    let indices = filtered_indices(&files, filter.as_str());
                    if let Some(&file_idx) = indices.get(list_state.selected().unwrap_or(0)) {
                        return Ok(files[file_idx].unseal());
                    }
                }
                KeyCode::Esc => {
                    if filter.is_empty() {
                        return Err(ClientCliError::InvalidInput(
                            "Selection cancelled or failed: no path to sign was provided".into(),
                        ));
                    }
                    filter.clear();
                    list_state.select(Some(0));
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                KeyCode::Char(c) => {
                    filter.insert(c);
                    list_state.select(Some(0));
                    draw(&mut terminal, &files, &filter, &mut list_state)
                        .map_err(|e| ClientCliError::InvalidInput(e.to_string()))?;
                }
                _ => {}
            },
            Ok(_) => {}
            Err(e) => return Err(ClientCliError::InvalidInput(e.to_string())),
        }
    }
}
