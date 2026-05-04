use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use crate::{
    default_setup_output, render_host_doctor_from_probe_with_config, setup_agent_command_name,
    setup_agent_label, setup_agent_profile_id, CliError, SetupAgent,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TuiOptions {
    pub config: Option<PathBuf>,
    pub db: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TuiInput {
    NextWorkflow,
    PreviousWorkflow,
    NextProfile,
    PreviousProfile,
    ToggleHelp,
    Refresh,
    Activate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TuiWorkflow {
    Setup,
    Doctor,
    DryRun,
    Launch,
    Receipts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TuiProfile {
    agent: SetupAgent,
    setup_command: &'static str,
}

#[derive(Clone, Debug)]
pub(crate) struct TuiDashboard {
    options: TuiOptions,
    workflows: Vec<TuiWorkflow>,
    workflow_index: usize,
    profiles: Vec<TuiProfile>,
    profile_index: usize,
    show_splash: bool,
    show_help: bool,
    doctor_text: String,
    log_lines: Vec<String>,
}

pub fn run_tui(options: TuiOptions) -> Result<(), CliError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(CliError {
            message: "warder tui requires an interactive terminal; use warder doctor, profiles, dry-run, run, receipt, and journal for scriptable output".to_string(),
        });
    }

    let mut stdout = io::stdout();
    enable_raw_mode().map_err(|error| tui_error("enable raw mode", error))?;
    let _terminal_guard = TerminalGuard;
    execute!(stdout, EnterAlternateScreen)
        .map_err(|error| tui_error("enter alternate screen", error))?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal =
        Terminal::new(backend).map_err(|error| tui_error("initialize terminal", error))?;
    let mut dashboard = TuiDashboard::new(options);

    loop {
        terminal
            .draw(|frame| draw_dashboard(frame, &dashboard))
            .map_err(|error| tui_error("draw dashboard", error))?;

        if event::poll(Duration::from_millis(150))
            .map_err(|error| tui_error("poll input", error))?
        {
            match event::read().map_err(|error| tui_error("read input", error))? {
                Event::Key(key) if should_quit(key) => break,
                Event::Key(_) if dashboard.splash_is_visible() => {
                    dashboard.dismiss_splash();
                }
                Event::Key(key) => {
                    if let Some(input) = input_from_key(key) {
                        dashboard.handle_input(input);
                    }
                }
                _ => {}
            }
        }
    }

    terminal
        .show_cursor()
        .map_err(|error| tui_error("restore cursor", error))?;
    Ok(())
}

impl TuiDashboard {
    fn new(options: TuiOptions) -> Self {
        let mut dashboard = Self::for_test(options);
        dashboard.refresh_doctor();
        dashboard
    }

    pub(crate) fn for_test(options: TuiOptions) -> Self {
        Self {
            options,
            workflows: vec![
                TuiWorkflow::Setup,
                TuiWorkflow::Doctor,
                TuiWorkflow::DryRun,
                TuiWorkflow::Launch,
                TuiWorkflow::Receipts,
            ],
            workflow_index: 0,
            profiles: vec![
                TuiProfile {
                    agent: SetupAgent::Codex,
                    setup_command: "codex",
                },
                TuiProfile {
                    agent: SetupAgent::Claude,
                    setup_command: "claude",
                },
                TuiProfile {
                    agent: SetupAgent::OpenClaw,
                    setup_command: "openclaw",
                },
            ],
            profile_index: 0,
            show_splash: true,
            show_help: false,
            doctor_text: "host doctor has not been refreshed yet".to_string(),
            log_lines: vec![
                "TUI started in guidance mode; launches still use the existing Warder command path."
                    .to_string(),
            ],
        }
    }

    pub(crate) fn handle_input(&mut self, input: TuiInput) {
        if self.show_splash {
            self.dismiss_splash();
            return;
        }

        match input {
            TuiInput::NextWorkflow => {
                self.workflow_index = next_index(self.workflow_index, self.workflows.len())
            }
            TuiInput::PreviousWorkflow => {
                self.workflow_index = previous_index(self.workflow_index, self.workflows.len())
            }
            TuiInput::NextProfile => {
                self.profile_index = next_index(self.profile_index, self.profiles.len())
            }
            TuiInput::PreviousProfile => {
                self.profile_index = previous_index(self.profile_index, self.profiles.len())
            }
            TuiInput::ToggleHelp => self.show_help = !self.show_help,
            TuiInput::Refresh => {
                self.refresh_doctor();
                self.log_lines
                    .push("Refreshed host readiness using warder doctor checks.".to_string());
            }
            TuiInput::Activate => {
                self.log_lines.push(format!(
                    "Next command: {}",
                    self.primary_command_for_current_workflow()
                ));
            }
        }
        if self.log_lines.len() > 6 {
            self.log_lines.remove(0);
        }
    }

    pub(crate) fn workflow_title(&self) -> &'static str {
        self.current_workflow().title()
    }

    pub(crate) fn splash_is_visible(&self) -> bool {
        self.show_splash
    }

    #[cfg(test)]
    pub(crate) fn splash_text(&self) -> &'static str {
        SPLASH_TEXT
    }

    #[cfg(test)]
    pub(crate) fn dismiss_splash_for_test(&mut self) {
        self.dismiss_splash();
    }

    #[cfg(test)]
    pub(crate) fn profile_titles(&self) -> Vec<String> {
        self.profiles
            .iter()
            .map(|profile| setup_agent_label(profile.agent).to_string())
            .collect()
    }

    pub(crate) fn overview_text(&self) -> String {
        let profile = self.current_profile();
        let config = self.config_display_path();
        let setup_output = default_setup_output(profile.agent);
        let setup_output = setup_output.display();
        let command = setup_agent_command_name(profile.agent);
        let profile_id = setup_agent_profile_id(profile.agent);

        match self.current_workflow() {
            TuiWorkflow::Setup => format!(
                "Warder only supervises Warder-launched sessions.\n\nStart here for {label}:\n1. Generate a reviewed policy:\n   warder setup {setup} --workspace . --protect-secrets --output {setup_output}\n2. Read the host/config report:\n   warder doctor --config {setup_output}\n3. Dry-run the launch before using real work:\n   warder dry-run --config {setup_output} --agent {profile_id} -- {command}\n\nThe TUI keeps base commands visible so you can copy them, script them, or run them directly.",
                label = setup_agent_label(profile.agent),
                setup = profile.setup_command,
            ),
            TuiWorkflow::Doctor => format!(
                "Current doctor target: {config}\n\n{}\n\nPress r to refresh this report.",
                self.doctor_text
            ),
            TuiWorkflow::DryRun => format!(
                "Dry-run checks the same policy path without launching the agent.\n\nSuggested command:\nwarder dry-run --config {config} --agent {profile_id} -- {command}\n\nDry-run is still not a simulator of all future agent behavior. It shows config, host support, and degraded protections before launch."
            ),
            TuiWorkflow::Launch => format!(
                "Launch still goes through Warder's existing guarded command path.\n\nBest-effort launch:\nwarder {setup} --config {config} -- <agent args>\n\nStrict launch:\nwarder {setup} --config {config} --require-enforcement --receipt-key <external-key> -- <agent args>\n\nStrict mode refuses degraded enforcement and requires an external receipt key.",
                setup = profile.setup_command,
            ),
            TuiWorkflow::Receipts => format!(
                "After a launch, inspect what actually happened.\n\nRecent receipt:\nwarder receipt --db {db} --session <id>\n\nVerify receipt chain:\nwarder verify-receipts --db {db} --external-key <external-key>\n\nJournals:\nwarder journal --db {db} --all --session <id>\n\nReceipts document host coverage and remind you that direct launches outside Warder are unsupervised.",
                db = self.db_display_path(),
            ),
        }
    }

    fn dismiss_splash(&mut self) {
        if !self.show_splash {
            return;
        }
        self.show_splash = false;
        self.log_lines
            .push("Welcome dismissed. Start with setup, or press ? for controls.".to_string());
        if self.log_lines.len() > 6 {
            self.log_lines.remove(0);
        }
    }

    #[cfg(test)]
    pub(crate) fn help_is_visible(&self) -> bool {
        self.show_help
    }

    fn refresh_doctor(&mut self) {
        self.doctor_text = render_host_doctor_from_probe_with_config(
            warder_daemon::probe_current_host(),
            self.options.config.clone(),
        )
        .unwrap_or_else(|error| format!("doctor check failed: {}", error.message));
    }

    fn current_workflow(&self) -> TuiWorkflow {
        self.workflows[self.workflow_index]
    }

    fn current_profile(&self) -> TuiProfile {
        self.profiles[self.profile_index]
    }

    fn config_display_path(&self) -> String {
        self.options
            .config
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| {
                default_setup_output(self.current_profile().agent)
                    .display()
                    .to_string()
            })
    }

    fn db_display_path(&self) -> String {
        self.options
            .db
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<default warder db>".to_string())
    }

    fn primary_command_for_current_workflow(&self) -> String {
        let profile = self.current_profile();
        match self.current_workflow() {
            TuiWorkflow::Setup => format!(
                "warder setup {} --workspace . --protect-secrets --output {}",
                profile.setup_command,
                default_setup_output(profile.agent).display()
            ),
            TuiWorkflow::Doctor => format!("warder doctor --config {}", self.config_display_path()),
            TuiWorkflow::DryRun => format!(
                "warder dry-run --config {} --agent {} -- {}",
                self.config_display_path(),
                setup_agent_profile_id(profile.agent),
                setup_agent_command_name(profile.agent)
            ),
            TuiWorkflow::Launch => format!(
                "warder {} --config {} -- <agent args>",
                profile.setup_command,
                self.config_display_path()
            ),
            TuiWorkflow::Receipts => format!(
                "warder receipt --db {} --session <id>",
                self.db_display_path()
            ),
        }
    }
}

#[cfg(test)]
const SPLASH_TEXT: &str = "Warder\n\
Run local AI agents with protected paths, receipts, and recovery.\n\
Warder only supervises Warder-launched sessions.\n\
Starts with Codex CLI, Claude Code, and OpenClaw.\n\
Press any key to continue. Press q to quit.";

impl TuiWorkflow {
    fn title(self) -> &'static str {
        match self {
            TuiWorkflow::Setup => "Setup",
            TuiWorkflow::Doctor => "Doctor",
            TuiWorkflow::DryRun => "Dry run",
            TuiWorkflow::Launch => "Launch",
            TuiWorkflow::Receipts => "Receipts",
        }
    }

    fn summary(self) -> &'static str {
        match self {
            TuiWorkflow::Setup => "Pick a known agent and generate a starter policy.",
            TuiWorkflow::Doctor => "Review host support, degraded coverage, and config warnings.",
            TuiWorkflow::DryRun => "Check the planned session before launching an agent.",
            TuiWorkflow::Launch => "Run through the existing guarded Warder launch path.",
            TuiWorkflow::Receipts => "Review receipts, verify integrity, and inspect journals.",
        }
    }
}

fn draw_dashboard(frame: &mut Frame<'_>, dashboard: &TuiDashboard) {
    if dashboard.splash_is_visible() {
        draw_splash(frame);
        return;
    }

    let page = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(7),
        ])
        .split(frame.area());

    draw_top_bar(frame, page[0], dashboard);
    draw_main_columns(frame, page[1], dashboard);
    draw_log_panel(frame, page[2], dashboard);
    if dashboard.show_help {
        draw_help_popup(frame);
    }
}

fn draw_splash(frame: &mut Frame<'_>) {
    let frame_area = frame.area();
    let splash_width = if frame_area.width < 96 { 92 } else { 68 };
    let splash_height = if frame_area.height < 28 { 78 } else { 58 };
    let area = centered_rect(splash_width, splash_height, frame_area);
    frame.render_widget(Clear, area);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Warder",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Run local AI agents with protected paths, receipts, and recovery.",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from("Codex CLI  |  Claude Code  |  OpenClaw"),
        Line::from(""),
        Line::from(Span::styled(
            "Warder only supervises Warder-launched sessions.",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Use the dashboard to setup a profile, check doctor, dry-run, launch, and review receipts."),
        Line::from(""),
        Line::from(Span::styled(
            "Press any key to continue. Press q to quit.",
            Style::default().fg(Color::Green),
        )),
    ];

    frame.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .title("Welcome")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_top_bar(frame: &mut Frame<'_>, area: Rect, dashboard: &TuiDashboard) {
    let top_line = Line::from(vec![
        Span::styled(
            "Warder",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::raw("supervised-session dashboard"),
        Span::raw("  |  "),
        Span::raw(format!(
            "profile: {}",
            setup_agent_label(dashboard.current_profile().agent)
        )),
        Span::raw("  |  ? help  q quit"),
    ]);
    frame.render_widget(
        Paragraph::new(top_line)
            .alignment(Alignment::Left)
            .block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_main_columns(frame: &mut Frame<'_>, area: Rect, dashboard: &TuiDashboard) {
    if area.width >= 112 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(24),
                Constraint::Min(48),
                Constraint::Length(30),
            ])
            .split(area);
        draw_workflows(frame, columns[0], dashboard);
        draw_overview(frame, columns[1], dashboard);
        draw_profiles(frame, columns[2], dashboard);
    } else {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(22), Constraint::Min(30)])
            .split(area);
        draw_workflows(frame, columns[0], dashboard);
        draw_overview(frame, columns[1], dashboard);
    }
}

fn draw_workflows(frame: &mut Frame<'_>, area: Rect, dashboard: &TuiDashboard) {
    let items = dashboard
        .workflows
        .iter()
        .enumerate()
        .map(|(index, workflow)| {
            let style = if index == dashboard.workflow_index {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(format!("{} - {}", index + 1, workflow.title())).style(style)
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(Block::default().title("Flow").borders(Borders::ALL)),
        area,
    );
}

fn draw_overview(frame: &mut Frame<'_>, area: Rect, dashboard: &TuiDashboard) {
    let text = format!(
        "{}\n\n{}",
        dashboard.current_workflow().summary(),
        dashboard.overview_text()
    );
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(dashboard.workflow_title())
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_profiles(frame: &mut Frame<'_>, area: Rect, dashboard: &TuiDashboard) {
    let items = dashboard
        .profiles
        .iter()
        .enumerate()
        .map(|(index, profile)| {
            let style = if index == dashboard.profile_index {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(vec![
                Line::from(setup_agent_label(profile.agent)),
                Line::from(format!(
                    "command: {}",
                    setup_agent_command_name(profile.agent)
                )),
                Line::from(format!(
                    "profile: {}",
                    setup_agent_profile_id(profile.agent)
                )),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(Block::default().title("Agent").borders(Borders::ALL)),
        area,
    );
}

fn draw_log_panel(frame: &mut Frame<'_>, area: Rect, dashboard: &TuiDashboard) {
    let body = if dashboard.show_help {
        "Help is open. Press ? again to close."
    } else {
        "Keys: up/down or j/k flow, tab profile, enter show next command, r refresh doctor, ? help, q quit"
    };
    let mut lines = dashboard
        .log_lines
        .iter()
        .cloned()
        .map(Line::from)
        .collect::<Vec<_>>();
    lines.push(Line::from(""));
    lines.push(Line::from(body));
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title("Status").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_help_popup(frame: &mut Frame<'_>) {
    let area = centered_rect(70, 52, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(
            "Warder TUI\n\n\
             This dashboard is an interactive front door to the existing safe CLI flows.\n\n\
             up/down or j/k: move through setup, doctor, dry-run, launch, receipts\n\
             tab / shift-tab: switch agent profile\n\
             r: refresh host doctor output\n\
             enter: print the next recommended command in the status panel\n\
             q: quit\n\n\
             Launches still use Warder's existing guarded command path. Direct launches outside Warder are unsupervised.",
        )
        .block(Block::default().title("Help").borders(Borders::ALL))
        .wrap(Wrap { trim: false }),
        area,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn input_from_key(key: KeyEvent) -> Option<TuiInput> {
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => Some(TuiInput::NextWorkflow),
        KeyCode::Up | KeyCode::Char('k') => Some(TuiInput::PreviousWorkflow),
        KeyCode::Tab => Some(TuiInput::NextProfile),
        KeyCode::BackTab => Some(TuiInput::PreviousProfile),
        KeyCode::Char('?') => Some(TuiInput::ToggleHelp),
        KeyCode::Char('r') => Some(TuiInput::Refresh),
        KeyCode::Enter => Some(TuiInput::Activate),
        _ => None,
    }
}

fn should_quit(key: KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
        || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c'))
}

fn next_index(current: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else {
        (current + 1) % len
    }
}

fn previous_index(current: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else if current == 0 {
        len - 1
    } else {
        current - 1
    }
}

fn tui_error(context: &str, error: io::Error) -> CliError {
    CliError {
        message: format!("failed to {context}: {error}"),
    }
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}
