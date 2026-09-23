//! Typed progress events for human-facing verification transcripts.
//!
//! Events describe work as it happens. They never determine whether a run
//! passes: the completed [`crate::outcome::Assessment`] remains the only input
//! to verdict selection and the verification record.

use std::io::{self, Write};

const SUBJECT_LIMIT: usize = 96;
const VALUE_LIMIT: usize = 384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Inputs,
    Statement,
    ReceiptKeys,
    ArtifactBinding,
    Policy,
    Evidence,
    Adapter,
    Summary,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Inputs => "Read inputs",
            Self::Statement => "Verify transparent statement",
            Self::ReceiptKeys => "Acquire receipt verification keys",
            Self::ArtifactBinding => "Check artifact binding",
            Self::Policy => "Evaluate relying-party policy",
            Self::Evidence => "Collect resource evidence",
            Self::Adapter => "Appraise node evidence",
            Self::Summary => "Assessment summary",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Started,
    Done,
    Pass,
    Fail,
    CannotEvaluate,
    NotRun,
    NotChecked,
    Notice,
}

impl State {
    fn label(self) -> &'static str {
        match self {
            Self::Started => "START",
            Self::Done => "DONE",
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::CannotEvaluate => "CANNOT EVALUATE",
            Self::NotRun => "NOT RUN",
            Self::NotChecked => "NOT CHECKED",
            Self::Notice => "NOTICE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub stage: Stage,
    pub check: Option<String>,
    pub subject: Option<String>,
    pub compact_subject: Option<String>,
    pub state: State,
    pub message: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
    pub presentation: Presentation,
}

/// Presentation hints come from the owner of a check, not a renderer's list
/// of domain-specific check identifiers. Unknown findings default to visible.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Presentation {
    #[default]
    Normal,
    Detail,
    FinalLimitation,
    Brief(String),
    Context(String),
    #[cfg_attr(not(feature = "adapter-mst-ledger"), allow(dead_code))]
    Checklist {
        checks: Vec<String>,
        columns: Vec<String>,
        subject_width: usize,
    },
    #[cfg_attr(not(feature = "adapter-mst-ledger"), allow(dead_code))]
    Row(Vec<State>),
}

impl Event {
    pub fn detail(mut self) -> Self {
        self.presentation = Presentation::Detail;
        self
    }

    pub fn brief(mut self, message: impl Into<String>) -> Self {
        self.presentation = Presentation::Brief(message.into());
        self
    }

    #[cfg_attr(not(feature = "adapter-mst-ledger"), allow(dead_code))]
    pub fn subject_label(mut self, label: impl Into<String>) -> Self {
        self.compact_subject = Some(label.into());
        self
    }

    pub fn context(label: &str, value: impl Into<String>) -> Self {
        let mut event = Self::stage(Stage::Inputs, State::Done, value);
        event.presentation = Presentation::Context(label.into());
        event
    }

    pub fn stage(stage: Stage, state: State, message: impl Into<String>) -> Self {
        Self {
            stage,
            check: None,
            subject: None,
            compact_subject: None,
            state,
            message: message.into(),
            expected: None,
            observed: None,
            presentation: Presentation::Normal,
        }
    }

    pub fn finding(
        stage: Stage,
        check: impl Into<String>,
        subject: Option<String>,
        state: State,
        message: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            check: Some(check.into()),
            subject,
            compact_subject: None,
            state,
            message: message.into(),
            expected: None,
            observed: None,
            presentation: Presentation::Normal,
        }
    }

    #[cfg_attr(not(feature = "adapter-mst-ledger"), allow(dead_code))]
    pub fn finding_with_values(
        stage: Stage,
        check: impl Into<String>,
        subject: Option<String>,
        state: State,
        message: impl Into<String>,
        expected: Option<String>,
        observed: Option<String>,
    ) -> Self {
        Self {
            stage,
            check: Some(check.into()),
            subject,
            compact_subject: None,
            state,
            message: message.into(),
            expected,
            observed,
            presentation: Presentation::Normal,
        }
    }
}

pub trait Sink {
    fn emit(&mut self, event: Event);
}

pub struct Noop;

impl Sink for Noop {
    fn emit(&mut self, _event: Event) {}
}

pub struct Text<'a, W: Write> {
    out: &'a mut W,
    last_stage: Option<Stage>,
    last_group: Option<(Stage, String)>,
    color: bool,
    error: Option<io::Error>,
    plan: Option<Vec<(Stage, String)>>,
    visited: Vec<Stage>,
    subject_width: usize,
}

impl<'a, W: Write> Text<'a, W> {
    pub fn new(out: &'a mut W, color: bool) -> Self {
        Self {
            out,
            last_stage: None,
            last_group: None,
            color,
            error: None,
            plan: None,
            visited: Vec::new(),
            subject_width: 21,
        }
    }

    pub fn compact(out: &'a mut W, color: bool, plan: Vec<(Stage, String)>) -> Self {
        let mut sink = Self::new(out, color);
        sink.plan = Some(plan);
        sink
    }

    pub fn finish(mut self) -> io::Result<()> {
        if let Some(plan) = self.plan.clone() {
            for (stage, _) in plan {
                if !self.visited.contains(&stage) {
                    self.emit(Event::stage(
                        stage,
                        State::NotRun,
                        "Prerequisites did not complete",
                    ));
                }
            }
        }
        match self.error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn compact_event(&mut self, event: &Event) -> io::Result<()> {
        let success = matches!(event.state, State::Pass | State::Done | State::Started);
        if event.presentation == Presentation::Detail && success {
            return Ok(());
        }
        if event.presentation == Presentation::FinalLimitation
            && event.state == State::CannotEvaluate
        {
            return Ok(());
        }
        if let Presentation::Context(label) = &event.presentation {
            writeln!(
                self.out,
                "{} {}",
                safe_text(label, SUBJECT_LIMIT),
                safe_text(&event.message, VALUE_LIMIT)
            )?;
            return self.out.flush();
        }
        let stage = if event.stage == Stage::ReceiptKeys {
            Stage::Statement
        } else {
            event.stage
        };
        if !self.visited.contains(&stage) {
            let skipped: Vec<_> = self
                .plan
                .as_ref()
                .into_iter()
                .flatten()
                .take_while(|(candidate, _)| *candidate != stage)
                .filter(|(candidate, _)| !self.visited.contains(candidate))
                .map(|(candidate, _)| *candidate)
                .collect();
            for skipped in skipped {
                self.compact_event(&Event::stage(
                    skipped,
                    State::NotRun,
                    "Prerequisites did not complete",
                ))?;
            }
            if let Some((index, (_, label))) = self
                .plan
                .as_ref()
                .and_then(|plan| plan.iter().enumerate().find(|(_, (s, _))| *s == stage))
            {
                writeln!(
                    self.out,
                    "\n[{}/{}] {}",
                    index + 1,
                    self.plan.as_ref().unwrap().len(),
                    label
                )?;
            }
            self.visited.push(stage);
        }
        match &event.presentation {
            Presentation::Checklist {
                checks,
                columns,
                subject_width,
            } => {
                self.subject_width = (*subject_width).clamp(21, SUBJECT_LIMIT);
                writeln!(self.out, "  Checks applied to each node:")?;
                for line in checks {
                    writeln!(self.out, "    {}", safe_text(line, VALUE_LIMIT))?;
                }
                self.table_row(
                    "Node",
                    columns
                        .iter()
                        .map(|column| format!("{:<16}", safe_text(column, SUBJECT_LIMIT))),
                )?;
            }
            Presentation::Row(states) => {
                let color = self.color;
                self.table_row(
                    &event.message,
                    states.iter().map(|state| styled_token(*state, color, 16)),
                )?;
            }
            _ => {
                let brief = match &event.presentation {
                    Presentation::Brief(message) if success => Some(message.as_str()),
                    _ => None,
                };
                let message = safe_text(brief.unwrap_or(&event.message), VALUE_LIMIT);
                let state = if event.state == State::Started {
                    String::new()
                } else {
                    format!("{} ", styled_token(event.state, self.color, 0))
                };
                let check = if brief.is_none() {
                    event
                        .check
                        .as_ref()
                        .map(|v| format!("{} ", safe_text(v, SUBJECT_LIMIT)))
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let subject = if brief.is_some() {
                    String::new()
                } else {
                    event
                        .compact_subject
                        .as_ref()
                        .or(event.subject.as_ref())
                        .map(|v| format!("[{}] ", safe_text(v, SUBJECT_LIMIT)))
                        .unwrap_or_default()
                };
                writeln!(self.out, "  {state}{check}{subject}{message}")?;
                if !success {
                    for (label, value) in
                        [("Expected", &event.expected), ("Observed", &event.observed)]
                    {
                        if let Some(value) = value {
                            writeln!(self.out, "    {label}: {}", safe_text(value, VALUE_LIMIT))?;
                        }
                    }
                }
            }
        }
        // A buffered stdout must expose starts before the blocking work begins.
        self.out.flush()
    }

    fn table_row(
        &mut self,
        subject: &str,
        cells: impl IntoIterator<Item = String>,
    ) -> io::Result<()> {
        write!(
            self.out,
            "  {:<width$}",
            safe_text(subject, SUBJECT_LIMIT),
            width = self.subject_width
        )?;
        for cell in cells {
            write!(self.out, "  {cell}")?;
        }
        writeln!(self.out)
    }
}

impl<W: Write> Sink for Text<'_, W> {
    fn emit(&mut self, event: Event) {
        if self.error.is_some() {
            return;
        }
        if self.plan.is_some() {
            if let Err(error) = self.compact_event(&event) {
                self.error = Some(error);
            }
            return;
        }
        if matches!(event.presentation, Presentation::Row(_)) {
            return;
        }

        let result = (|| {
            if self.last_stage != Some(event.stage) {
                if self.last_stage.is_some() {
                    writeln!(self.out)?;
                }
                writeln!(self.out, "{}", event.stage.label())?;
                self.last_stage = Some(event.stage);
                self.last_group = None;
            }

            // Bounded and escaped like every other displayed value. Today's
            // check names are in-repo constants, but the field is filled from
            // an adapter's own vocabulary, and a displayed value that is safe
            // only because of who currently supplies it is an exception
            // waiting to be forgotten.
            let check = event
                .check
                .as_deref()
                .map(|value| format!(" {}", safe_text(value, SUBJECT_LIMIT)))
                .unwrap_or_default();
            let message = safe_text(&event.message, VALUE_LIMIT);
            let group = group_label(&event);
            let grouped = if let Some((kind, subject)) = group {
                let group_key = (event.stage, subject.to_string());
                if self.last_group.as_ref() != Some(&group_key) {
                    writeln!(self.out, "  {kind} {}", safe_text(subject, SUBJECT_LIMIT))?;
                    self.last_group = Some(group_key);
                }
                true
            } else {
                false
            };
            let subject = if grouped {
                String::new()
            } else {
                event
                    .subject
                    .as_deref()
                    .map(|value| format!(" [{}]", safe_text(value, SUBJECT_LIMIT)))
                    .unwrap_or_default()
            };
            let indent = if grouped { "    " } else { "  " };
            let state = styled_state(event.state, self.color);
            writeln!(self.out, "{indent}{state}{}{} {}", check, subject, message)?;
            let value_indent = if grouped {
                "                      "
            } else {
                "                  "
            };
            if let Some(expected) = &event.expected {
                writeln!(
                    self.out,
                    "{value_indent}Expected: {}",
                    safe_text(expected, VALUE_LIMIT)
                )?;
            }
            if let Some(observed) = &event.observed {
                writeln!(
                    self.out,
                    "{value_indent}Observed: {}",
                    safe_text(observed, VALUE_LIMIT)
                )?;
            }
            self.out.flush()
        })();

        if let Err(error) = result {
            self.error = Some(error);
        }
    }
}

fn group_label(event: &Event) -> Option<(&'static str, &str)> {
    let subject = event.subject.as_deref()?;
    match event.stage {
        Stage::Adapter => Some(("Node", subject)),
        Stage::ReceiptKeys => Some(("Ledger", subject)),
        Stage::Statement
            if matches!(
                event.check.as_deref(),
                Some(
                    "receipt-identity" | "receipt-key" | "registration-time" | "receipt-inclusion"
                )
            ) =>
        {
            Some(("Receipt", subject))
        }
        _ => None,
    }
}

fn styled_state(state: State, color: bool) -> String {
    styled_token(state, color, 15)
}

fn styled_token(state: State, color: bool, width: usize) -> String {
    let padded = format!("{:<width$}", state.label());
    if !color {
        return padded;
    }
    let code = match state {
        State::Pass | State::Done => "32",
        State::Fail => "1;31",
        State::CannotEvaluate | State::NotRun | State::NotChecked => "33",
        State::Notice => "36",
        State::Started => "34",
    };
    format!("\u{1b}[{code}m{padded}\u{1b}[0m")
}

pub(crate) fn safe_text(value: &str, limit: usize) -> String {
    let mut rendered = String::new();
    let mut rendered_len = 0;

    for character in value.chars() {
        let escaped = match character {
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            c if c.is_control() => format!("\\u{{{:x}}}", c as u32),
            c => c.to_string(),
        };
        let escaped_len = escaped.chars().count();
        if rendered_len + escaped_len > limit {
            rendered.push_str("...");
            break;
        }
        rendered.push_str(&escaped);
        rendered_len += escaped_len;
    }

    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_table_headers_and_rows_share_visible_column_positions() {
        for width in [21, 36] {
            for color in [false, true] {
                let mut bytes = Vec::new();
                let mut sink =
                    Text::compact(&mut bytes, color, vec![(Stage::Adapter, "Appraise".into())]);
                let mut header = Event::stage(Stage::Adapter, State::Started, "Checking nodes");
                header.presentation = Presentation::Checklist {
                    checks: vec!["Check each node".into()],
                    columns: vec![
                        "Service binding".into(),
                        "SNP / UVM".into(),
                        "Policy match".into(),
                    ],
                    subject_width: width,
                };
                sink.emit(header);
                for label in ["#1 5b84f348...", "#12 5b84f348abcdef0123456789..."] {
                    if label.len() > width {
                        continue;
                    }
                    let mut row = Event::stage(Stage::Adapter, State::Done, label);
                    row.presentation =
                        Presentation::Row(vec![State::Pass, State::Fail, State::CannotEvaluate]);
                    sink.emit(row);
                }
                sink.finish().unwrap();
                let text = String::from_utf8(bytes).unwrap();
                let plain = text
                    .replace("\u{1b}[32m", "")
                    .replace("\u{1b}[1;31m", "")
                    .replace("\u{1b}[33m", "")
                    .replace("\u{1b}[0m", "");
                let header = plain
                    .lines()
                    .find(|line| line.starts_with("  Node"))
                    .unwrap();
                for row in plain.lines().filter(|line| line.starts_with("  #")) {
                    for (title, state) in [
                        ("Service binding", "PASS"),
                        ("SNP / UVM", "FAIL"),
                        ("Policy match", "CANNOT EVALUATE"),
                    ] {
                        assert_eq!(header.find(title), row.find(state), "{plain}");
                    }
                    assert_eq!(row.find("PASS"), Some(2 + width + 2));
                }
            }
        }
    }

    #[test]
    fn compact_final_limitation_hint_never_hides_a_failure() {
        let mut event = Event::finding(
            Stage::Adapter,
            "freshness",
            None,
            State::Fail,
            "failure detail",
        );
        event.presentation = Presentation::FinalLimitation;
        let text = compact(vec![event.clone()]);
        assert!(text.contains("FAIL freshness failure detail"));
        event.state = State::CannotEvaluate;
        let mut bytes = Vec::new();
        let mut verbose = Text::new(&mut bytes, false);
        verbose.emit(event);
        verbose.finish().unwrap();
        assert!(String::from_utf8(bytes)
            .unwrap()
            .contains("CANNOT EVALUATE freshness failure detail"));
    }

    fn compact(events: Vec<Event>) -> String {
        let mut bytes = Vec::new();
        let mut sink = Text::compact(&mut bytes, false, vec![(Stage::Adapter, "Appraise".into())]);
        for event in events {
            sink.emit(event);
        }
        sink.finish().unwrap();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn compact_only_hides_explicitly_summarized_successes() {
        let success = Event::finding_with_values(
            Stage::Adapter,
            "known",
            Some("node".into()),
            State::Pass,
            "measurement full-hash",
            Some("same-hash".into()),
            Some("same-hash".into()),
        )
        .detail();
        let unknown = Event::finding(
            Stage::Adapter,
            "future-check",
            None,
            State::Pass,
            "new finding",
        );
        let mut events = vec![success.clone(), unknown];
        for state in [
            State::Fail,
            State::CannotEvaluate,
            State::NotRun,
            State::NotChecked,
            State::Notice,
        ] {
            let mut event = success.clone();
            event.state = state;
            events.push(event);
        }
        let text = compact(events);
        assert!(text.contains("PASS future-check new finding"));
        assert!(!text.contains("PASS known"));
        for state in [
            "FAIL",
            "CANNOT EVALUATE",
            "NOT RUN",
            "NOT CHECKED",
            "NOTICE",
        ] {
            assert!(
                text.contains(&format!("{state} known [node] measurement full-hash")),
                "{text}"
            );
        }
        assert_eq!(text.matches("Expected: same-hash").count(), 5);
        assert_eq!(text.matches("Observed: same-hash").count(), 5);
    }

    #[test]
    fn compact_context_and_exceptions_are_escaped_and_bounded() {
        let text = compact(vec![
            Event::context("Verifying", format!("bad\n\u{1b}[2J{}", "x".repeat(500))),
            Event::finding_with_values(
                Stage::Adapter,
                "check\nspoof",
                Some("full-id".into()),
                State::Fail,
                "mismatch\r\n",
                Some("expected\tvalue".into()),
                Some("observed".into()),
            )
            .subject_label("short\nid"),
        ]);
        assert!(text.contains("bad\\n\\u{1b}[2J"));
        assert!(text.contains("..."));
        assert!(text.contains("check\\nspoof [short\\nid] mismatch\\r\\n"));
        assert!(text.contains("Expected: expected\\tvalue"));
        assert!(text.contains("Observed: observed"));
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains("full-id"));
        assert!(text.lines().all(|line| line.len() < 410));
    }

    #[test]
    fn start_is_flushed_before_completion_and_skipped_stages_are_ordered() {
        use std::cell::RefCell;
        use std::rc::Rc;
        struct Observed(Rc<RefCell<Vec<u8>>>, Rc<RefCell<usize>>);
        impl Write for Observed {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                *self.1.borrow_mut() += 1;
                Ok(())
            }
        }
        let bytes = Rc::new(RefCell::new(Vec::new()));
        let flushes = Rc::new(RefCell::new(0));
        let mut out = Observed(bytes.clone(), flushes.clone());
        let mut sink = Text::compact(
            &mut out,
            false,
            vec![
                (Stage::Inputs, "Read inputs".into()),
                (Stage::Evidence, "Load evidence".into()),
                (Stage::Adapter, "Appraise".into()),
            ],
        );
        sink.emit(Event::stage(Stage::Inputs, State::Started, "Reading..."));
        assert!(*flushes.borrow() > 0);
        let before = String::from_utf8(bytes.borrow().clone()).unwrap();
        assert!(before.contains("Reading..."));
        assert!(!before.contains("DONE"));
        sink.emit(Event::stage(Stage::Inputs, State::Done, "Loaded"));
        sink.emit(Event::stage(Stage::Adapter, State::NotRun, "No evidence"));
        sink.finish().unwrap();
        let text = String::from_utf8(bytes.borrow().clone()).unwrap();
        assert!(text.find("[2/3]").unwrap() < text.find("[3/3]").unwrap());
        assert_eq!(text.matches("[2/3]").count(), 1);
        assert_eq!(text.matches("NOT RUN").count(), 2);
    }

    #[test]
    fn compact_sink_retains_output_errors() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut out = Broken;
        let mut sink = Text::compact(&mut out, false, Vec::new());
        sink.emit(Event::stage(Stage::Inputs, State::Started, "Reading"));
        assert_eq!(sink.finish().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn text_groups_findings_by_stage_without_making_order_a_contract() {
        let mut bytes = Vec::new();
        let mut sink = Text::new(&mut bytes, false);
        sink.emit(Event::stage(
            Stage::Inputs,
            State::Started,
            "statement.cose",
        ));
        sink.emit(Event::finding(
            Stage::Inputs,
            "policy",
            None,
            State::Done,
            "release-policy v1",
        ));
        sink.emit(Event::stage(
            Stage::Statement,
            State::Pass,
            "signature and receipt inclusion verified",
        ));
        sink.finish().unwrap();

        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Read inputs"));
        assert!(text.contains("DONE            policy release-policy v1"));
        assert!(text.contains("Verify transparent statement"));
        assert!(text.contains("PASS"));
    }

    #[test]
    fn structured_values_render_without_being_parsed_from_detail() {
        let mut bytes = Vec::new();
        let mut sink = Text::new(&mut bytes, false);
        sink.emit(Event::finding_with_values(
            Stage::Adapter,
            "cce-policy-host-data",
            Some("node-a".into()),
            State::Fail,
            "policy commitment differs",
            Some("expected".into()),
            Some("observed".into()),
        ));
        sink.finish().unwrap();

        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Expected: expected"));
        assert!(text.contains("Observed: observed"));
    }

    #[test]
    fn untrusted_values_cannot_inject_terminal_lines_or_controls() {
        let mut bytes = Vec::new();
        let mut sink = Text::new(&mut bytes, false);
        sink.emit(Event::finding_with_values(
            Stage::ReceiptKeys,
            "acquisition",
            Some("ledger\nspoof".into()),
            State::CannotEvaluate,
            "failed\r\nPASS forged\u{1b}[2J",
            Some("a\tb".into()),
            None,
        ));
        sink.finish().unwrap();

        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Ledger ledger\\nspoof"));
        assert!(text.contains("failed\\r\\nPASS forged\\u{1b}[2J"));
        assert!(text.contains("Expected: a\\tb"));
        assert!(!text.contains('\u{1b}'));
        assert_eq!(text.lines().count(), 4);
    }

    #[test]
    fn an_adapters_check_name_is_escaped_like_any_other_displayed_value() {
        let mut bytes = Vec::new();
        let mut sink = Text::new(&mut bytes, false);
        sink.emit(Event::finding(
            Stage::Adapter,
            "check\u{1b}[2J\nPASS forged",
            None,
            State::Fail,
            "detail",
        ));
        sink.finish().unwrap();

        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("check\\u{1b}[2J\\nPASS forged"));
        assert!(!text.contains('\u{1b}'));
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn untrusted_values_are_bounded() {
        let rendered = safe_text(&"x".repeat(VALUE_LIMIT + 1), VALUE_LIMIT);
        assert_eq!(rendered.len(), VALUE_LIMIT + 3);
        assert!(rendered.ends_with("..."));
    }

    #[test]
    fn adapter_findings_group_under_their_node() {
        let mut bytes = Vec::new();
        let mut sink = Text::new(&mut bytes, false);
        for check in ["identity", "policy"] {
            sink.emit(Event::finding(
                Stage::Adapter,
                check,
                Some("node-a".into()),
                State::Pass,
                "verified",
            ));
        }
        sink.finish().unwrap();

        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text.matches("Node node-a").count(), 1);
        assert!(text.contains("    PASS            identity verified"));
        assert!(text.contains("    PASS            policy verified"));
    }

    #[test]
    fn color_wraps_only_the_fixed_width_state_token() {
        let state = styled_state(State::Fail, true);
        assert!(state.starts_with("\u{1b}[1;31mFAIL"));
        assert!(state.ends_with("\u{1b}[0m"));
        assert_eq!(styled_state(State::Fail, false), "FAIL           ");
        assert_eq!(
            styled_token(State::Pass, true, 0),
            "\u{1b}[32mPASS\u{1b}[0m"
        );
    }
}
