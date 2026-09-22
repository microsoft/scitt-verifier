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
            Self::Adapter => "Appraise resource evidence",
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
    pub state: State,
    pub message: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
}

impl Event {
    pub fn stage(stage: Stage, state: State, message: impl Into<String>) -> Self {
        Self {
            stage,
            check: None,
            subject: None,
            state,
            message: message.into(),
            expected: None,
            observed: None,
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
            state,
            message: message.into(),
            expected: None,
            observed: None,
        }
    }

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
            state,
            message: message.into(),
            expected,
            observed,
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
}

impl<'a, W: Write> Text<'a, W> {
    pub fn new(out: &'a mut W, color: bool) -> Self {
        Self {
            out,
            last_stage: None,
            last_group: None,
            color,
            error: None,
        }
    }

    pub fn finish(self) -> io::Result<()> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl<W: Write> Sink for Text<'_, W> {
    fn emit(&mut self, event: Event) {
        if self.error.is_some() {
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
            Ok(())
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
    let padded = format!("{:<15}", state.label());
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

fn safe_text(value: &str, limit: usize) -> String {
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
    }
}
