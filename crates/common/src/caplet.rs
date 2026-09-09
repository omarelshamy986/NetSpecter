//! Caplet scripting engine — bettercap-style attack automation.
//!
//! A *caplet* is a small text file of commands, one per line, executed
//! top-to-bottom against the scheduler / attack modules. Caplets let an
//! operator codify a repeatable engagement flow:
//!
//! ```text
//! # recon-first.cap — auto-attack the loudest networks
//! set scan.duration 30
//! set scan.band 2.4
//! run scan
//!
//! set attack.timeout 60
//! set attack.workers 4
//! run attack-all
//!
//! set crack.wordlist /usr/share/wordlists/rockyou.txt
//! run crack-queue
//!
//! set report.output /tmp/engagement-42
//! run report
//! ```
//!
//! ## Grammar
//!
//! ```text
//! line        := comment | blank | command
//! comment     := '#' rest-of-line
//! blank       := whitespace-only
//! command     := 'set' key value | 'run' action | 'sleep' seconds
//! set         := variable binding (persisted across the caplet)
//! run         := execute a named action
//! sleep       := pause between steps
//! ```
//!
//! ## Variable interpolation
//!
//! `set` variables are referenced in later lines as `{name}`:
//!
//! ```text
//! set target aa:bb:cc:dd:ee:ff
//! run pmkid {target}
//! ```
//!
//! ## Error model
//!
//! A caplet stops on the first failing `run` action unless the line is
//! suffixed with `|| continue` (borrowing shell semantics). `set` /
//! `sleep` never abort. Parse errors abort before execution starts.
//!
//! ## What this module does NOT do
//!
//! It is not a general scripting language — no loops, no conditionals,
//! no user-defined functions. Those belong in the GUI or an external
//! orchestrator. Caplets are deliberately linear: predictable,
//! auditable, and easy to review before running.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// One parsed caplet line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapletLine {
    /// `set key value`
    Set { key: String, value: String },
    /// `run action args...` — `continue_on_error` mirrors `|| continue`.
    Run {
        action: String,
        args: Vec<String>,
        continue_on_error: bool,
    },
    /// `sleep seconds`
    Sleep { secs: u64 },
    /// `# comment` (kept for round-trip rendering).
    Comment { text: String },
}

/// Parse a caplet's text into lines. Returns errors with line numbers
/// so the operator can fix the file before execution.
pub fn parse_caplet(text: &str) -> Result<Vec<CapletLine>, Vec<String>> {
    let mut out = Vec::new();
    let mut errors = Vec::new();

    for (i, raw) in text.lines().enumerate() {
        let lineno = i + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            out.push(CapletLine::Comment {
                text: comment.trim().to_string(),
            });
            continue;
        }

        // `|| continue` suffix (shell semantics; check before tokenizing
        // so the '||' isn't mistaken for an argument).
        let (line, continue_on_error) = match line.strip_suffix("|| continue") {
            Some(head) => (head.trim_end(), true),
            None => (line, false),
        };

        let mut tokens = line.split_whitespace();
        let verb = tokens.next().unwrap_or("");
        match verb {
            "set" => {
                let key = match tokens.next() {
                    Some(k) => k.to_string(),
                    None => {
                        errors.push(format!("line {lineno}: 'set' requires a key"));
                        continue;
                    }
                };
                let value = tokens.collect::<Vec<_>>().join(" ");
                if value.is_empty() {
                    errors.push(format!("line {lineno}: 'set {key}' requires a value"));
                    continue;
                }
                out.push(CapletLine::Set { key, value });
            }
            "run" => {
                let action = match tokens.next() {
                    Some(a) => a.to_string(),
                    None => {
                        errors.push(format!("line {lineno}: 'run' requires an action"));
                        continue;
                    }
                };
                let args: Vec<String> = tokens.map(String::from).collect();
                out.push(CapletLine::Run {
                    action,
                    args,
                    continue_on_error,
                });
            }
            "sleep" => {
                match tokens.next().and_then(|s| s.parse::<u64>().ok()) {
                    Some(secs) => out.push(CapletLine::Sleep { secs }),
                    None => errors.push(format!(
                        "line {lineno}: 'sleep' requires an integer seconds value"
                    )),
                }
            }
            other => {
                errors.push(format!(
                    "line {lineno}: unknown verb '{other}' (expected set/run/sleep)"
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// Interpolate `{name}` references from the variable table.
///
/// Unknown references are left as-is (visible in logs rather than
/// silently replaced by an empty string).
pub fn interpolate(text: &str, vars: &HashMap<String, String>) -> String {
    let mut out = text.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

/// Actions a caplet's `run` verb can invoke, dispatched by name.
///
/// The executor receives the interpolated args and returns Ok/Err with
/// a human-readable message. The actual attack work happens through
/// the same modules the GUI drives; the caplet layer is pure control
/// flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KnownAction {
    Scan,
    AttackAll,
    Pmkid,
    WpsPixie,
    Deauth,
    HiddenRecovery,
    Karma,
    CrackQueue,
    Report,
}

impl KnownAction {
    pub fn from_name(name: &str) -> Option<KnownAction> {
        match name {
            "scan" => Some(KnownAction::Scan),
            "attack-all" => Some(KnownAction::AttackAll),
            "pmkid" => Some(KnownAction::Pmkid),
            "wps-pixie" => Some(KnownAction::WpsPixie),
            "deauth" => Some(KnownAction::Deauth),
            "hidden-recovery" => Some(KnownAction::HiddenRecovery),
            "karma" => Some(KnownAction::Karma),
            "crack-queue" => Some(KnownAction::CrackQueue),
            "report" => Some(KnownAction::Report),
            _ => None,
        }
    }
}

/// Executor result for a single `run` action.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionResult {
    pub action: String,
    pub ok: bool,
    pub message: String,
    /// Wall-clock duration of the action in seconds.
    pub duration_secs: u64,
}

/// Execution report for a whole caplet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapletReport {
    pub total_lines: usize,
    pub executed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub results: Vec<ActionResult>,
    /// Variables as they stood at the end of the run.
    pub final_vars: HashMap<String, String>,
}

/// Execute a parsed caplet.
///
/// `run_action` receives the action name and interpolated args and
/// performs the work. `Sleep` lines honor `sleep_fn` (tests inject a
/// no-op); `Set` lines mutate the variable table (visible to later
/// interpolation and included in the report).
pub fn execute_caplet<F, S>(
    lines: &[CapletLine],
    mut run_action: F,
    mut sleep_fn: S,
) -> CapletReport
where
    F: FnMut(&str, &[String]) -> Result<String, String>,
    S: FnMut(u64),
{
    let mut vars: HashMap<String, String> = HashMap::new();
    let mut report = CapletReport {
        total_lines: lines.len(),
        executed: 0,
        failed: 0,
        skipped: 0,
        results: Vec::new(),
        final_vars: HashMap::new(),
    };

    for line in lines {
        match line {
            CapletLine::Comment { .. } => { /* no-op */ }
            CapletLine::Set { key, value } => {
                vars.insert(key.clone(), interpolate(value, &vars));
                report.executed += 1;
            }
            CapletLine::Sleep { secs } => {
                sleep_fn(*secs);
                report.executed += 1;
            }
            CapletLine::Run {
                action,
                args,
                continue_on_error,
            } => {
                let interp_args: Vec<String> =
                    args.iter().map(|a| interpolate(a, &vars)).collect();
                let started = std::time::Instant::now();
                let outcome = run_action(action, &interp_args);
                let duration = started.elapsed().as_secs();
                report.executed += 1;
                match outcome {
                    Ok(msg) => report.results.push(ActionResult {
                        action: action.clone(),
                        ok: true,
                        message: msg,
                        duration_secs: duration,
                    }),
                    Err(msg) => {
                        report.failed += 1;
                        report.results.push(ActionResult {
                            action: action.clone(),
                            ok: false,
                            message: msg,
                            duration_secs: duration,
                        });
                        if !*continue_on_error {
                            // Count the remainder as skipped and stop.
                            let remaining = lines
                                .iter()
                                .skip(
                                    // approximate: lines consumed so far
                                    report.executed + report.skipped,
                                )
                                .count();
                            report.skipped += remaining;
                            report.final_vars = vars;
                            return report;
                        }
                    }
                }
            }
        }
    }

    report.final_vars = vars;
    report
}

/// Load a caplet from disk (parse + return lines).
pub fn load_caplet(path: &Path) -> Result<Vec<CapletLine>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read caplet {}: {e}", path.display()))?;
    parse_caplet(&text).map_err(|errs| errs.join("; "))
}

/// Render parsed lines back to caplet text (round-trip for editors).
pub fn render_caplet(lines: &[CapletLine]) -> String {
    let mut out = String::new();
    for line in lines {
        match line {
            CapletLine::Comment { text } => out.push_str(&format!("# {text}\n")),
            CapletLine::Set { key, value } => out.push_str(&format!("set {key} {value}\n")),
            CapletLine::Run {
                action,
                args,
                continue_on_error,
            } => {
                out.push_str(&format!("run {action} {}", args.join(" ")));
                if *continue_on_error {
                    out.push_str(" || continue");
                }
                out.push('\n');
            }
            CapletLine::Sleep { secs } => out.push_str(&format!("sleep {secs}\n")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn parse_simple_caplet() {
        let text = "\
# comment line
set scan.duration 30
run scan
sleep 5
run attack-all
";
        let lines = parse_caplet(text).unwrap();
        assert_eq!(lines.len(), 5);
        assert!(matches!(&lines[0], CapletLine::Comment { .. }));
        assert!(matches!(
            &lines[1],
            CapletLine::Set { key, value } if key == "scan.duration" && value == "30"
        ));
        assert!(matches!(
            &lines[2],
            CapletLine::Run { action, args, .. } if action == "scan" && args.is_empty()
        ));
        assert!(matches!(&lines[3], CapletLine::Sleep { secs } if *secs == 5));
    }

    #[test]
    fn parse_set_with_multiword_value() {
        let lines = parse_caplet("set report.output /tmp/my engagement dir").unwrap();
        match &lines[0] {
            CapletLine::Set { key, value } => {
                assert_eq!(key, "report.output");
                assert_eq!(value, "/tmp/my engagement dir");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_run_with_args_and_continue_suffix() {
        let lines = parse_caplet("run pmkid aa:bb:cc:dd:ee:ff || continue").unwrap();
        match &lines[0] {
            CapletLine::Run {
                action,
                args,
                continue_on_error,
            } => {
                assert_eq!(action, "pmkid");
                assert_eq!(args, &vec!["aa:bb:cc:dd:ee:ff".to_string()]);
                assert!(*continue_on_error);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_errors_carry_line_numbers() {
        let text = "set key\nbogus-verb x\nrun\nsleep abc";
        let errs = parse_caplet(text).unwrap_err();
        assert_eq!(errs.len(), 4);
        assert!(errs[0].starts_with("line 1:"));
        assert!(errs[1].starts_with("line 2:"));
        assert!(errs[2].starts_with("line 3:"));
        assert!(errs[3].starts_with("line 4:"));
    }

    #[test]
    fn interpolate_replaces_known_vars() {
        let mut vars = HashMap::new();
        vars.insert("target".to_string(), "aa:bb:cc:dd:ee:ff".to_string());
        assert_eq!(
            interpolate("run pmkid {target}", &vars),
            "run pmkid aa:bb:cc:dd:ee:ff"
        );
    }

    #[test]
    fn interpolate_leaves_unknown_refs() {
        let vars = HashMap::new();
        assert_eq!(interpolate("run pmkid {unknown}", &vars), "run pmkid {unknown}");
    }

    #[test]
    fn execute_runs_set_then_interpolated_run() {
        let lines = parse_caplet(
            "set target aa:bb:cc:dd:ee:ff\nrun pmkid {target}\nrun report",
        )
        .unwrap();
        let calls = AtomicU32::new(0);
        let report = execute_caplet(
            &lines,
            |action, args| {
                calls.fetch_add(1, Ordering::SeqCst);
                match action {
                    "pmkid" => {
                        assert_eq!(args, &["aa:bb:cc:dd:ee:ff".to_string()]);
                        Ok("captured".into())
                    }
                    "report" => Ok("written".into()),
                    other => Err(format!("unexpected action {other}")),
                }
            },
            |_| {},
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(report.executed, 3); // set + 2 runs
        assert_eq!(report.failed, 0);
        assert_eq!(report.final_vars.get("target").map(String::as_str), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn execute_stops_on_first_failure_without_continue() {
        let lines = parse_caplet("run pmkid x\nrun deauth y").unwrap();
        let report = execute_caplet(
            &lines,
            |action, _| match action {
                "pmkid" => Err("timeout".into()),
                _ => Ok("ok".into()),
            },
            |_| {},
        );
        assert_eq!(report.failed, 1);
        assert_eq!(report.skipped, 1);
        // Only one result recorded (the failing one).
        assert_eq!(report.results.len(), 1);
        assert!(!report.results[0].ok);
    }

    #[test]
    fn execute_continues_past_failure_with_continue_flag() {
        let lines = parse_caplet("run pmkid x || continue\nrun deauth y").unwrap();
        let report = execute_caplet(
            &lines,
            |action, _| match action {
                "pmkid" => Err("timeout".into()),
                _ => Ok("ok".into()),
            },
            |_| {},
        );
        assert_eq!(report.failed, 1);
        assert_eq!(report.results.len(), 2);
        assert!(report.results[1].ok);
    }

    #[test]
    fn execute_sleep_invokes_sleep_fn() {
        let lines = parse_caplet("sleep 3\nsleep 7").unwrap();
        let total = AtomicU32::new(0);
        execute_caplet(
            &lines,
            |_, _| Ok(String::new()),
            |secs| {
                total.fetch_add(secs as u32, Ordering::SeqCst);
            },
        );
        assert_eq!(total.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn execute_set_visible_to_later_set() {
        // A set value can reference a previous variable.
        let lines = parse_caplet("set a 5\nset b {a}0").unwrap();
        let report = execute_caplet(&lines, |_, _| Ok(String::new()), |_| {});
        assert_eq!(report.final_vars.get("b").map(String::as_str), Some("50"));
    }

    #[test]
    fn render_round_trips_through_parse() {
        let text = "# header\nset x 1\nrun scan\nsleep 2\nrun pmkid aa || continue\n";
        let lines = parse_caplet(text).unwrap();
        let rendered = render_caplet(&lines);
        let reparsed = parse_caplet(&rendered).unwrap();
        assert_eq!(lines, reparsed);
    }

    #[test]
    fn known_action_names_resolve() {
        assert_eq!(KnownAction::from_name("scan"), Some(KnownAction::Scan));
        assert_eq!(KnownAction::from_name("attack-all"), Some(KnownAction::AttackAll));
        assert_eq!(KnownAction::from_name("wps-pixie"), Some(KnownAction::WpsPixie));
        assert_eq!(KnownAction::from_name("nope"), None);
    }

    #[test]
    fn load_caplet_rejects_missing_file() {
        assert!(load_caplet(Path::new("/nonexistent.cap")).is_err());
    }

    #[test]
    fn load_caplet_rejects_syntax_errors() {
        let dir = std::env::temp_dir().join(format!(
            "cap-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bad.cap");
        std::fs::write(&p, "bogus-verb\n").unwrap();
        let err = load_caplet(&p).unwrap_err();
        assert!(err.contains("unknown verb"));
    }
}