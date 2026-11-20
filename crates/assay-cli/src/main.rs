//! Assay command-line interface.
//!
//! Exit codes are the contract with CI:
//!
//! | code | meaning |
//! |------|---------|
//! | 0    | clean or low risk |
//! | 1    | high risk |
//! | 2    | critical |
//! | 3    | usage error, I/O error, or partial analysis |
//!
//! The `--format` flag selects human text or machine JSON on every command that
//! produces a report. Machine output goes to stdout and nothing else does, so
//! `assay analyze x.exe --format json | jq` is always safe.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

use assay_core::analysis::score::Grade;
use assay_core::rules::RuleSet;
use assay_core::{analyze_bytes, analyze_path, AnalyzeOptions, Report};

/// Static supply-chain analysis: dissect a binary without running it.
#[derive(Parser, Debug)]
#[command(
    name = "assay",
    version,
    about = "Static supply-chain analysis for compiled artefacts",
    long_about = "Assay dissects PE, ELF, Mach-O, archive and script artefacts and reports \
                  structure, capability, indicators and a decomposed risk score — entirely \
                  offline, without executing the sample.\n\n\
                  Exit codes: 0 clean/low, 1 high, 2 critical, 3 error.",
    after_help = "Examples:\n  \
                  assay analyze sample.exe\n  \
                  assay analyze sample.exe --format json --rules corp.json\n  \
                  assay batch ./samples --threshold high\n  \
                  assay sbom app.exe -o bom.json\n  \
                  assay rules validate my-rules.json\n  \
                  assay diff old.exe new.exe"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Suppress progress output on stderr.
    #[arg(long, global = true)]
    quiet: bool,

    /// Force colour output on or off.
    #[arg(long, global = true, value_name = "WHEN", default_value = "auto")]
    color: ColorChoice,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Analyse one artefact and print a report.
    Analyze(AnalyzeArgs),
    /// Analyse every file in a directory (recursively by default).
    Batch(BatchArgs),
    /// Emit a CycloneDX SBOM for an artefact.
    Sbom(SbomArgs),
    /// Inspect or validate rule files.
    Rules(RulesArgs),
    /// Compare two artefacts structurally.
    Diff(DiffArgs),
    /// Show the parsed structure without scoring.
    Parse(ParseArgs),
    /// Print the built-in rule set so it can be used as a template.
    DumpRules,
}

#[derive(Args, Debug)]
struct AnalyzeArgs {
    /// File to analyse.
    #[arg(value_name = "FILE")]
    path: PathBuf,

    /// Output format.
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Write the report to a file instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Additional rule file (JSON). Replaces the built-in set when given.
    #[arg(long, value_name = "FILE")]
    rules: Option<PathBuf>,

    /// Use a deeper analysis profile (lower string threshold, finer entropy).
    #[arg(long, conflicts_with = "fast")]
    deep: bool,

    /// Use a faster, shallower profile.
    #[arg(long)]
    fast: bool,

    /// Exit non-zero when the score reaches this grade.
    #[arg(long, value_enum, default_value = "high")]
    fail_on: FailThreshold,
}

#[derive(Args, Debug)]
struct BatchArgs {
    /// Directory to scan, or a file to scan alone.
    #[arg(value_name = "PATH")]
    path: PathBuf,

    /// Output format for the aggregate report.
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Write the aggregate report to a file.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Do not descend into subdirectories.
    #[arg(long)]
    no_recursive: bool,

    /// Skip files larger than this many mebibytes.
    #[arg(long, value_name = "MB", default_value_t = 512)]
    max_size_mb: u64,

    /// Additional rule file (JSON).
    #[arg(long, value_name = "FILE")]
    rules: Option<PathBuf>,

    /// Exit non-zero when any file reaches this grade.
    #[arg(long, value_enum, default_value = "high")]
    threshold: FailThreshold,
}

#[derive(Args, Debug)]
struct SbomArgs {
    /// File to describe.
    #[arg(value_name = "FILE")]
    path: PathBuf,

    /// Write the BOM here instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct RulesArgs {
    #[command(subcommand)]
    action: RulesAction,
}

#[derive(Subcommand, Debug)]
enum RulesAction {
    /// Validate a rule file and print a summary.
    Validate {
        /// Rule file to check.
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },
    /// List the built-in rules.
    List,
}

#[derive(Args, Debug)]
struct DiffArgs {
    /// Baseline artefact.
    #[arg(value_name = "OLD")]
    old: PathBuf,
    /// Artefact to compare against the baseline.
    #[arg(value_name = "NEW")]
    new: PathBuf,
    /// Output format.
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,
}

#[derive(Args, Debug)]
struct ParseArgs {
    /// File to parse.
    #[arg(value_name = "FILE")]
    path: PathBuf,
    /// Output format.
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "lower")]
enum FailThreshold {
    Never,
    Critical,
    High,
    Medium,
    Low,
}

impl FailThreshold {
    fn breached(self, grade: Grade) -> bool {
        match self {
            FailThreshold::Never => false,
            FailThreshold::Critical => grade >= Grade::Critical,
            FailThreshold::High => grade >= Grade::High,
            FailThreshold::Medium => grade >= Grade::Medium,
            FailThreshold::Low => grade >= Grade::Low,
        }
    }
}

fn main() -> ExitCode {
    // `Cli::parse` would exit the process with clap's default code 2 on a usage
    // error, which collides with this tool's "critical risk" verdict. A CI job
    // that mistyped a subcommand would then read the failure as a critical
    // finding. Usage errors are code 3, like every other setup failure.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // `--help` and `--version` arrive through the same channel and are
            // successful output, not errors. A bare invocation is *not* in that
            // group: clap sends it to stderr precisely because a required
            // subcommand is missing, and reporting success for a run that did
            // nothing would let `assay && deploy` proceed on no analysis at all.
            let _ = error.print();
            return ExitCode::from(match error.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => 0,
                _ => 3,
            });
        }
    };
    let colour = should_colour(cli.color);
    let quiet = cli.quiet;

    match run(cli.command, quiet, colour) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("assay: {message}");
            ExitCode::from(3)
        }
    }
}

/// Decide whether to emit ANSI escapes.
///
/// `auto` means "when the output is a terminal", not "always". Getting this
/// wrong is not cosmetic: `assay batch > report.txt` wrote escape sequences into
/// the file, so anything parsing the text output — a spreadsheet import, a grep,
/// a log shipper — saw `\x1b[31mhigh\x1b[0m  55` where it expected `high  55`.
///
/// `NO_COLOR` is honoured because it is the de facto standard for exactly this,
/// and a script that already sets it should not have to also pass `--color never`
/// to every invocation.
fn should_colour(choice: ColorChoice) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
        }
    }
}

fn run(command: Command, quiet: bool, colour: bool) -> Result<u8, String> {
    match command {
        Command::Analyze(args) => cmd_analyze(args, quiet, colour),
        Command::Batch(args) => cmd_batch(args, quiet, colour),
        Command::Sbom(args) => cmd_sbom(args),
        Command::Rules(args) => cmd_rules(args, quiet),
        Command::Diff(args) => cmd_diff(args, colour),
        Command::Parse(args) => cmd_parse(args),
        Command::DumpRules => {
            println!("{}", assay_core::rules::BUILTIN_RULES_JSON);
            Ok(0)
        }
    }
}

fn options_from(
    deep: bool,
    fast: bool,
    rules_path: Option<&Path>,
) -> Result<AnalyzeOptions, String> {
    let mut options = if deep {
        AnalyzeOptions::deep()
    } else if fast {
        AnalyzeOptions::fast()
    } else {
        AnalyzeOptions::default()
    };

    if let Some(path) = rules_path {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read rules from {}: {e}", path.display()))?;
        let set = RuleSet::from_json(&text)
            .map_err(|e| format!("rules in {} are invalid: {e}", path.display()))?;
        let dups = set.duplicate_ids();
        if !dups.is_empty() {
            return Err(format!("duplicate rule ids: {}", dups.join(", ")));
        }
        options.rules = Some(set);
    }
    Ok(options)
}

fn cmd_analyze(args: AnalyzeArgs, quiet: bool, colour: bool) -> Result<u8, String> {
    let options = options_from(args.deep, args.fast, args.rules.as_deref())?;
    if !quiet {
        eprintln!("analysing {}", args.path.display());
    }
    // The Io variant already names the path; prefixing it again produced
    // "samples: cannot read samples: ...".
    let report = analyze_path(&args.path, &options).map_err(|e| e.to_string())?;

    emit(&report, args.format, args.output.as_deref(), colour)?;

    let grade = report.score.grade;
    if report.has_errors() {
        return Ok(3);
    }
    Ok(if args.fail_on.breached(grade) {
        match grade {
            Grade::Critical => 2,
            _ => 1,
        }
    } else {
        0
    })
}

fn cmd_batch(args: BatchArgs, quiet: bool, colour: bool) -> Result<u8, String> {
    let options = options_from(false, true, args.rules.as_deref())?;
    let max_bytes = args.max_size_mb.saturating_mul(1024 * 1024);

    let files = collect_files(&args.path, !args.no_recursive, max_bytes)?;
    if files.is_empty() {
        return Err(format!("no files found under {}", args.path.display()));
    }
    if !quiet {
        eprintln!(
            "scanning {}",
            assay_core::bytes::plural(files.len(), "file", None)
        );
    }

    use rayon::prelude::*;
    let reports: Vec<Report> = files
        .par_iter()
        .filter_map(|path| {
            let data = std::fs::read(path).ok()?;
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string_lossy().into_owned());
            Some(analyze_bytes(&data, &name, &options))
        })
        .collect();

    match args.format {
        OutputFormat::Json => {
            let mut payload = Vec::with_capacity(reports.len());
            for r in &reports {
                payload.push(serde_json::json!({
                    "name": r.artefact.name,
                    "path": r.artefact.path,
                    "score": r.score.score,
                    "grade": r.score.grade.as_str(),
                    "format": r.artefact.detected_format,
                    "findings": r.findings.len(),
                    "techniques": r.techniques.len(),
                    "indicators": r.indicators.indicators.len(),
                    "sha256": r.artefact.sha256,
                }));
            }
            let json = serde_json::to_string_pretty(&payload)
                .map_err(|e| format!("could not serialise batch report: {e}"))?;
            write_out(&json, args.output.as_deref())?;
        }
        OutputFormat::Text => {
            let mut text = String::new();
            let mut worst = Grade::Clean;
            for r in &reports {
                if r.score.grade > worst {
                    worst = r.score.grade;
                }
                text.push_str(&format!(
                    "{:<10} {:>3}  {:<9} {}\n",
                    paint(r.score.grade, colour),
                    r.score.score,
                    r.artefact.detected_format,
                    r.artefact.name
                ));
            }
            text.push_str(&format!(
                "\n{} scanned; worst grade: {}\n",
                assay_core::bytes::plural(reports.len(), "file", None),
                paint(worst, colour)
            ));
            write_out(&text, args.output.as_deref())?;
        }
    }

    let breached = reports
        .iter()
        .any(|r| args.threshold.breached(r.score.grade));
    let errored = reports.iter().any(|r| r.has_errors());
    Ok(if errored {
        3
    } else if breached {
        if reports.iter().any(|r| r.score.grade == Grade::Critical) {
            2
        } else {
            1
        }
    } else {
        0
    })
}

fn cmd_sbom(args: SbomArgs) -> Result<u8, String> {
    let data = std::fs::read(&args.path)
        .map_err(|e| format!("cannot read {}: {e}", args.path.display()))?;
    let name = args
        .path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| args.path.to_string_lossy().into_owned());

    let report = analyze_bytes(&data, &name, &AnalyzeOptions::fast());
    let bom = assay_core::sbom::build(
        &report.image,
        &name,
        &report.artefact.sha256,
        assay_core::VERSION,
    );
    let json = assay_core::sbom::to_json(&bom).map_err(|e| e.to_string())?;
    write_out(&json, args.output.as_deref())?;
    Ok(0)
}

fn cmd_rules(args: RulesArgs, quiet: bool) -> Result<u8, String> {
    match args.action {
        RulesAction::Validate { path } => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let set = RuleSet::from_json(&text).map_err(|e| format!("invalid rule file: {e}"))?;
            let dups = set.duplicate_ids();
            if !dups.is_empty() {
                return Err(format!("duplicate rule ids: {}", dups.join(", ")));
            }
            if !quiet {
                println!(
                    "{}: {}, all valid",
                    path.display(),
                    assay_core::bytes::plural(set.rules.len(), "rule", None)
                );
                for rule in &set.rules {
                    println!(
                        "  {:<32} {:<9} {}",
                        rule.id,
                        rule.severity.as_str(),
                        rule.name
                    );
                }
            }
            Ok(0)
        }
        RulesAction::List => {
            let set = assay_core::rules::builtin().map_err(|e| e.to_string())?;
            println!("{:<34} {:<9} NAME", "ID", "SEVERITY");
            for rule in set.active() {
                println!(
                    "{:<34} {:<9} {}",
                    rule.id,
                    rule.severity.as_str(),
                    rule.name
                );
            }
            println!(
                "\n{}",
                assay_core::bytes::plural(set.active().count(), "active rule", None)
            );
            Ok(0)
        }
    }
}

fn cmd_diff(args: DiffArgs, colour: bool) -> Result<u8, String> {
    let old_opts = AnalyzeOptions::fast();
    let old =
        analyze_path(&args.old, &old_opts).map_err(|e| format!("{}: {e}", args.old.display()))?;
    let new =
        analyze_path(&args.new, &old_opts).map_err(|e| format!("{}: {e}", args.new.display()))?;

    match args.format {
        OutputFormat::Json => {
            let payload = serde_json::json!({
                "old": diff_view(&old),
                "new": diff_view(&new),
                "score_delta": i32::from(new.score.score) - i32::from(old.score.score),
                "sections_added": added(&old, &new),
                "sections_removed": removed(&old, &new),
                "techniques_added": techniques_added(&old, &new),
                "techniques_removed": techniques_removed(&old, &new),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .map_err(|e| format!("could not serialise diff: {e}"))?
            );
        }
        OutputFormat::Text => {
            println!("old: {}", old.summary());
            println!("new: {}", new.summary());
            let delta = i32::from(new.score.score) - i32::from(old.score.score);
            let sign = if delta >= 0 { "+" } else { "" };
            println!(
                "score delta: {}",
                paint_delta(delta, &format!("{sign}{delta}"), colour)
            );

            let added_sections = added(&old, &new);
            let removed_sections = removed(&old, &new);
            if !added_sections.is_empty() {
                println!("sections added:   {}", added_sections.join(", "));
            }
            if !removed_sections.is_empty() {
                println!("sections removed: {}", removed_sections.join(", "));
            }
            let ta = techniques_added(&old, &new);
            let tr = techniques_removed(&old, &new);
            if !ta.is_empty() {
                println!("techniques added:   {}", ta.join(", "));
            }
            if !tr.is_empty() {
                println!("techniques removed: {}", tr.join(", "));
            }
        }
    }
    Ok(0)
}

fn cmd_parse(args: ParseArgs) -> Result<u8, String> {
    let data = std::fs::read(&args.path)
        .map_err(|e| format!("cannot read {}: {e}", args.path.display()))?;
    let image = assay_core::parse_only(&data).map_err(|e| e.to_string())?;

    match args.format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&image)
                    .map_err(|e| format!("could not serialise structure: {e}"))?
            );
        }
        OutputFormat::Text => {
            println!(
                "{:?} {:?} ({}-bit)",
                image.format, image.arch, image.bitness
            );
            println!("entry point: {:?}", image.entry_point);
            println!("sections ({}):", image.sections.len());
            println!(
                "  {:<24} {:>10} {:>10} {:<6} {:>6}",
                "NAME", "VADDR", "VSIZE", "PERM", "ENTROPY"
            );
            for s in &image.sections {
                println!(
                    "  {:<24} {:>10x} {:>10x} {:<6} {:>6.2}",
                    s.name,
                    s.virtual_address,
                    s.virtual_size,
                    s.permissions.render(),
                    s.entropy
                );
            }
            println!(
                "imports: {}  exports: {}",
                image.imports.len(),
                image.exports.len()
            );
            for note in &image.structural_notes {
                println!("note: {note}");
            }
        }
    }
    Ok(0)
}

fn emit(
    report: &Report,
    format: OutputFormat,
    output: Option<&Path>,
    colour: bool,
) -> Result<(), String> {
    let body = match format {
        OutputFormat::Json => report
            .to_json()
            .map_err(|e| format!("could not serialise report: {e}"))?,
        OutputFormat::Text => {
            let mut text = assay_core::report::render_text(report);
            if colour {
                text = colourise(&text, report.score.grade);
            }
            text
        }
    };
    write_out(&body, output)
}

fn write_out(body: &str, output: Option<&Path>) -> Result<(), String> {
    match output {
        Some(path) => {
            let mut file = std::fs::File::create(path)
                .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
            file.write_all(body.as_bytes())
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            if !body.ends_with('\n') {
                let _ = file.write_all(b"\n");
            }
            eprintln!("wrote {}", path.display());
            Ok(())
        }
        None => {
            println!("{body}");
            Ok(())
        }
    }
}

fn collect_files(root: &Path, recursive: bool, max_bytes: u64) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut empty = 0usize;
    if root.is_file() {
        out.push(root.to_path_buf());
        return Ok(out);
    }
    if !root.is_dir() {
        return Err(format!(
            "{} is neither a file nor a directory",
            root.display()
        ));
    }

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| format!("cannot read directory {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                if recursive {
                    stack.push(path);
                }
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if meta.len() > max_bytes {
                eprintln!(
                    "skipping {} ({} exceeds the size cap)",
                    path.display(),
                    assay_core::report::format_size(meta.len())
                );
                continue;
            }
            // An empty file has no structure, imports or strings to examine.
            // Reporting one as "clean, score 0" is worse than skipping it: the
            // reader concludes it was analysed and cleared, when nothing was
            // analysed at all. Placeholders like `.gitkeep` are the common case.
            if meta.len() == 0 {
                empty += 1;
                continue;
            }
            out.push(path);
        }
    }
    out.sort();
    if empty > 0 {
        eprintln!(
            "skipped {} (zero bytes, nothing to analyse)",
            assay_core::bytes::plural(empty, "empty file", None)
        );
    }
    Ok(out)
}

fn paint(grade: Grade, colour: bool) -> String {
    let label = grade.as_str();
    if !colour {
        return label.to_string();
    }
    let code = match grade {
        Grade::Clean => "32",
        Grade::Low => "36",
        Grade::Medium => "33",
        Grade::High => "31",
        Grade::Critical => "1;31",
    };
    format!("\x1b[{code}m{label}\x1b[0m")
}

fn paint_delta(delta: i32, rendered: &str, colour: bool) -> String {
    if !colour {
        return rendered.to_string();
    }
    let code = if delta > 0 {
        "31"
    } else if delta < 0 {
        "32"
    } else {
        "0"
    };
    format!("\x1b[{code}m{rendered}\x1b[0m")
}

/// No-op colouriser that exists so text output can be extended without touching
/// call sites; the caller decides whether ANSI is wanted.
fn colourise(text: &str, _grade: Grade) -> String {
    text.to_string()
}

fn diff_view(r: &Report) -> serde_json::Value {
    serde_json::json!({
        "name": r.artefact.name,
        "sha256": r.artefact.sha256,
        "score": r.score.score,
        "grade": r.score.grade.as_str(),
        "sections": r.image.sections.iter().map(|s| &s.name).collect::<Vec<_>>(),
        "imports": r.image.imports.len(),
        "techniques": r.techniques.iter().map(|t| &t.id).collect::<Vec<_>>(),
    })
}

fn added(old: &Report, new: &Report) -> Vec<String> {
    let before: std::collections::HashSet<&str> =
        old.image.sections.iter().map(|s| s.name.as_str()).collect();
    new.image
        .sections
        .iter()
        .map(|s| s.name.as_str())
        .filter(|n| !before.contains(n))
        .map(String::from)
        .collect()
}

fn removed(old: &Report, new: &Report) -> Vec<String> {
    let after: std::collections::HashSet<&str> =
        new.image.sections.iter().map(|s| s.name.as_str()).collect();
    old.image
        .sections
        .iter()
        .map(|s| s.name.as_str())
        .filter(|n| !after.contains(n))
        .map(String::from)
        .collect()
}

fn techniques_added(old: &Report, new: &Report) -> Vec<String> {
    let before: std::collections::HashSet<&str> =
        old.techniques.iter().map(|t| t.id.as_str()).collect();
    new.techniques
        .iter()
        .map(|t| t.id.as_str())
        .filter(|id| !before.contains(id))
        .map(String::from)
        .collect()
}

fn techniques_removed(old: &Report, new: &Report) -> Vec<String> {
    let after: std::collections::HashSet<&str> =
        new.techniques.iter().map(|t| t.id.as_str()).collect();
    old.techniques
        .iter()
        .map(|t| t.id.as_str())
        .filter(|id| !after.contains(id))
        .map(String::from)
        .collect()
}
