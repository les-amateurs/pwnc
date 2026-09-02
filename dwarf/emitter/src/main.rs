use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use teemo_dwarf::{Document, EmitOptions, emit};

fn main() -> Result<()> {
    let mut arguments = env::args_os().skip(1);
    let Some(command) = arguments.next() else {
        usage();
        bail!("missing command");
    };
    let Some(input) = arguments.next() else {
        usage();
        bail!("missing input path");
    };
    let input = PathBuf::from(input);
    let raw = fs::read(&input)
        .with_context(|| format!("failed to read IR document {}", input.display()))?;
    let document: Document = serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse IR document {}", input.display()))?;

    match command.to_string_lossy().as_ref() {
        "validate" => {
            if arguments.next().is_some() {
                usage();
                bail!("validate accepts exactly one input path");
            }
            document.validate()?;
            println!("valid Teemo IR v{}", document.version);
        }
        "emit" => {
            let Some(output) = arguments.next() else {
                usage();
                bail!("missing output path");
            };
            let mut options = EmitOptions::default();
            while let Some(option) = arguments.next() {
                let target = match option.to_str() {
                    Some("--source-root") => &mut options.source_root,
                    Some("--source-reference-root") => &mut options.source_reference_root,
                    _ => {
                        usage();
                        bail!("unknown emit option {option:?}");
                    }
                };
                let Some(path) = arguments.next() else {
                    usage();
                    bail!("emit option {option:?} requires a path");
                };
                *target = Some(PathBuf::from(path));
            }
            let output = PathBuf::from(output);
            let report = emit(&document, &output, &options)?;
            for warning in report.warnings {
                eprintln!("warning: {warning}");
            }
        }
        _ => {
            usage();
            bail!("unknown command {:?}", command);
        }
    }
    Ok(())
}

fn usage() {
    eprintln!("usage: teemo-dwarf validate <input.json>");
    eprintln!(
        "       teemo-dwarf emit <input.json> <output.debug> [--source-root PATH] [--source-reference-root PATH]"
    );
}
