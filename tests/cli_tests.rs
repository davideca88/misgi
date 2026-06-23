use std::ffi::OsString;
use std::path::PathBuf;

use misgi::cli::{parse_args, CliArgs, CliError, CliParseResult};
use misgi::graph_export::GraphExportFormat;

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn expected_run() -> CliParseResult {
    CliParseResult::Run(CliArgs {
        target_binary: PathBuf::from("target.bin"),
        malware_binary: PathBuf::from("malware.bin"),
        export_graphs: false,
        export_format: None,
    })
}

#[test]
fn parses_short_malware_option() {
    let parsed = parse_args(args(&["target.bin", "-m", "malware.bin"])).expect("args should parse");

    assert_eq!(parsed, expected_run());
}

#[test]
fn parses_long_malware_option() {
    let parsed = parse_args(args(&["target.bin", "--malware-binary", "malware.bin"]))
        .expect("args should parse");

    assert_eq!(parsed, expected_run());
}

#[test]
fn parses_export_graphs() {
    let parsed = parse_args(args(&[
        "target.bin",
        "-m",
        "malware.bin",
        "--export-graphs",
    ]))
    .expect("args should parse");

    assert_eq!(
        parsed,
        CliParseResult::Run(CliArgs {
            target_binary: PathBuf::from("target.bin"),
            malware_binary: PathBuf::from("malware.bin"),
            export_graphs: true,
            export_format: None,
        })
    );
}

#[test]
fn parses_supported_export_formats() {
    for (value, format) in [
        ("json", GraphExportFormat::Json),
        ("dot", GraphExportFormat::Dot),
        ("gml", GraphExportFormat::Gml),
    ] {
        let parsed = parse_args(args(&[
            "target.bin",
            "-m",
            "malware.bin",
            "--export-graphs",
            "--export-format",
            value,
        ]))
        .expect("args should parse");

        assert_eq!(
            parsed,
            CliParseResult::Run(CliArgs {
                target_binary: PathBuf::from("target.bin"),
                malware_binary: PathBuf::from("malware.bin"),
                export_graphs: true,
                export_format: Some(format),
            })
        );
    }
}

#[test]
fn parses_help() {
    assert_eq!(parse_args(args(&["--help"])), Ok(CliParseResult::Help));
}

#[test]
fn missing_target_binary_fails() {
    assert_eq!(
        parse_args(Vec::<OsString>::new()),
        Err(CliError::MissingTargetBinary)
    );
}

#[test]
fn missing_malware_binary_fails() {
    assert_eq!(
        parse_args(args(&["target.bin"])),
        Err(CliError::MissingMalwareBinary)
    );
}

#[test]
fn missing_malware_binary_value_fails() {
    assert_eq!(
        parse_args(args(&["target.bin", "-m"])),
        Err(CliError::MissingMalwareBinaryValue)
    );
}

#[test]
fn missing_export_format_value_fails() {
    assert_eq!(
        parse_args(args(&[
            "target.bin",
            "-m",
            "malware.bin",
            "--export-graphs",
            "--export-format",
        ])),
        Err(CliError::MissingExportFormatValue)
    );
}

#[test]
fn export_format_without_export_graphs_fails() {
    assert_eq!(
        parse_args(args(&[
            "target.bin",
            "-m",
            "malware.bin",
            "--export-format",
            "json",
        ])),
        Err(CliError::ExportFormatWithoutExportGraphs)
    );
}

#[test]
fn unsupported_export_format_fails() {
    assert_eq!(
        parse_args(args(&[
            "target.bin",
            "-m",
            "malware.bin",
            "--export-graphs",
            "--export-format",
            "svg",
        ])),
        Err(CliError::UnsupportedExportFormat(OsString::from("svg")))
    );
}

#[test]
fn extra_positional_argument_fails() {
    assert_eq!(
        parse_args(args(&["target.bin", "extra.bin", "-m", "malware.bin"])),
        Err(CliError::UnexpectedArgument(OsString::from("extra.bin")))
    );
}
