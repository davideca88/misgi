use std::ffi::OsString;
use std::path::PathBuf;

use misgi::cli::{parse_args, CliArgs, CliError, CliParseResult, MockArgs};
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
        mock: None,
    })
}

#[test]
fn parses_short_malware_option() {
    let parsed = parse_args(args(&["target.bin", "-m", "malware.bin"])).expect("args should parse");

    assert_eq!(parsed, expected_run());
}

#[test]
fn parses_long_malware_option() {
    let parsed =
        parse_args(args(&["target.bin", "--malware", "malware.bin"])).expect("args should parse");

    assert_eq!(parsed, expected_run());
}

#[test]
fn parses_legacy_long_malware_option() {
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
            mock: None,
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
                mock: None,
            })
        );
    }
}

#[test]
fn parses_mock_option() {
    let parsed = parse_args(args(&[
        "target.bin",
        "-m",
        "malware.bin",
        "--mock",
        "0.1",
        "0.25",
        "0.75",
        "123",
    ]))
    .expect("args should parse");

    assert_eq!(
        parsed,
        CliParseResult::Run(CliArgs {
            target_binary: PathBuf::from("target.bin"),
            malware_binary: PathBuf::from("malware.bin"),
            export_graphs: false,
            export_format: None,
            mock: Some(MockArgs {
                perturbation_percentage: 0.1,
                injection_ratio: 0.25,
                add_ratio: 0.75,
                seed: 123,
            }),
        })
    );
}
/*
#[test]
fn missing_mock_values_fail() {
    assert_eq!(
        parse_args(args(&["target.bin", "-m", "malware.bin", "--mock"])),
        Err(CliError::MissingMockPerturbationPercentage)
    );
    assert_eq!(
        parse_args(args(&["target.bin", "-m", "malware.bin", "--mock", "0.2"])),
        Err(CliError::MissingMockAddRatio)
    );
    assert_eq!(
        parse_args(args(&[
            "target.bin",
            "-m",
            "malware.bin",
            "--mock",
            "0.2",
            "0.5",
        ])),
        Err(CliError::MissingMockSeed)
    );
}


#[test]
fn invalid_mock_values_fail() {
    assert_eq!(
        parse_args(args(&[
            "target.bin",
            "-m",
            "malware.bin",
            "--mock",
            "1.2",
            "0.5",
            "1",
        ])),
        Err(CliError::InvalidMockPerturbationPercentage(OsString::from(
            "1.2"
        )))
    );
    assert_eq!(
        parse_args(args(&[
            "target.bin",
            "-m",
            "malware.bin",
            "--mock",
            "0.2",
            "-0.1",
            "1",
        ])),
        Err(CliError::InvalidMockAddRatio(OsString::from("-0.1")))
    );
    assert_eq!(
        parse_args(args(&[
            "target.bin",
            "-m",
            "malware.bin",
            "--mock",
            "0.2",
            "0.5",
            "seed",
        ])),
        Err(CliError::InvalidMockSeed(OsString::from("seed")))
    );
}
*/
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
