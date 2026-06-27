use std::ffi::OsString;
use std::path::PathBuf;

use crate::graph_export::GraphExportFormat;

#[derive(Debug, Clone, PartialEq)]
pub struct CliArgs {
    pub target_binary: PathBuf,
    pub malware_binary: PathBuf,
    pub export_graphs: bool,
    pub export_format: Option<GraphExportFormat>,
    pub mock: Option<MockArgs>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MockArgs {
    pub perturbation_percentage: f64,
    pub injection_ratio: f64,
    pub add_ratio: f64,
    pub seed: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CliParseResult {
    Run(CliArgs),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    MissingTargetBinary,
    MissingMalwareBinary,
    MissingMalwareBinaryValue,
    MissingExportFormatValue,
    MissingMockPerturbationPercentage,
    MissingMockInjectionRatio,
    MissingMockAddRatio,
    MissingMockSeed,
    InvalidMockPerturbationPercentage(OsString),
    InvalidMockInjectionRatio(OsString),
    InvalidMockAddRatio(OsString),
    InvalidMockSeed(OsString),
    ExportFormatWithoutExportGraphs,
    UnsupportedExportFormat(OsString),
    UnexpectedArgument(OsString),
}

impl CliError {
    pub fn message(&self) -> String {
        match self {
            Self::MissingTargetBinary => "missing target binary".to_string(),
            Self::MissingMalwareBinary => "missing malware binary; use -m <FILE>".to_string(),
            Self::MissingMalwareBinaryValue => {
                "missing value for malware binary option".to_string()
            }
            Self::MissingExportFormatValue => "missing value for export format option".to_string(),
            Self::MissingMockPerturbationPercentage => {
                "missing perturbation percentage for mock option".to_string()
            }
            Self::MissingMockInjectionRatio => "missing injection ratio for mock option".to_string(),
            Self::MissingMockAddRatio => "missing add ratio for mock option".to_string(),
            Self::MissingMockSeed => "missing seed for mock option".to_string(),
            Self::InvalidMockPerturbationPercentage(value) => format!(
                "invalid mock perturbation percentage: {}; expected a number in [0.0, 1.0]",
                value.to_string_lossy()
            ),
            Self::InvalidMockInjectionRatio(value) => format!(
                "invalid mock injection ratio: {}; expected a non-negative number",
                value.to_string_lossy()
            ),
            Self::InvalidMockAddRatio(value) => format!(
                "invalid mock add ratio: {}; expected a number in [0.0, 1.0]",
                value.to_string_lossy()
            ),
            Self::InvalidMockSeed(value) => format!(
                "invalid mock seed: {}; expected a non-negative integer",
                value.to_string_lossy()
            ),
            Self::ExportFormatWithoutExportGraphs => {
                "export format requires --export-graphs".to_string()
            }
            Self::UnsupportedExportFormat(format) => {
                format!("unsupported export format: {}", format.to_string_lossy())
            }
            Self::UnexpectedArgument(argument) => {
                format!("unexpected argument: {}", argument.to_string_lossy())
            }
        }
    }
}

pub const HELP: &str = "\
misgi v0.1.0 - Malware Identifier with SubGraph Isomorphism

USAGE:
    misgi <exec-binary> [OPTIONS]

Analyze a binary and detect obfuscated malware using subgraph isomorphism.

ARGUMENTS:
    <exec-binary>                 Path to the binary file to analyze

OPTIONS:
    -m, --malware <FILE>               Malware binary to search for
    -e, --export-graphs                Export generated graphs
    -i, --import-graphs                Import graphs from dot instead of RE binaries
    -f, --export-format <FORMAT>       Graph export format (dot, json, gml)
                                       Requires --export-graphs
    -M, --mock <PP> <IR> <AR> <SEED>   Run detection against a mocked target
                                         PP: perturbation percentage
                                         IR: injection ratio
                                         AR: add ratio
                                         SEED: RNG seed
    -h, --help                         Display this help message and exit
";

pub fn parse_args<I>(args: I) -> Result<CliParseResult, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut target_binary = None;
    let mut malware_binary = None;
    let mut export_graphs = false;
    let mut export_format = None;
    let mut mock_args = None;
    let mut iter = args.into_iter();

    while let Some(argument) = iter.next() {
        if argument == "-h" || argument == "--help" {
            return Ok(CliParseResult::Help);
        }

        if argument == "-m" || argument == "--malware" || argument == "--malware-binary" {
            let value = iter.next().ok_or(CliError::MissingMalwareBinaryValue)?;
            malware_binary = Some(PathBuf::from(value));
            continue;
        }

        if argument == "-e" || argument == "--export-graphs" {
            export_graphs = true;
            continue;
        }

        if argument == "-f" || argument == "--export-format" {
            let value = iter.next().ok_or(CliError::MissingExportFormatValue)?;
            let format = GraphExportFormat::parse(&value)
                .ok_or_else(|| CliError::UnsupportedExportFormat(value.clone()))?;
            export_format = Some(format);
            continue;
        }

        if argument == "-M" || argument == "--mock" {
            let perturbation_percentage = iter
                .next()
                .ok_or(CliError::MissingMockPerturbationPercentage)?;
                let injection_ratio = iter.next().ok_or(CliError::MissingMockPerturbationPercentage)?;
            let add_ratio = iter.next().ok_or(CliError::MissingMockAddRatio)?;
            let seed = iter.next().ok_or(CliError::MissingMockSeed)?;

            mock_args = Some(MockArgs {
                perturbation_percentage: parse_unit_interval(
                    &perturbation_percentage,
                    CliError::InvalidMockPerturbationPercentage,
                )?,
                injection_ratio: parse_unit_interval(&injection_ratio, CliError::InvalidMockInjectionRatio)?,
                add_ratio: parse_unit_interval(&add_ratio, CliError::InvalidMockAddRatio)?,
                seed: seed
                    .to_string_lossy()
                    .parse::<u64>()
                    .map_err(|_| CliError::InvalidMockSeed(seed.clone()))?,
            });
            continue;
        }

        if argument.to_string_lossy().starts_with('-') {
            return Err(CliError::UnexpectedArgument(argument));
        }

        if target_binary.is_some() {
            return Err(CliError::UnexpectedArgument(argument));
        }

        target_binary = Some(PathBuf::from(argument));
    }

    let target_binary = target_binary.ok_or(CliError::MissingTargetBinary)?;
    let malware_binary = malware_binary.ok_or(CliError::MissingMalwareBinary)?;

    if export_format.is_some() && !export_graphs {
        return Err(CliError::ExportFormatWithoutExportGraphs);
    }

    Ok(CliParseResult::Run(CliArgs {
        target_binary,
        malware_binary,
        export_graphs,
        export_format,
        mock: mock_args,
    }))
}

fn parse_unit_interval(value: &OsString, error: fn(OsString) -> CliError) -> Result<f64, CliError> {
    let parsed = value
        .to_string_lossy()
        .parse::<f64>()
        .map_err(|_| error(value.clone()))?;

    if (0.0..=1.0).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(error(value.clone()))
    }
}
