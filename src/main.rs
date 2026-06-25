use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use misgi::cli::{parse_args, CliParseResult, HELP};
use misgi::detection::{analyze_detection, analyze_detection_with_mock, DetectionReport};
use misgi::graph_export::{export_graph, GraphExportFormat};
use misgi::graph_processor::mock::{MockConfig, MockReport};
use misgi::graph_processor::GraphModel;

fn main() -> ExitCode {
    match parse_args(env::args_os().skip(1)) {
        Ok(CliParseResult::Help) => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Ok(CliParseResult::Run(args)) => {
            if let Some(mock_args) = args.mock {
                let mock_config = MockConfig {
                    perturbation_percentage: mock_args.perturbation_percentage,
                    injection_ratio: mock_args.injection_ratio,
                    add_ratio: mock_args.add_ratio,
                    seed: mock_args.seed,
                };

                match analyze_detection_with_mock(
                    &args.target_binary,
                    &args.malware_binary,
                    &mock_config,
                ) {
                    Ok(analysis) => {
                        print_report(&analysis.report);
                        print_mock_report(&analysis.mock_report);

                        if args.export_graphs {
                            let format = args.export_format.unwrap_or(GraphExportFormat::Json);
                            match export_mock_generated_graphs(
                                &analysis.original_target_graph,
                                &analysis.target_mock_graph,
                                &analysis.malware_graph,
                                format,
                                Path::new("."),
                            ) {
                                Ok(paths) => {
                                    println!("exported target graph: {}", paths.target.display());
                                    println!(
                                        "exported mocked target graph: {}",
                                        paths.target_mock.display()
                                    );
                                    println!("exported malware graph: {}", paths.malware.display());
                                }
                                Err(error) => {
                                    eprintln!("error: failed to export graphs: {error}");
                                    return ExitCode::FAILURE;
                                }
                            }
                        }

                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("error: {error}");
                        ExitCode::FAILURE
                    }
                }
            } else {
                match analyze_detection(&args.target_binary, &args.malware_binary) {
                    Ok(analysis) => {
                        print_report(&analysis.report);

                        if args.export_graphs {
                            let format = args.export_format.unwrap_or(GraphExportFormat::Json);
                            match export_generated_graphs(
                                &analysis.target_graph,
                                &analysis.malware_graph,
                                format,
                                Path::new("."),
                            ) {
                                Ok(paths) => {
                                    println!("exported target graph: {}", paths.target.display());
                                    println!("exported malware graph: {}", paths.malware.display());
                                }
                                Err(error) => {
                                    eprintln!("error: failed to export graphs: {error}");
                                    return ExitCode::FAILURE;
                                }
                            }
                        }

                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("error: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
        }
        Err(error) => {
            eprintln!("error: {}", error.message());
            eprintln!();
            eprint!("{HELP}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug)]
struct ExportedGraphPaths {
    target: PathBuf,
    malware: PathBuf,
}

#[derive(Debug)]
struct ExportedMockGraphPaths {
    target: PathBuf,
    target_mock: PathBuf,
    malware: PathBuf,
}

fn export_generated_graphs(
    target_graph: &GraphModel,
    malware_graph: &GraphModel,
    format: GraphExportFormat,
    directory: &Path,
) -> std::io::Result<ExportedGraphPaths> {
    let target_path = directory.join(format!("target_graph.{}", format.extension()));
    let malware_path = directory.join(format!("malware_graph.{}", format.extension()));

    fs::write(&target_path, export_graph(target_graph, format))?;
    fs::write(&malware_path, export_graph(malware_graph, format))?;

    Ok(ExportedGraphPaths {
        target: target_path,
        malware: malware_path,
    })
}

fn export_mock_generated_graphs(
    original_target_graph: &GraphModel,
    target_mock_graph: &GraphModel,
    malware_graph: &GraphModel,
    format: GraphExportFormat,
    directory: &Path,
) -> std::io::Result<ExportedMockGraphPaths> {
    let target_path = directory.join(format!("target_graph.{}", format.extension()));
    let target_mock_path = directory.join(format!("target_mock_graph.{}", format.extension()));
    let malware_path = directory.join(format!("malware_graph.{}", format.extension()));

    fs::write(&target_path, export_graph(original_target_graph, format))?;
    fs::write(&target_mock_path, export_graph(target_mock_graph, format))?;
    fs::write(&malware_path, export_graph(malware_graph, format))?;

    Ok(ExportedMockGraphPaths {
        target: target_path,
        target_mock: target_mock_path,
        malware: malware_path,
    })
}

fn print_report(report: &DetectionReport) {
    if report.detected {
        println!("MALWARE DETECTED");
    } else {
        println!("NO MATCH");
    }

    println!(
        "pattern: {} vertices, {} edges",
        report.pattern.vertices, report.pattern.edges
    );
    println!(
        "target: {} vertices, {} edges",
        report.target.vertices, report.target.edges
    );
}

fn print_mock_report(report: &MockReport) {
    println!(
        "mock pattern edges added: {}",
        report.pattern_edges_removed
    );
    println!(
        "mock pattern edges removed: {}",
        report.pattern_edges_removed
    );
    println!(
        "mock injection edges added: {}",
        report.injection_edges_added
    )
}
