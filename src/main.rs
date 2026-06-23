use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use misgi::cli::{parse_args, CliParseResult, HELP};
use misgi::detection::{analyze_detection, DetectionReport};
use misgi::graph_export::{export_graph, GraphExportFormat};
use misgi::graph_processor::GraphModel;

fn main() -> ExitCode {
    match parse_args(env::args_os().skip(1)) {
        Ok(CliParseResult::Help) => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Ok(CliParseResult::Run(args)) => {
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
