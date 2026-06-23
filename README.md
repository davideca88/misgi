# MISGI: Malware Identifier with SubGraph Isomorphism

Code obfuscation represents a significant challenge for malware detection, as it alters the program's structure without compromising its malicious functionalities. This work presents MISGI (Malware Identifier with SubGraph Isomorphism), a graph theory-based approach that performs static analysis by comparing graph representations of programs with a database of known malware. Using subgraph isomorphism techniques, the solution seeks to identify malicious behavior even in obfuscated code.

Help:
```
misgi v0.1.0 - Malware Identifier with SubGraph Isomorphism

USAGE:
    misgi <exec-binary> [OPTIONS]

Analyze a binary and detect obfuscated malware using subgraph isomorphism.

ARGUMENTS:
    <binary> Path to the binary file to analyze

OPTIONS:

    -m, --malware-binary <FILE>

    -e, --export-graphs     Export generated graphs

    -f, --export-format <FORMAT>    Graph export format (dot, json, gml, ...)
        Requires --export-graphs

    -h, --help  Display this help message and exit

```

## Installation

Requirements:
  - rustc + cargo
  - radare2

### Build

This project uses `make` as a thin around `cargo`.

```sh
make help
```

| Target                | Description                                               |
| --------------------- | --------------------------------------------------------- |
| `make build`          | Debug build                                               |
| `make release`        | Optimized build (`--release`)                             |
| `make run ARGS="..."` | Runs the binary, forwarding arguments to the CLI          |
| `make test`           | Runs the entire test suite (`tests/*.rs`)                 |
| `make fmt`            | Formats the code (`cargo fmt`)                            |
| `make fmt-check`      | Checks formatting without modifying files (for CI usage)  |
| `make lint`           | `cargo clippy --all-targets -- -D warnings`               |
| `make check`          | Fast type checking without producing binaries             |
| `make doc`            | Generates the documentation (`cargo doc`)                 |
| `make clean`          | Removes Cargo build artifacts                             |
| `make install`        | Installs the release binary via `cargo install`           |
| `make distclean`      | `clean` + removes exported graphs (`.dot`/`.json`/`.gml`) |
| `make all`            | `fmt-check` + `lint` + `build` + `test`                   |

Example:

```sh
make build
make run ARGS="bin/target_sample -m bin/malware_sample -e -f dot"
make test
```

