# vibescan

Lightweight CLI scaffolding for authorized scan workflows. `vibescan` is an MVP security scanner that currently supports:
- TCP connect scanning (no SYN/UDP)
- Basic service/banner detection
- Optional CVE lookups (NVD API)
- Recursive web tech detection (headers, cookies, HTML)
- Nmap XML import
- Plain, JSON, and XML output formats

**Disclaimer:** Use this tool only on systems you are authorized to scan.

## Quick Start

1. Install Go (see Requirements below).
2. Clone the repo and enter it:
   ```bash
   git clone https://github.com/harshaljain03/VibeScan.git
   cd VibeScan
   ```
3. Download dependencies and generate `go.sum`:
   ```bash
   go mod tidy
   ```
4. Build the binary:
   ```bash
   go build -o vibescan .
   ```
5. Run a scan:
   ```bash
   ./vibescan example.com
   ```

## Requirements

- Go `1.24.4` or newer (matches `go.mod`).
- Network access if you want to run scans or CVE lookups.

## Build

```bash
go mod tidy
go build -o vibescan .
```

Then run:
```bash
./vibescan example.com
```

## Usage

```
vibescan [flags] <target>
```

### Target Input

The CLI accepts exactly one positional argument when not using `--input`. This argument can be:
- IP address
- Domain
- URL (scheme removed, trailing slash removed)
- Comma-separated list
- File path (one target per line; blank lines and comments are ignored)

Examples:
```bash
./vibescan 192.0.2.10
./vibescan example.com
./vibescan https://example.com/
./vibescan example.com,192.0.2.1
./vibescan targets.txt
```

### Flags

- `-p, --ports` Ports to scan (comma-separated list or ranges). Default: `80,443`
  - Example: `-p 22,80,443,8000-8005`
- `--timeout` Per-port timeout. Default: `2s`
- `--fast` Use a shorter timeout (200ms) unless `--timeout` is provided
- `--non-recursive` Disable recursive web scanning
- `-i, --input` Load targets from an Nmap XML file (bypasses scanning)
- `--format` Output format: `plain`, `json`, `xml` (default `plain`)

### Output Formats

- `plain` is the human-readable text output.
- `json` and `xml` are stable, structured representations of `ScanResult`.

Examples:
```bash
./vibescan example.com --format json
./vibescan example.com --format xml
```

### Nmap XML Import

If you already have Nmap XML output, you can import it with `-i/--input`. This bypasses active scanning and simply renders the parsed data.

```bash
./vibescan --input nmap.xml --format json
```

Note: When `--input` is provided, positional targets are not allowed.

## CVE Lookups (Optional)

`vibescan` can enrich detected services and web technologies with CVEs from the NVD API. This is optional and will gracefully handle API failures.

To use a key:
```bash
export NVD_API_KEY="your-key-here"
```

## Tests

Run all tests:
```bash
go test ./...
```

Note: TCP service detection tests spin up a local TCP listener. These require the OS to allow local sockets.

## Troubleshooting

- **`missing go.sum entry`**  
  Run `go mod tidy` to download dependencies and generate `go.sum`.
- **No network access**  
  Go module downloads require network access. Configure your proxy or run in an environment with internet access.

## Project Layout

- `cmd/` CLI entrypoint and flag wiring
- `internal/domain/` Core scan models
- `internal/input/` Input parsing (targets, ports, Nmap XML)
- `internal/render/` Plain, JSON, and XML renderers
- `internal/scan/` Scanners and enrichment pipeline
- `internal/cve/` CVE client, matching, and cache

## Safety

- TCP connect scans only
- No UDP or SYN scanning
- HTTP probing is read-only (HEAD/GET)
- No exploitation logic

## License

See `LICENSE`.
