# VibeScan

VibeScan is a vulnerability scanner CLI.

## Installation

```bash
pip install -e .
```

## Usage

Run the doctor command to verify your environment:

```bash
vibescan doctor
```

Run a scan (example with dry-run):

```bash
vibescan scan example.com --dry-run
```

Run a real scan:

```bash
# Sudo might be required for some Nmap features
sudo vibescan scan scanme.nmap.org
```

### Tests

To run the test suite:

```bash
pytest
```