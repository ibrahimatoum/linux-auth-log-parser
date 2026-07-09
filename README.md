# Linux Auth Log Parser (Python)

A Python tool that parses Linux `auth.log` files, classifies each line as a security event (failed login, successful login, privilege escalation, or system event), assigns a severity level, and exports the results to JSON and/or CSV.

I built this as part of my cybersecurity portfolio. The JSON output is designed to be ingested by Splunk.

## What it does

- Parses raw `auth.log` lines using regex to extract **timestamp, source IP, port, and username**
- Classifies each event by keyword matching, in priority order:
  | Event Type | Severity | Example Trigger |
  |---|---|---|
  | Failed Login | HIGH | `Failed password`, `Invalid user` |
  | Privilege Escalation | HIGH | `sudo`, `COMMAND` |
  | Successful Login | MEDIUM | `Accepted password`, `session opened` |
  | System Event | LOW | `cron`, `Disconnected` |
  | Unknown | INFO | anything unmatched |
- Writes structured **JSON** (Splunk-friendly) and optional **CSV** (Excel-friendly) output
- Prints a summary report of event type and severity counts
- Can generate its own sample `auth.log` for testing/demo (`--sample`)
- Handles missing files, permission errors, and blank lines 

## Usage

```bash
# Parse a real auth log and export JSON + CSV
python3 log_parser.py --log /var/log/auth.log --csv

# Custom output filename
python3 log_parser.py --log /var/log/auth.log --output results.json

# Generate a sample log for testing
python3 log_parser.py --sample

# No arguments: generates a sample log and parses it (demo mode)
python3 log_parser.py
```

No dependencies beyond the Python standard library (`re`, `json`, `csv`, `argparse`, `sys`). Tested on Python 3.10+.

## Example output

Console summary from the included sample log:

```
==================================================
         PARSE SUMMARY
==================================================
  Total events parsed : 16

  --- By Event Type ---
  Failed Login              8
  Privilege Escalation      1
  Successful Login          5
  System Event              2

  --- By Severity ---
  HIGH       9
  LOW        2
  MEDIUM     5
==================================================
```

JSON record example:

```json
{
    "line_number": 1,
    "timestamp": "Jun 26 09:01:12",
    "source_ip": "203.0.113.42",
    "port": "51234",
    "username": "root",
    "event_type": "Failed Login",
    "severity": "HIGH",
    "raw": "Jun 26 09:01:12 ubuntu-server sshd[1101]: Failed password for root from 203.0.113.42 port 51234 ssh2"
}
```

Full sample outputs are in the [`examples/`](examples/) folder.

## Why JSON output?

Splunk and most SIEMs ingest JSON natively with automatic field extraction. 

## What I learned

- Writing and testing regex patterns against real log formats
- Structuring a CLI tool with `argparse` (flags, defaults, boolean switches)
- Defensive coding: try/except for file errors, `.get()` for safe dict lookups, handling blank/malformed lines
- Why analysts care about output format, JSON for SIEM ingestion, CSV for spreadsheet triage

## Repo contents

```
log_parser.py          # The parser
examples/
  sample_auth.log      # Generated sample input
  parsed_logs.json     # Example JSON output
  parsed_logs.csv      # Example CSV output
```
