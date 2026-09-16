# ThreatIntel

A test-driven Python project for building a modular threat-intelligence processing pipeline around **Indicators of Compromise (IOCs)**.

The project is being developed incrementally, with an emphasis on clear data models, explicit provenance, testable transformations, and separation between source-specific ingestion and source-independent processing.

## What it does today

ThreatIntel currently supports:

- an `IOC` domain model with source provenance;
- IOC types for IP addresses, domain names, and SHA-256 hashes;
- validation and normalization of:
  - IPv4 and IPv6 addresses;
  - domain names;
  - SHA-256 hashes;
- deduplication using `(type, value)` as IOC identity;
- merging source information when duplicate indicators are found;
- non-destructive processing: input IOC objects are not mutated;
- local JSON ingestion and parsing;
- processing statistics:
  - indicators processed;
  - unique indicators;
  - duplicates;
  - counts by IOC type;
- a CLI for processing local JSON IOC files;
- live ThreatFox ingestion through an authenticated HTTPS client;
- a ThreatFox adapter that converts supported external IOC types into the internal model;
- cross-source deduplication while preserving provenance;
- unit, integration, end-to-end, and mocked HTTP tests with `pytest`.

## Architecture

Each external source has its own ingestion path. Supported records are converted into the common `IOC` model before entering the shared processing pipeline.

```text
Local JSON                              ThreatFox API
    |                                       |
    v                                       v
Ingestion                              HTTP client
    |                                       |
    v                                       v
Parsing                              ThreatFox adapter
    |                                       |
    +-------------------+-------------------+
                        |
                        v
                    list[IOC]
                        |
                        v
                  Normalization
                        |
                        v
                  Deduplication
                        |
                        v
                   Statistics
                        |
                        v
                  CLI / Output
```

This keeps source-specific formats, authentication, and transport details outside the normalization and deduplication logic.

## Supported IOC types

The internal model currently supports:

| Internal type | Notes |
|---|---|
| `IP` | IPv4 and IPv6 normalization |
| `DOMAIN` | ASCII domain validation and normalization |
| `SHA256` | 64-character hexadecimal SHA-256 values |

ThreatFox currently maps:

| ThreatFox type | Internal type |
|---|---|
| `domain` | `DOMAIN` |
| `sha256_hash` | `SHA256` |

Unsupported ThreatFox types are ignored rather than coerced into incompatible internal types.


## Installation

Install the project in editable mode:

```bash
python -m pip install -e .
```

For development, including test dependencies:

```bash
python -m pip install -e .[dev]
```

## Running the tests

Run the complete test suite with:

```bash
python -m pytest
```

The suite includes:

- unit tests for parsing, normalization, deduplication, statistics, configuration, and feed-specific components;
- CLI tests;
- integration and end-to-end tests;
- mocked HTTP tests that do not require Internet access or real credentials;
- cross-source processing tests.

## Local JSON usage

Process the included sample IOC file:

```bash
python -m threatintel.cli samples/iocs.json
```

Example output:

```text
Indicators processed: 4
Unique indicators: 3
Duplicates: 1

ip: 1
domain: 1
sha256: 1
```

## ThreatFox integration

ThreatFox authentication is provided through the `THREATFOX_AUTH_KEY` environment variable.

**Never store the real key in source code, tests, sample files, the README, or Git history.**

For example, in PowerShell, configure it for the current shell session:

```powershell
$env:THREATFOX_AUTH_KEY = "YOUR_KEY"
```

Retrieve recent ThreatFox IOCs through the orchestration layer:

```python
from threatintel.feeds.threatfox_orchestrator import get_threatfox_iocs

iocs = get_threatfox_iocs(days=1)
```

The returned values are internal `IOC` objects and can be passed through the shared pipeline:

```python
from threatintel.pipeline import process_iocs

processed_iocs = process_iocs(iocs)
```

The ThreatFox client uses authenticated HTTPS requests with an explicit timeout and propagates HTTP, timeout, and JSON-decoding failures to callers.

## Cross-source processing

Indicators from heterogeneous sources can be combined before processing:

```text
Local feed ──────┐
                 ├──> normalization ──> deduplication
ThreatFox ───────┘
```

For example:

```text
Local:
    EVIL.COM.
    source = local_feed

ThreatFox:
    evil.com
    source = threatfox
```

becomes:

```text
DOMAIN
value = evil.com
sources = {"local_feed", "threatfox"}
```

This makes source provenance part of the model while allowing equivalent observations to converge on one canonical IOC.

## Roadmap

### IOC model and processing

- [x] Define IOC types and the IOC data model
- [x] Track source provenance
- [x] Validate and normalize IOC values
- [x] Deduplicate by `(type, value)`
- [x] Merge source information
- [x] Compose normalization and deduplication into a processing pipeline
- [ ] Add `IP_PORT`
- [ ] Add URL support
- [ ] Add SHA-1 and MD5 support

### Feed ingestion

- [x] Add local JSON ingestion
- [x] Parse and validate external IOC records
- [x] Add ThreatFox HTTP client
- [x] Add ThreatFox response adapter
- [x] Read ThreatFox authentication from the environment
- [x] Add a ThreatFox orchestration layer
- [x] Validate live ThreatFox ingestion
- [x] Deduplicate IOCs across heterogeneous sources
- [ ] Define a common feed interface
- [ ] Add additional threat-intelligence feeds

### Enrichment and analysis

- [ ] Define an enrichment interface
- [ ] Add contextual metadata to IOCs
- [ ] Preserve provenance of enrichment data
- [ ] Add timestamps and freshness handling
- [ ] Add basic confidence / scoring concepts
- [ ] Filter by IOC type and source
- [ ] Search by value

### Persistence and output

- [ ] Export normalized IOCs
- [ ] Add JSON output
- [ ] Add CSV output
- [ ] Add lightweight persistence
- [ ] Preserve source and enrichment metadata

### CLI and usability

- [x] Process local JSON IOC files from the CLI
- [x] Display processing statistics
- [ ] Add ThreatFox as a CLI-selectable source
- [ ] Add feed selection
- [ ] Add filtering options
- [ ] Add machine-readable output modes
- [ ] Improve user-facing error reporting

### Engineering quality

- [x] Unit tests for core components
- [x] Integration and end-to-end tests
- [x] Mocked HTTP tests without external network dependencies
- [x] Tests for configuration and failure propagation
- [ ] Add static analysis / linting
- [ ] Add type checking
- [ ] Add CI with GitHub Actions
- [ ] Add structured logging
- [ ] Document architecture decisions
- [ ] Add performance benchmarks as the pipeline grows

## Design principles

The project is intentionally being built in small steps, with emphasis on:

- clear data models;
- explicit provenance of threat-intelligence data;
- deterministic and testable transformations;
- separation between source-specific ingestion and source-independent processing;
- isolation of external services behind small clients and adapters;
- explicit network timeouts and predictable failure behavior;
- secrets kept outside source code and Git history;
- readable Python rather than unnecessary abstraction;
- incremental evolution toward a realistic threat-intelligence workflow.

## Why this project

Threat-intelligence systems often need to combine indicators from heterogeneous sources while retaining enough context to reason about where the data came from, whether multiple sources agree, and how fresh or trustworthy an observation is.

This repository explores those problems through a progressively more realistic Python implementation, with a focus on software-engineering fundamentals, networked services, testability, and security-oriented data processing.
