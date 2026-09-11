# ThreatIntel

A test-driven Python project for building a threat-intelligence processing pipeline around **Indicators of Compromise (IOCs)**.

The project is under active development. Its goal is to evolve from a simple IOC domain model into a modular pipeline capable of ingesting, normalizing, deduplicating, enriching, filtering, and exporting threat-intelligence data from multiple sources.

## Current status

Implemented so far:

- `IOC` domain model
- `IOCType` enumeration
- Tracking of the sources that reported each IOC
- Validation and normalization of:
  - IPv4 and IPv6 addresses
  - domain names
  - SHA-256 hashes
- Deduplication of IOCs using `(type, value)` as identity
- Merging of source information when duplicate IOCs are found
- Non-destructive transformations: processing does not mutate input IOCs
- Processing pipeline combining normalization and deduplication
- Parsing of external IOC records
- JSON file ingestion
- Processing statistics, including duplicate and per-type counts
- Command-line interface for processing JSON IOC files
- Unit, integration, and end-to-end tests with `pytest`
- Standard `src/` project layout
- Packaging through `pyproject.toml`

## Architecture

The project is being developed incrementally around the following pipeline:

```text
Threat intelligence feeds
          |
          v
      Ingestion
          |
          v
       Parsing
          |
          v
    Normalization
          |
          v
    Deduplication
          |
          v
     Enrichment
          |
          v
 Filtering / Analysis
          |
          v
   Export / Persistence
```

Each stage is kept as independent as practical so that new feeds, enrichment providers, storage backends, or output formats can be added without tightly coupling the whole pipeline.

## Project structure

```text
ThreatIntel/
├── samples/
│   └── iocs.json
├── src/
│   └── threatintel/
│       ├── __init__.py
│       ├── models.py
│       ├── parser.py
│       ├── normalize.py
│       ├── deduplicate.py
│       ├── pipeline.py
│       ├── ingest.py
│       ├── stats.py
│       └── cli.py
├── tests/
│   ├── test_parser.py
│   ├── test_normalize.py
│   ├── test_deduplicate.py
│   ├── test_pipeline.py
│   ├── test_ingest.py
│   ├── test_stats.py
│   ├── test_cli.py
│   └── test_end_to_end.py
├── pyproject.toml
└── README.md
```

## Usage

Install the project in editable mode:

```bash
python -m pip install -e .
```

Run the test suite:
```bash
python -m pytest
```

Process the included sample IOC file:
```bash
python -m threatintel.cli samples/iocs.json
```

Example output:
```
Indicators processed: 4
Unique indicators: 3
Duplicates: 1

ip: 1
domain: 1
sha256: 1
```

## Roadmap

### 1. Core IOC model
- [x] Define IOC types
- [x] Define the IOC data model
- [x] Track IOC sources
- [x] Normalize IOC values
- [x] Validate IOC values
- [x] Deduplicate IOCs
- [x] Merge source information for duplicates
- [x] Compose normalization and deduplication into a processing pipeline

### 2. Feed ingestion
- [ ] Define a common feed interface
- [x] Add local JSON file ingestion
- [x] Parse and validate external IOC records
- [x] Reject malformed or incomplete IOC entries
- [x] Add ingestion tests
- [ ] Add at least one real threat-intelligence feed

### 3. Enrichment
- [ ] Define an enrichment interface
- [ ] Add contextual metadata to IOCs
- [ ] Preserve provenance of enrichment data
- [ ] Handle unavailable or rate-limited enrichment services

### 4. Querying and analysis
- [ ] Filter by IOC type
- [ ] Filter by source
- [ ] Search by value
- [ ] Add basic confidence / scoring concepts
- [ ] Add timestamps and freshness handling

### 5. Persistence and output
- [ ] Export normalized IOCs
- [ ] Add JSON output
- [ ] Add CSV output
- [ ] Evaluate lightweight persistence
- [ ] Preserve source and enrichment metadata

### 6. CLI and usability
- [x] Add a command-line interface
- [x] Process local JSON IOC files from the CLI
- [x] Display processing statistics
- [ ] Allow feed selection from the CLI
- [ ] Add filtering options
- [ ] Add machine-readable output modes
- [ ] Improve error reporting

### 7. Engineering quality
- [x] Unit tests for the initial core
- [x] Integration and end-to-end tests for the current pipeline
- [ ] Increase test coverage as modules are added
- [ ] Add static analysis / linting
- [ ] Add type checking
- [ ] Add CI with GitHub Actions
- [ ] Add structured logging
- [ ] Document architecture decisions


## Design principles

The project is intentionally being built in small steps, with emphasis on:

- clear data models;
- explicit provenance of threat-intelligence data;
- deterministic and testable transformations;
- separation between ingestion, processing, enrichment, and output;
- readable Python rather than unnecessary abstraction;
- incremental evolution toward a realistic threat-intelligence workflow.


## Why this project

Threat-intelligence systems often need to combine indicators from heterogeneous sources while retaining enough context to reason about where the data came from, whether multiple sources agree, and how fresh or trustworthy an observation is.

This repository explores those problems through a progressively more realistic Python implementation, with a focus on software-engineering fundamentals as well as security-oriented data processing.
