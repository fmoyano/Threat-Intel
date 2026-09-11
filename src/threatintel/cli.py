from sys import argv
import argparse

from threatintel.ingest import load_iocs_from_json
from threatintel.pipeline import process_iocs
from threatintel.stats import compute_stats

def main(arguments: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="show-stats")
    parser.add_argument("filename")
    args = parser.parse_args(arguments)

    unprocessed = load_iocs_from_json(args.filename)
    processed = process_iocs(unprocessed)
    stats = compute_stats(unprocessed, processed)

    print(f"Indicators processed: {stats.indicators_processed}")
    print(f"Unique indicators: {stats.unique_indicators}")
    print(f"Duplicates: {stats.duplicates}")
    print("")
    
    for ioc_type in stats.count_by_type:
        print(f"{ioc_type.value}: {stats.count_by_type[ioc_type]}")

if __name__ == "__main__":
    main(argv[1:])