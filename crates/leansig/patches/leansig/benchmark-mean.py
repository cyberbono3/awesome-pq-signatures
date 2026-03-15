import os
import json
import argparse
from collections import defaultdict
from tabulate import tabulate  # Install with `pip install tabulate`

def format_time(nanoseconds):
    """
    Convert nanoseconds to the most appropriate time unit.
    """
    if nanoseconds < 1_000:  # Less than 1 microsecond
        return f"{nanoseconds:.2f} ns"
    elif nanoseconds < 1_000_000:  # Less than 1 millisecond
        return f"{nanoseconds / 1_000:.2f} µs"
    elif nanoseconds < 1_000_000_000:  # Less than 1 second
        return f"{nanoseconds / 1_000_000:.2f} ms"
    else:  # 1 second or more
        return f"{nanoseconds / 1_000_000_000:.2f} s"

def extract_data(root_dir, include_intervals=False):
    """
    Traverse the directory structure and collect benchmark data.
    """
    results = defaultdict(dict)  # {benchmark_name: {category: value}}
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file == "estimates.json":
                parts = os.path.normpath(root).split(os.sep)
                if len(parts) >= 3:  # Ensure valid structure
                    benchmark_name = parts[-3]
                    category = parts[-2]

                    file_path = os.path.join(root, file)
                    with open(file_path, "r") as f:
                        data = json.load(f)
                        if "mean" in data:
                            mean_time = format_time(data["mean"]["point_estimate"])
                            if include_intervals and "confidence_interval" in data["mean"]:
                                ci = data["mean"]["confidence_interval"]
                                lower = format_time(ci["lower_bound"])
                                upper = format_time(ci["upper_bound"])
                                results[benchmark_name][category] = f"{mean_time} ({lower} - {upper})"
                            else:
                                results[benchmark_name][category] = mean_time
    return results

def main():
    parser = argparse.ArgumentParser(description="Generate a benchmark report.")
    parser.add_argument("root_dir", type=str, help="Root directory containing benchmarks.")
    parser.add_argument("--intervals", action="store_true", help="Include confidence intervals in the table.")
    args = parser.parse_args()

    # Extract data
    results = extract_data(args.root_dir, include_intervals=args.intervals)

    # Prepare data for tabulation
    benchmarks = sorted(results.keys())
    categories = sorted({cat for bench in results.values() for cat in bench.keys()})
    table_data = [
        [benchmark] + [results[benchmark].get(category, "N/A") for category in categories]
        for benchmark in benchmarks
    ]
    headers = ["Benchmark"] + categories

    # Print the table
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

if __name__ == "__main__":
    main()
