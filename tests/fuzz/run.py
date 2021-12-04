#!/usr/bin/env python3
import argparse
import logging
import os
import re
import subprocess

from concurrent.futures import ThreadPoolExecutor, as_completed


def job(command):
    """Takes a list of str, and runs it as a subprocess."""
    command_line = " ".join(command)
    logging.debug(f"Running '{command_line}'\n")
    res = subprocess.run(command, check=True, stderr=subprocess.PIPE,
                         universal_newlines=True).stderr
    logging.debug(f"Command '{command_line} output:\n'{res}'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run the fuzz targets a given amount of times, or generate"
                    " new seeds.",
    )
    parser.add_argument(
        "seed_dir",
        help="The parent directory for the seed corpora of each target.",
    )
    parser.add_argument("-g", "--generate", action="store_true")
    parser.add_argument(
        "-j",
        "--par",
        type=int,
        default=1,
        help="How many targets to run in parallel.",
    )
    parser.add_argument(
        "-n",
        "--runs",
        default=100000,
        help="How many times to run each target (if generating).",
    )
    parser.add_argument(
        "-m",
        "--merge_dir",
        default=None,
        help="The parent directory to merge each target corpus from.",
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    target_dir = os.path.abspath(os.path.dirname(__file__))
    targets = [os.path.join(target_dir, f) for f in os.listdir(target_dir)
               if re.compile(r"^fuzz-[\w-]*$").findall(f)]
    with ThreadPoolExecutor(max_workers=args.par) as pool:
        jobs = []
        runs = args.runs if args.generate else 1

        for target in targets:
            seed_dir = os.path.join(args.seed_dir, os.path.basename(target))
            os.makedirs(seed_dir, exist_ok=True)
            command = [
                target,
                f"-runs={runs}" if args.merge_dir is None else "-merge=1",
                seed_dir,
            ]
            if args.merge_dir is not None:
                input_target = os.path.join(args.merge_dir,
                                            os.path.basename(target))
                if not os.path.exists(input_target):
                    continue
                command.append(input_target)
            jobs.append(pool.submit(job, command))

        for completed in as_completed(jobs):
            completed.result()
