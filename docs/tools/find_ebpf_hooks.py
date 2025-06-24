#!/usr/bin/env python3
#### DESCRIPTION
# run find-ebpf-hooks.py dir-to-search/ out-filename
#
# this will search the directory and all subdirectories for .bpf.c files and
# create 'out-filename.csv' with the following line format for each hook in each file:
# file/path/to/pogram.bpf.c:line##, hook_type, hook_location
# ex: lippbf-boootstrap/examles/c/bootstrap.bpf.c:25, tp, sched_process_exec
#
##### REQUIREMENTS
#
##### FUTURE WORK
# add support for searching bcc python files with embedded ebpf code

import argparse
import csv
import fnmatch
import os
import re

# Process command line arugment into variables
parser = argparse.ArgumentParser(
    description="Search a directory for eBPF code. Save each eBPF hook as a line in an output csv file."
)
parser.add_argument("dir", help="relative path to the search directory")
parser.add_argument(
    "out",
    nargs="?",
    default="out",
    help="the name of the output file (optional, default=out.csv)",
)
args = parser.parse_args()
dir = args.dir
out = args.out

# Select files to search
bpf_file_list = []
for root, dirs, files in os.walk(dir):
    for f in files:
        if fnmatch.fnmatch(f, "*.bpf.c"):  # we only check .bpf.c files
            bpf_file_list.append(os.path.join(root, f))

# Pull hooks from each file
# A hook looks like: 'SEC(hook_type/hook_location)' or 'SEC(hook_type)'
hook_pattern = re.compile('SEC\("(.*)"\)')
hook_list = []
for file in bpf_file_list:
    with open(file) as f:
        for line_num, line in enumerate(f, start=1):
            if match := hook_pattern.search(line):
                hook = match.group(1).strip()
                # We do not include eBPF maps or license information
                if hook not in ["license", ".maps"]:
                    file_str = "{}:{}".format(file, line_num)
                    hook_parts = hook.split("/", 1)
                    if len(hook_parts) == 2:
                        hook_list.append((file_str, hook_parts[0], hook_parts[1]))
                    else:
                        hook_list.append((file_str, hook, "N/A"))

# Write to output file
with open(out + ".csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerows(hook_list)

print(len(hook_list), "hooks written to " + out + ".csv")
