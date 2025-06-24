#!/usr/bin/env python3

# bpf-helper-info.py prints out a list of ebpf-helper functions along with
# the major linux version they first appeared in. Expected usage:
# `bpf-helper-info.py {path_to_linux_kernel_git_checkout}`

import io
import pathlib
import re
import sys

import git
from natsort import natsorted

repo_path = pathlib.Path(sys.argv[1]).resolve()
linux_repo = git.Repo(repo_path)
file_of_interest = "include/uapi/linux/bpf.h"

# examine linux repository references to get list of major version tags
major_version_pattern = re.compile(r"^v\d\.\d{1,2}$")
major_versions = []
for tag in linux_repo.tags:
    if major_version_pattern.match(tag.name):
        major_versions.append(tag.name)

major_versions = natsorted(major_versions)  # fix versions being in alphabetical order

# check out each tagged verions, use regex to get ebpf helpers for each
bpf_helper_regex = re.compile(
    r"^\ \*\ (?:\w*\ ){1,2}\*{0,1}(\w*)\(.*\)+$", re.MULTILINE
)

total_helpers = 0
for old, new in zip(major_versions[:-1], major_versions[1:]):
    helper_additions = []
    # expecting versions that don't have the bpf.h file; just move on in that case
    try:
        earlier = linux_repo.commit(old)
        newer = linux_repo.commit(new)
        earlier_file = earlier.tree / file_of_interest
        newer_file = newer.tree / file_of_interest
    except Exception:
        print("{} doesn't appear in {}".format(file_of_interest, old))
        continue

    with io.BytesIO(earlier_file.data_stream.read()) as f, io.BytesIO(
        newer_file.data_stream.read()
    ) as g:
        funcs_earlier = bpf_helper_regex.findall(f.read().decode("utf-8"))
        funcs_newer = bpf_helper_regex.findall(g.read().decode("utf-8"))

    for func in set(funcs_newer) - set(funcs_earlier):
        helper_additions.append(func)

    if not helper_additions:
        continue

    print(
        "\n\nThe following {} BPF helper functions were added in kernel version {}".format(
            len(helper_additions), new
        )
    )
    print("======================================================================")
    for func in helper_additions:
        print(func)
    total_helpers += len(helper_additions)
print("======================================================================")
print("The current total number of helpers is:", total_helpers)
