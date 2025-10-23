# Folder Map

## `.vscode`

Contains the settings necessary for VSCode extensions and their configurations.

## `bpf`

This crate contains all BPF program code (`.bpf.c` and `.h`) and Rust interfaces
  to interpret the data that comes from them in a ring buffer map.
Utility functions useful for multiple programs should be stored under the
  `bpf/include` folder as a header file.
Do not write any BPF-related code other than BPF skeleton configuration outside
  of this crate.

## `ci`

Contains the configurations necessary to compile, lint, and test the code in a ci.
See its [documentation](ci.md) for more info.

## `docs`

Contains a majority of the high-level documentation for the project.

## `sample_policy`

Contains SeaBee policy examples.

## `scripts`

Contains all of the shell scripts used for installation and configuring.

## `seabee`

Contains all the code specific to the SeaBee program.

## `tests`

Contains all of the code and configurations necessary
  to run integration tests against the code to ensure the capabilities
  and protections offered by SeaBee actually work.
