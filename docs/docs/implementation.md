# Implementation Notes

## BPF Naming Conventions

The BPF-to-Rust-skeleton compilation uses the name of the `.bpf.c` file
    as the module name and prefixes for module functions.
`my_bpf_program.bpf.c` will be converted into `mod MyBpfProgram;`
  and `MyBpfProgramSkelBuilder` and other `MyBpfProgram...` prefixes.

## Logging

So you've written up a new BPF program, that's great!
Unfortunately, you've been using `bpf_printk` in your code.
While this is nice for quick testing of your prototype,
  it isn't a great long term solution.
We want to have custom logs for your BPF program in a designated location.
However, setting that up takes a couple steps.
Don't worry though, it'll look great when we're done!

### Logging A New BPF Hook

1. Add a new entry to the `log_type` enum in `bpf/include/logging_types.h`.
   This allows translation between the C log structs and the generated Rust log structs.
1. Add a new struct in `bpf/include/logging_types.h` with the
     name `*_log` where `*` is the name of the BPF program.
   This struct describes any contextual info relevant to the hook.
   At a minimum, it should contain the info used to make the access control decision.
1. Create a logging function in `bpf/src/seabee_enforce/self_enforce_log.h`.
   Follow the pattern of the other functions already present.
   Instantiate the struct from step 2 and send it to the ringbuffer.
   Use the `log_type` defined in the first step to aid the C-to-Rust translation.
1. Replace `bpf_printk` calls with the new log function.
   Choose a `reason` and a `level` for each call.
   The `reason` explains why the log is being printed.
   For example, `LOG_REASON_DENY`, suggests that some action was attempted and denied.
   The `level` defines a relative level of importance of the log.
   This allows some customization of how many logs are printed.
   Typically only the most critical logs will be printed,
     but if a problem is being debugged, including less important logs may be helpful.
   In order to differentiate between different reasons and levels,
     code may need to be restructured.
1. Add the struct to the `get_log_struct` function in `bpf/src/logging/mod.rs`.
   Following the pattern of other logs,
     add a case to the match statment and include the new `log_type` enum value and log struct.
   The `ToString` trait must also be implemented to print the log.
   Follow the pattern of other structs in the file.
   Note: The name of the struct and `log_type` need to match in Rust and C,
      otherwise it will fail to compile.

### Logging for a new Skel

Note: SeaBee no longer uses multiple skeletons

- Setup logging in skeleton code (c code)
  - `#include "logging.h"`
  - create a global variable for log level: `u32 log_level;`
  - add the ringbuf: `struct log_ringbuf log_ringbuf SEC(".maps");`
- Setup the userspace code
  - configure skeleton log level: `open_skel.bss_mut().log_level = ...`;
  - configure skeleton ringbuf: `open_skel.maps().log_ringbuf().reuse_fd(<original log ringbuf>.as_fd())?;`
