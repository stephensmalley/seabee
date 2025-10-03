# SeaBee Policy

## Security Framework

- SeaBee provides isolation between eBPF applications via policy.
- Policy is defined for an executable or a set of executables (the policy scope)
- SeaBee detects when protected objects are created by a process in the policy
scope and assigns them with the corresponding policy ID including the process itself
- Any executable or process will have access to all protected objects with the same
Policy ID as itself, which indicates that it falls within the same scope.
- A SeaBee policy for an executable must be loaded before that executable starts in order
for SeaBee to associate the exe path with the created process and protect eBPF
objects for that process. When run as a systemd daemon(strongly recommended), SeaBee
must still start before other daemon applications during boot. If an application using
SeaBee starts early during boot, it must ensure that it starts after SeaBee
(or add SeaBee as a dependency).

## Definitions

- Protected Object: anything that SeaBee protects including: processes, eBPF maps, pinned
programs, or specific files.
- Policy ID: Each policy is assigned a Policy ID. The Policy ID is used to identify
protected objects associated with the same policy. All objects in the same policy have
the same Policy ID.
- Action: actions are defined in the policy config. The action determines how a process
not governed by the policy should be allowed to interact with a particular protected object.
The action can be different for each protected object. For example: "maps: audit" would audit,
but allow any external process to access a map that is within the policy scope.
- Policy Config: A list of actions. The policy config determines how processes not governed by
the policy scope can access protected objects within the policy scope. It assigns an Action for
each protected object indicating how the external access should be handled.

## Policy Expressiveness

Think of a SeaBee policy as a list of "deny" or "audit" rules. By default, everything is allowed
(this is the 'policy' if SeaBee is not being used). When a file path for an executable is listed
under the "scope" for a SeaBee policy, the corresponding process is allowed to access any
protected object it creates. The Policy Config determines how every other process not in policy
scope is allowed to access those protected objects within the policy scope.

When answering "Is some process allowed to access some object?", SeaBee considers two things:

1. Does the process have the same Policy ID (scope) as the object?
1. If not, does the policy config for the object's policy have an 'audit' or 'allow' action?
Since these actions grant access to an external process.

Actions in the Policy Config are only granular to the class of protected object not to each
particular object. This means that you cannot have one map that is 'audit' and a different map
that is 'block' for the same policy scope/executable.

## Example Use Case

- A can access all of its objects and none of B's objects.
- B can access all of its objects and none of A's objects.

for testing/debugging, an action could be changed to 'audit' or bpftool could be added to the policy scope

## Policy Anatomy

a policy is a yaml file and has the following keys

### Name

The name of the policy

### Version

The version should be incremented when a policy is updated. The version ensures
that an attacker cannot downgrade the policy to an old version or maliciously update
a policy.

### Scope

- a file path, determines which binaries the policy applies to

### Files

This section determines which files are protected by the policy.
It may be the case that there are repeated files between `scope` and `files`.
This would be the case if you wanted to prevent an executable from being modified
and allow a process created by that executable permissions to access other objects in the policy.

The paths listed in this section can include directories, files, and some other types of linux directory entries.
For each entry SeaBee will attempt to label the underlying inode.
These labels are used to enforce security controls. If the entry is a directory,
SeaBee uses the [walkdir crate](https://docs.rs/walkdir/latest/walkdir/) to recursively iterate through
all subdirectories and label everything in those directories as well.
This directory walk will not follow symlinks.

All of paths you specify must exist when the policy is loaded.
If one of your files does not exist on policy load, then SeaBee will generate an error.
In order to protect files that are created at runtime, the current approach is to
specify a directory and all files/directories created in that directory at runtime will
be protected. If support for protecting files at runtime is important to you, leave a comment
on our GitHub letting us know: [Issue 35](https://github.com/NationalSecurityAgency/seabee/issues/35).

### Config

The policy config determines what protections this policy provides within the `scope`.

config has the following keys:

- map_access: control access to eBPF maps within the scope (allow, audit, block)
- file_write_access: control write access to the files listed in `files` seciton (allow, audit, block)
- pin_access: control access to removing eBPF pins (allow, audit, block)
- signals: control how to enforce the sigmask (allow, audit, block)
- sigmask: determines which signals should be allowed

### Sigmask

The sigmask requires further explanation. The sigmask allows a user to precisly control which signals are allowed
to be sent to a process within scope. To construct a sigmask, you need to first enumerate the codes for each signal
you want to allow. For example, if you want to allow SIGINT, you should get code 2.

The sigmask is a `u64` so it covers all possible signals including RT signals 32 through 64.
The null signal is not part of the standard signal set and there cannot be blocked
We construct the sigmask by taking the code for each signal we want to block, subtracting 1,
and flipping that bit to a 1 `(1<<(CODE-1))`. For SIGINT, we do `(1<<1)` and get `0x2`.

The `0x2` sigmask will allow SIGINT but block all other signals to the process (if `signals` is set to `block`)

Setting `signals: allow` will cause the sigmask to be ignored altogether.

Sigmask can be specified as a hex or a decimal in the policy

We use this sigmask by default for SeaBee: `0x8430000`. This allows all signals that don't kill the process by default.
We generate the sigmask with the following code (from `seabee/src/utils.rs`)

```Rust
/// Generates a [mask](https://en.wikipedia.org/wiki/Mask_(computing))
/// of allowed signals
pub const fn generate_sigmask(sigint: SecurityLevel) -> u64 {
    let mut sigmask: u64 = 0;
    // These signals are those that do not terminate a process by default
    sigmask |= 1 << (Signal::SIGCHLD as u64 - 1);
    sigmask |= 1 << (Signal::SIGCONT as u64 - 1);
    sigmask |= 1 << (Signal::SIGURG as u64 - 1);
    sigmask |= 1 << (Signal::SIGWINCH as u64 - 1);

    if is_sigint_allowed(sigint) {
        sigmask |= 1 << (Signal::SIGINT as u64 - 1);
    }
    sigmask
}
```

## Examples

more test policies can be seen at `tests/policies`

```yaml
name: sample-policy
version: 1
scope:
  - ../usr/sbin/my-ebpf-tool
files:
  - /etc/my-ebpf-tool/
config:
  map_access: block
  file_write_access: block
  pin_access: block
  signals: block
  signal_allow_mask: 0x8430002
```
