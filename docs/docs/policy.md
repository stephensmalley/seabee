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

a policy has four parts: scope, config, hash, and signature

### Scope

- a file path, determines which binaries the policy applies to

### Config

- determines what protections this policy provides within the `scope`
- `files` in this section determine how files are protected by the policy
it may be the case that there are repeated files between `scope` and `config`.
This would be the case if you wanted to prevent an executable from being modified
and allow a process created by that executable permissions to access other objects in the policy.

### Version

- the version should be incremented when a policy is updated. The version ensures
that an attacker cannot downgrade the policy to an old version or maliciously update
a policy.

### Examples

test policies can be seen at `tests/policies`
