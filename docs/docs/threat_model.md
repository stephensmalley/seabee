# Threat Model

An important question with any security project is to define the threat model:

> What are we trying to protect from and what are we not trying to protect.

This project aims to protect a userspace process
  and its eBPF programs from anything a privileged user
  can do to interrupt it. Examples include:

* Signals that would kill the userspace program
* Ptrace on the userspace program
* Unauthorized eBPF map access and manipulation
* Deletion of pinned eBPF programs and eBPF maps
* Trusted loading of kernel modules*
