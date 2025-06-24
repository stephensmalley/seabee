# Threat Model

An important question with any security project is to define the threat model:

> What are we trying to protect from and what are we not trying to protect.

This project aims to protect a userspace process
  and its eBPF programs from a variety of attacks:

* Signals that would kill the userspace program
* Ptracing the userspace program
* Unauthorized eBPF map access and manipulation
* Deletion of pinned eBPF programs and eBPF maps
* Trusted loading of kernel modules*

Some attack types are currently outside the scope of this project:

* Disabling systemd service at boot:
  * `sudo systemctl disable seabee && sudo reboot`
* Disabling the BPF LSM module at boot:
  * GRUB modification
  * Kernel command-line modification
