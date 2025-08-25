# SeaBee

SeaBee is a stylized acronym for "Security Enhanced Architecture for eBPF".

SeaBee is a framework for hardening other eBPF security tools against intervention by
privileged users. For example, eBPF maps can be written to by any privileged user which
might make it easy to disrupt security policy or configuration of an eBPF security tool.
SeaBee allows an administrator to enforce policies controlling who has access to eBPF
tools on a system based on private keys. This makes it harder for an attacker to compromise
or subvert security controls implemented in eBPF.

For an overview, see our [presentation about SeaBee](https://www.youtube.com/watch?v=4bWpTKK7Mlw) at the [2025 Linux Security Summit NA](https://events.linuxfoundation.org/linux-security-summit-north-america/)

See our guide to [Getting Started with SeaBee](./docs/docs/getting_started.md)

Then try our [tutorial](./docs/docs/tutorial.md)

Don't hesidate to create an issue or a PR! See [CONTRIBUTING.md](./CONTRIBUTING.md)

Warning: this project is still under active development, it is not yet ready for production use.

## Documentation

Documentation is found under `docs/docs/`

* To build the documentation:
  * Reload the shell `source ~/.bashrc`
  * `make docs` and then `make -C docs build`
* To view the documentation in a browser: `make -C docs serve-build`

## Disclaimer of Endorsement

Nothing in this Work is intended to constitute an endorsement, explicit or implied,
by the United States Government of any particular manufacturer's product or service.

Any reference made herein by the United States Government to any specific commercial
product, process, or service by trade name, trademark, manufacturer, or otherwise,
in this Work does not constitute an endorsement, recommendation, or favoring by the
United States Government and shall not be construed as a reference for advertising
or product endorsement purposes.
