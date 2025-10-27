# Getting Started with SeaBee

Do all of the following steps in order to make sure SeaBee is correctly installed on your system

## Is Your Linux Supported?

See the [system requirements](./requirements.md) to check if SeaBee will run in your environment.

## Installing SeaBee

Since SeaBee is not distributed as a binary, you will have to build it from source.

On a new system, you may need to install `git` and `make` manually with your package manager

* Clone this repository with `git`
* Change into the directory `cd seabee`
* Install the dependencies with `make update`
  * This should take a few minutes to run
* Reload shell `source ~/.bashrc`

## Compile SeaBee

* To compile the debug version: `make all`
* To compile the release version: `make release`

Troubleshooting

* `make: cargo: No such file or directory`
  * you forgot to `source ~/.bashrc`
* Build errors or missing dependencies
  * something probably went wrong in the install script. Try re-running the install script
* [Full Troubleshooting Docs](./troubleshooting.md)

If errors persist, make an issue on our GitHub.

## Install binaries

* Use `make install` to install compiled binaries to `/usr/sbin`

## Create a SeaBee Root Key

SeaBee requires a root key in order to run.
If no root key is installed, SeaBee will fail to run.
This key is used to turn off SeaBee and optionally to verify the keys used to add SeaBee policies (if `--verify-keys` is enabled)

Read more here: [Cryptography in SeaBee](./crypto.md)

The following commands require openssl installed on the system, the best way to do that is with your package manager (`apt` or `dnf`)

* Use `make gen-root-key` to generate an encrypted RSA key pair for SeaBee
  * In production, it would be better to store the root private key on a separate secure system
  * if you are only using SeaBee experimentally, use `make gen-root-key-ci` to generate an unencrypted root key
* Use `make install-root-key` to copy the resulting public key to `/etc/seabee/seabee_root_key.pem`

## Run SeaBee Test Cases to Verify Functionality

Before running tests make you completed

* running `make install`
* creating a root key

run full test suite: `make test`

If the tests fail, see if there is an open GitHub issue regarding that error message.
If not, please create one!

## Run SeaBee in Terminal

* make sure you've compiled: `make all`
* `sudo target/debug/seabee -s allow`
* You should get an `Error reading from keylist` since you haven't added any keys yet!

we highly recommend running with options during testing/experimentation to prevent needing to reboot the machine in order to stop the program.
This may occur because the program is designed to be difficult to remove, even in the presence of a malicious superuser.

* `-s allow` allow killing the program with ctrl+c (sigint)
* `-p allow` allows removing the pinned programs from the bpf filesystem which effectively stops the program.
  * remove pins with `sudo rm -r /sys/fs/bpf/seabee`

## Run SeaBee as a Daemon

* To launch the daemon with release version: `make run`
* To install the daemon to run on next boot: `make enable`
* can currently be reversed with `sudo systemctl disable seabee.service`

To turn off Seabee, see [seabeectl shutdown](./seabeectl.md#seabeectl-shutdown)

NOTE: after running the test cases, you can use the `test_seabee` daemon:

* `sudo systemctl start test_seabee`
* `sudo systemctl status test_seabee`
* `sudo systemctl stop test_seabee`

## SeaBee Tutorial

Great! You're all ready to go.

We highly recommend you start with the [SeaBee tutorial](./tutorial.md) if you are unfamiliar with SeaBee.
