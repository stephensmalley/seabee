# Getting Started with SeaBee

Do all of the following steps in order to make sure SeaBee is correctly installed on your system

## Is Your Linux Supported?

See the [system requirements](./requirements.md) to check if SeaBee will run in your environment.

## Installing SeaBee from Source

### Clone the Repository and Install Dependencies

On a new system, you may need to install `git` and `make` manually with your package manager

- Clone this repository with `git`
- Change into the directory `cd seabee`
- Install the dependencies with `make update`
  - This should take a few minutes to run
- Reload shell `source ~/.bashrc`

### Compile SeaBee

- To compile the debug version: `make all`
- To compile the release version: `make release`

Troubleshooting

- `make: cargo: No such file or directory`
  - you forgot to `source ~/.bashrc`
- Build errors or missing dependencies
  - something probably went wrong in the install script. Try re-running the install script
- [Full Troubleshooting Docs](./troubleshooting.md)

If errors persist, make an issue on our GitHub.

### Install binaries

Use `make install` to install compiled binaries to `/usr/sbin`

### Create a SeaBee Root Key

SeaBee requires a root key in order to run.
If no root key is installed, SeaBee will fail to run.
This key is used to turn off SeaBee and optionally to verify the keys used to add SeaBee policies (if `--verify-keys` is enabled)

Read more here: [Cryptography in SeaBee](./crypto.md)

The following commands require openssl installed on the system, the best way to do that is with your package manager (`apt` or `dnf`)

- Use `make gen-root-key` to generate an encrypted RSA key pair for SeaBee
  - In production, it would be better to store the root private key on a separate secure system
  - if you are only using SeaBee experimentally, use `make gen-root-key-ci` to generate an unencrypted root key
- Use `make install-root-key` to copy the resulting public key to `/etc/seabee/seabee_root_key.pem`

### Run SeaBee Test Cases to Verify Functionality

Before running tests make you completed

- running `make install`
- creating a root key

run full test suite: `make test`

If the tests fail, see if there is an open GitHub issue regarding that error message.
If not, please create one!

### Run SeaBee in Terminal

- make sure you've compiled: `make all`
- `sudo target/debug/seabee -s allow`
- You should get an `Error reading from keylist` since you haven't added any keys yet!

we highly recommend running with options during testing/experimentation to prevent needing to reboot the machine in order to stop the program.
This may occur because the program is designed to be difficult to remove, even in the presence of a malicious superuser.

- `-s allow` allow killing the program with ctrl+c (sigint)
- `-p allow` allows removing the pinned programs from the bpf filesystem which effectively stops the program.
  - remove pins with `sudo rm -r /sys/fs/bpf/seabee`

### Run SeaBee as a Daemon

- To launch the daemon with release version: `make run`
- To install the daemon to run on next boot: `make enable`
- can currently be reversed with `sudo systemctl disable seabee.service`

To turn off Seabee, see [seabeectl shutdown](./seabeectl.md#seabeectl-shutdown)

NOTE: after running the test cases, you can use the `test_seabee` daemon:

- `sudo systemctl start test_seabee`
- `sudo systemctl status test_seabee`
- `sudo systemctl stop test_seabee`

## Installing SeaBee from Binary

### Choose which kernel

Currently there are 3 precompiled versions of SeaBee.

- ubuntu 24.04 with kernel `6.8.0-86-generic`
- Rocky 9 with kernel `5.14.0-570.55.1.el9_6.x86_64`
- fedora 43 with kernel `6.17.5-300.fc43.x86_64`

If you have a similar kernel, for example, RHEL 9, the rocky build may work for you.
Or for fedora 42, the fedora 43 build may work for you.

Otherwise you should jump to [installing SeaBee from source](#installing-seabee-from-source)

### Run install script

Use the install script to download and install the appropriate binary for your system:

```bash
wget https://raw.githubusercontent.com/nationalsecurityagency/seabee/main/install/install.sh
chmod +x install.sh
sudo ./install.sh # needs an agrument: one of "ubuntu-24", "rocky-9", "fedora-43"
```

### Install a root key

SeaBee needs a root key to run.
See [crypto docs](./crypto.md) for more.

create private rsa key: `openssl genpkey -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-private-key.pem`

create corresponding public rsa key: `openssl pkey -in rsa-private-key.pem -out rsa-public-key.pem -pubout`

Install the public key:

```shell
sudo mkdir /etc/seabee
sudo cp rsa-public-key.pem /etc/seabee/seabee_root_key.pem
```

### Install a SeaBee config

SeaBee has a secure default configuration,
but for testing we are going to enable ctrl+c to easily
kill seabee.
See [config docs](./config.md) for more about seabee configuration.

Create a config to enable ctrl+c for testing: `echo "sigint: true" > config.yaml`

Install config: `sudo seabeectl config update config.yaml`

### Test installation

start up seabee: `systemctl start seabee`

check the logs to see if seabee is working: `journalctl -u seabee --since "5 minutes ago"`

We should not see any errors.
There should be a line reading `INFO Sucessfully loaded eBPF LSM`

Now you can turn off SeaBee" `systemctl stop seabee` and proceed to the tutorial.

If you encounter errors, try building from source or open an [issue on github](https://github.com/NationalSecurityAgency/seabee/issues).

### Uninstall

```bash
wget -qO- https://raw.githubusercontent.com/nationalsecurityagency/seabee/main/install/uninstall.sh | sudo bash
```

## SeaBee Tutorial

Great! You're all ready to go.

We highly recommend you start with the [SeaBee tutorial](./tutorial.md) if you are unfamiliar with SeaBee.
