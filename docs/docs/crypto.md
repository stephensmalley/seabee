# Cryptography in SeaBee

This document assumes you are running SeaBee with `-v` or `--verify-policy` option enabled.
This option is enabled by default and is the only secure way to use SeaBee. This option enables
signature verification on SeaBee policies, ensuring the authenticity and integrity of requests
to update SeaBee policy. If this option is turned off, SeaBee provides no security guarantees,
but will still verify signatures and report (but not block) on failure.

## Signed Policy Updates

SeaBee uses digital signatures to sign and verify policy updates.
A policy can only be updated when signed with the same key used when the policy was first added.
This ensures that only a user with access to a private signing key should be able to
update the SeaBee policy. This also requires that users add a key to SeaBee before adding a policy
in order for the policy to be verified. [SeaBee's threat model](./threat_model.md) considers a malicious
superuser or comprised process with root privileges in its scope. This means that the
private signing key should exist on a secure system that is separate from the system where SeaBee
 is deployed.

## SeaBee Root Key

SeaBee will require a public verification key on startup. This verification key is known as the
"root key" because it is used to control the administration of SeaBee.

TODO: document use cases for the root key (disable, runtime config change)

If SeaBee runs with the `verify-keys` option, then all keys added to SeaBee must be signed by
this root key. This allows a system administrator to control who can use SeaBee.
The root key cannot be updated during the lifetime of SeaBee, It can only be chagned
while SeaBee is turned off. This remains true even if `verify-keys` is disabled.

If this option is disabled, then anyone can use SeaBee and add keys. This does not
inherently represent an integrity problem since a policy update must be signed with the same
key used to create the policy. However, if anyone is allowed to add keys, it may open the
door for availability attacks. A file or binary cannot be tracked by two different SeaBee
policies ([see policy.md](./policy.md)). This means that errors will occur if two different
entities create conflicting SeaBee policies.

Enabling this option allows control over who is creating SeaBee policies, but also
adds a layer of complexity for using SeaBee since each user will have to obtain a
signature from the root key.

## seabeectl

All updates will happen through the trusted binary `seabeectl`.
If `-v` or `--verify-policy` is enabled in SeaBee's config
(which is the only secure way to use SeaBee), then the following `seabeectl` operations require
signatures:

- Adding a new policy: The policy yaml must be given alongside a valid signature for the file.
- Updating a policy: Update works exactly the same as add, except that the name of the policy
should already exist in SeaBee. In order for an update to be accepted, the version number
must be greater than the current policy version. You can view the current version with
`seabeectl show` or `seabeectl list`.
- Removing a policy: A yaml file called a "remove request" must be passed along with a valid
signature for this file. The "remove request" is a yaml file with only two fields: a name
and a version.
- Removing a key: removing a key requires passing a path to the key file (pem) and a valid
signature for that file. The signature must be verified using the key itself or the SeaBee root key.
Removing a key does not automatically revoke any polices that were signed by that key. Instead,
during reboot, all policies are reloaded and re-verified. The removal of a key
may cause some policies to generate verification errors on reboot. The SeaBee root key cannot
be removed, it can only be changed while SeaBee is turned off.

Additionally, if `--verify-keys` is enabled, the following operations also require a signature

- Adding a key: adding a key requires passing the path of the key file (pem) and a valid
signature for that file signed by the SeaBee root key.

Use `seabeectl alg` to see a list of supported cryptographic algorithms or formats

## Generating a key pair

In production, keys should be generated on a separate system from where SeaBee is deployed.

We recommend using `openssl` to generate keys. SeaBee only uses keys for digital signatures
and verification. SeaBee accepts RSA or ECDSA keys and expects password protected .pem files.

The following instructions are from the [openssl wiki](https://wiki.openssl.org/index.php/Command_Line_Utilities).

generate an RSA private key with passphrase

- `openssl genpkey -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-private-key.pem`

generate an RSA public key

- `openssl pkey -in rsa-private-key.pem -out rsa-public-key.pem -pubout`

generate an ECDSA private key with passphrase using NIST curve `P-256`. See [NIST Recommendations](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf) for ECDSA curves.

- `openssl genpkey -aes256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ecdsa-private-key.pem`

generate an ECDSA public key

- `openssl pkey -in ecdsa-private-key.pem -out ecdsa-public-key.pem -pubout`

## Installing the SeaBee Root Key

TODO: maybe make this a part of seabeectl?

This step must be done before starting up SeaBee or it will generate an error.

`sudo cp ecdsa-public-key.pem /etc/seabee/seabee_root_key.pem`

## Signing a SeaBee Policy

`seabeectl` has a utility for signing SeaBee policies, but it is also possible to use `openssl`.
We will use the ECDSA key from the previous section to do signing. By default, SeaBee expects
the message digest to be `sha3-256`, but any `SHA2` or `SHA3` can be used by specifying it in the policy file
or on the command line using `seabeectl sign -d`

Using `seabeectl`

- `sudo seabeectl sign -t test_policy.yaml -k ecdsa-private-key.pem -o signature.sign`

Using `openssl`

- `openssl dgst -sha3-256 -sign ecdsa-private-key.pem -out signature.sign test_policy.yaml`

## Verifying a SeaBee Policy

SeaBee will verify policies before they are loaded for the first time and whenever SeaBee receives a policy update.
SeaBee will try to verify an update with each of its verification keys (recall that SeaBee is initialized with a
verification key and updates can include additional verification keys). If all of SeaBee's keys fail to verify a policy
update, then the update will be rejected. By default, SeaBee expects signatures to use a `sha3-256` message digest,
but if the policy specifies another digest algorithm, then that algorithm will be used if SeaBee supports it.

Using `openssl` to test verification of policy signatures

- `openssl dgst -sha3-256 -verify ecdsa-public-key.pem -signature signature.sign test_policy.yaml`

Using `seabeectl` to test verification of policy signatures

- `sudo seabeectl verify -t test_policy.yaml -k ecdsa-public-key.pem -s signature.sign`
