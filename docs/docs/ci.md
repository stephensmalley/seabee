# GitLab Continuous Integration Workflow

Disclaimer: these notes primarily apply to GitLab. Since the project has
moved to GitHub, there have been substantial changes.

This guide explains the thoughts and considerations behind why the CI/CD
  pipeline is setup the way it is.

## Linting & Formatting

This is primarily provided by [MegaLinter](https://megalinter.io).

Rust's [`clippy`](https://github.com/rust-lang/rust-clippy) is supported by MegaLinter,
  but the current project requires system dependencies in order to compile
  the eBPF bytecode to embed inside the Rust code (see `build.rs`).
This requires using a separate VM or container which has these dependencies.

Rust's built-in formatter `cargo fmt` is not available in MegaLinter and is
  therefore ran separately to check for style inconsistencies in `.rs` files.

## Testing

To run eBPF programs and the tests against them,
  we need a sufficiently new enough kernel that has all of the features (v5.14+).

To run a new enough kernel for a CI job (container or not),
  we must provide our own VM for GitLab to run the job on.

To run our own VM with the latest kernel,
  we cannot deploy on EC2 due to the limited AMI options.

To this end, [Terraform](https://terraform.io) is utilized to programmatically create
  a VM on our own hardware through libvirt/QEMU and install the
  [GitLab Runner](https://docs.gitlab.com/runner/) to accept and run jobs.
Terraform by itself simply interacts with infrastructure providers to provision VMs.

It is generally not recommended to allow GitLab CI jobs to change the state of the
  underlying system that is running the GitLab Runner process.
As a result,
  Docker or Kubernetes is often used to run the job in a containerized environment.
However, official Docker container providers (Ubuntu, Fedora, etc.) do not have the
  project's system dependencies installed and have to be installed on each run.
In order to not incur this overhead, a custom container image can be created.
In our case, a custom Dockerfile can be used.

## Docker Image

The `ci` folder contains Dockerfiles which will install all of the
  dependencies necessary to compile, format, and document the Rust
  code.

These images should be built manually on your development workstation
  and then uploaded to your Docker registry server under the name `build`.

```bash
docker build -t build -f ci/Dockerfile .
```

**NOTE** - If you are using a Docker mirror for base images, you need to use the
  `--build-arg DOCKER_MIRROR=<url>` syntax to set it with a `/` at the end

```bash
docker build -t build -f ci/Dockerfile --build-arg DOCKER_MIRROR=your.docker.mirror:1234/ .
```

## GitLab CI Variables

The following variables need to be set for the full CI pipeline to work

### DOCKER_MIRROR

**Optional** if you are using a Docker mirror to cache images.

### EDIT_URI

The URI to use for generating direct links to edit the page in the source
  code repository.

### REPO_NAME

The name of the repository to use in the generated documentation.

### REPO_URL

The full URL to the source code repository.

### SITE_URL

The full URL to the GitLab Pages or other static web server that will host
  the compiled documentation.

The default uses the GitLab scheme, but for GitHub it will need to be changed.

## Running

For Terraform, the ideal place to run private VMs are on your own infrastructure.

After logging into your server, install Terraform by following the guide:

- [Terraform Installation](https://developer.hashicorp.com/terraform/install)

```bash
# Check out the Terraform scripts into a new directory
git clone <repo_url>
cd terraform
# Create a GitLab runner for the group if necessary
cd gitlab_runner
terraform init
terraform apply
```

## Destroying

In the same folder that your `*.tfstate` files were created when you ran
  `terraform apply`, you can run `terraform destroy` to have all resources
  Terraform created to be deleted too.
