# Set Up the Development Environment

This guide walks you through installing the CLI tools required to develop with zkMove.

---

## 1. Install the `zkmove` CLI

The `zkmove` CLI is the primary tool for zkMove development. It supports proof generation, proof verification, and circuit debugging.

```shell
cargo install --git https://github.com/zkmove/zkmove.git --branch main zkmove-cli
```

---

## 2. Install the Customized `aptos`  or `sui` CLI
A customized build of the Aptos or Sui CLI is required. It includes native functions used by the Halo2 on-chain verifier, and is used to interact with the local DevNet, publish contracts, and submit transactions.

### 3.1 Install `aptos` CLI

1. Download the release from:
   <https://github.com/zkmove/aptos-core/releases/download/aptos-cli-v7.11.1-zkmove>

   > On macOS, the file is named `aptos-cli-<version>-macOS-arm64.zip`. Choose the correct architecture (`x86_64` or `arm64`).

2. Extract the archive and move the binary to your preferred location.
3. Make it executable:

```shell
chmod +x ~/aptos
```

4. Verify the installation:

```shell
~/aptos help
```

### 3.2 Install `sui` CLI

Install the zkMove Sui CLI with the following command. An upstream Sui release
binary is not sufficient for the Sui verifier flow because it does not include
the `sui::halo2_kzg` native verifier module used by `verifier_api`.

```shell
cargo install --git https://github.com/zkmove/sui.git --branch main sui --locked
```

`cargo install` places the `sui` binary under `~/.cargo/bin`. Add that
directory to your `PATH` so the Sui deployment and verification guides can call
`sui` directly:

```shell
export PATH="$HOME/.cargo/bin:$PATH"
```

To make this persistent for new terminal sessions, add the same line to your
shell profile. For macOS with `zsh`:

```shell
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Verify that the customized `sui` CLI is available:

```shell
command -v sui
sui --version
```

## 3. Clone the halo2-verifier.move Repository

The `halo2-verifier.move` repository contains the source code for the on-chain Halo2 verifier. You will need it to publish the verifier contracts.

```shell
git clone git@github.com:zkmove/halo2-verifier.move.git
```
