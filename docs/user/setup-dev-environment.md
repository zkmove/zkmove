# Set Up the Development Environment

This guide walks you through installing the three CLI tools required to develop with zkMove.

---

## 1. Install the Customized `move` CLI

A customized Move CLI is required to generate witnesses. Install it directly from the zkMove fork:

```shell
cargo install --git https://github.com/zkmove/aptos-core move-cli --branch witnessing
```

---

## 2. Install the `zkmove` CLI

The `zkmove` CLI is the primary tool for zkMove development. It supports proof generation, proof verification, and circuit debugging.

**Steps:**

1. Download the latest release from:
   <https://github.com/zkmove/zkmove/tree/main/release/latest>
2. Extract the archive.
3. Move the binary to your preferred location (e.g., `/usr/local/bin`).
4. Make it executable and verify the installation:

```shell
chmod +x zkmove
zkmove -h
```

---

## 3. Install the Customized `aptos` CLI

A customized build of the Aptos CLI is required. It includes native functions used by the Halo2 on-chain verifier, and is used to interact with the local DevNet, publish contracts, and submit transactions.

**Steps:**

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

## 4. Clone the halo2-verifier.move Repository

The `halo2-verifier.move` repository contains the source code for the on-chain Halo2 verifier. You will need it to publish the verifier contracts.

```shell
git clone git@github.com:zkmove/halo2-verifier.move.git
```
