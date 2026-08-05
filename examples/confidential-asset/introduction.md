# Confidential Assets (CA)

## Overview
Confidential Assets (CA) allow token balances and transfer amounts to be stored and transferred on-chain in encrypted form, visible only to authorized parties through decryption, thereby achieving privacy protection.

Applicable scenarios: privacy payments, corporate salary distribution, compliant financial applications, etc. The identities of the sender and receiver remain public, with only the amount kept confidential.

## Functionality
This example demonstrates the following functionalities:
- Minting confidential assets to a user's account.
- Transferring confidential assets between users.
- Viewing confidential asset balances.
- Burning confidential assets from a user's account.

## Testing Confidential Assets Locally

Before getting started, install the Aptos CLI by following the zkMove User Guide.

**Run the unit tests:**

```bash
# From the confidential-asset/on-chain directory
aptos move test --experiments spec-check=off
```

**Build the smart contracts:**

The on-chain contracts use `mock_verify_proof` for local testing. To build against the real verifier, replace all occurrences of `mock_verify_proof` with `verify_proof`, then run:

```bash
# From the confidential-asset/on-chain directory
aptos move build --dev --experiments spec-check=off
```