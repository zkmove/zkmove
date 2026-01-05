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
Download the Aptos CLI for zkMove from [here](https://github.com/zkmove/aptos-core/releases) and run the following command:
```aptos move test --experiments spec-check=off```