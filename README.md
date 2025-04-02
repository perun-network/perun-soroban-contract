<h1 align="center">
    <a href="https://perun.network/"><img src=".assets/go-perun.png" alt="Perun" width="30%"></a>
</h1>

<h2 align="center">Perun Soroban Contract </h2>

<p align="center">
  <a href="https://www.apache.org/licenses/LICENSE-2.0.txt"><img src="https://img.shields.io/badge/license-Apache%202-blue" alt="License: Apache 2.0"></a>
</p>

## Overview
Perun's Generalized State Channels Framework uses a set of interconnected smart contracts to define the on-chain logic for channel deposits, disputes, settlements and withdrawals.
For more detailed information, check out the [documentation](https://labs.hyperledger.org/perun-doc/index.html).

# [Perun](https://perun.network/) Soroban Contract
This repository contains the [Soroban](https://soroban.stellar.org/docs) smart contracts for [go-perun](https://github.com/hyperledger-labs/go-perun)'s [Stellar Backend](https://github.com/perun-network/perun-stellar-backend).
Additionally, it allows cross-contract swaps with the [Ethereum Contract](https://github.com/hyperledger-labs/perun-eth-contracts) by leveraging ethereum specific cryptographic schemes to validate the Perun Channels.

Build contract:

``` sh
cargo build
```

Run tests:

``` sh
cargo test
```

To use this Payment Channel contract on the Stellar blockchain, you also need to use our [Perun Stellar Backend](https://github.com/perun-network/perun-stellar-backend).

# Copyright

Copyright 2024 PolyCrypt GmbH. Use of the source code is governed by the Apache 2.0 license that can be found in the [LICENSE file](LICENSE).
