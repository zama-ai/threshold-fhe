<p align="center">
<!-- product name logo -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/threshold-fhe-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/threshold-fhe-light.png">
  <img width=600 alt="Zama Threshold FHE">
</picture>
</p>

<hr/>

<p align="center">
  <a href="https://eprint.iacr.org/2023/815"> 📃 White Paper</a> | <a href="https://zama.ai/community"> 💛 Community support</a> | <a href="https://github.com/zama-ai/awesome-zama"> 📚 FHE resources by Zama</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSD--3--Clause--Clear-%23ffb243?style=flat-square"></a>
  <a href="https://github.com/zama-ai/bounty-program"><img src="https://img.shields.io/badge/Contribute-Zama%20Bounty%20Program-%23ffd208?style=flat-square"></a>
</p>

## About

### What is it?

This repository provides threshold multi-party computation protocols
such as threshold key generation, threshold decryption
and so on for TFHE, BFV and BGV.
Our protocols are designed to be both secure and robust when a fraction
of the parties are malicious.

This repository is an early sneak peak of what we aim to be part of the submission
for the [NIST call for Multi-Party Threshold Cryptography](https://csrc.nist.gov/projects/threshold-cryptography).

### Main features

- Threshold key generation for the three FHE schemes
- Distributed decryption FHE with two techniques
  - Using noise flooding
  - Using bit decomposition
- Resharing of FHE key shares
- Distributed setup for CRS (common reference string) using in ZK proofs

### Additional resources

- Blog post *TODO link*
- The [Noah's ark](https://eprint.iacr.org/2023/815) paper contains the technical details of our protocols
- An [inital preliminary version of our proposed NIST submission](TechnicalDocumentation/CryptographicDocumentation.pdf), which contains the detailed specification

## How to use this repository

> [!Important]
> **threshold-fhe** is a snapshot of the work-in-progress code of what will eventually become a NIST submission. Use at your own risk!

The main way to use the repository is to run experiments and benchmarks on the various threshold protocols,
which we describe in detail in the file [threshold-benchmark.md](threshold-benchmark.md).
It is also possible to use the the repository as a library (see the example in `examples/distributed_decryption.rs`),
but the public API is not documented so use your own discretion.

