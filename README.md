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
  <a href="https://zama.ai/community"> 💛 Community support</a> | <a href="https://github.com/zama-ai/awesome-zama"> 📚 FHE resources by Zama</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSD--3--Clause--Clear-%23ffb243?style=flat-square"></a>
  <a href="https://github.com/zama-ai/bounty-program"><img src="https://img.shields.io/badge/Contribute-Zama%20Bounty%20Program-%23ffd208?style=flat-square"></a>
</p>

## About

### What is it?

This repository provides threshold multi-party computation protocols
such as threshold key generation and threshold decryption for TFHE, BFV and BGV.
Our protocols are designed to be both secure and robust when a fraction
of the parties are malicious.

This repository is an early sneak peak of what we aim to be part of our submission
for the [NIST call for Multi-Party Threshold Cryptography](https://csrc.nist.gov/projects/threshold-cryptography).
It is also a preview of a part of a larger repository that we'll release later, where we open-source our HTTPZ key management system.

### Main features

- Threshold key generation for the three FHE schemes
- Distributed decryption for FHE ciphertexts with two techniques:
  - Using noise flooding (section 2.2.1 of the [spec](docs/CryptographicDocumentation.pdf))
  - Using bit decomposition (section 2.2.2 of the [spec](docs/CryptographicDocumentation.pdf))
- Resharing of FHE key shares
- Distributed setup for CRS (common reference string) using in ZK proofs

## Getting Started

### Requirements

See the [requirements](docs/threshold-benchmark.md#prerequisites-for-running-benchmarks) for the benchmarks.

### A simple example

> [!Important]
> **threshold-fhe** is a snapshot of the work-in-progress code of what will eventually become a NIST submission. Use at your own risk!

The main way to use the repository is to run experiments and benchmarks on the various threshold protocols, which we describe in detail in the file [docs/threshold-benchmark.md](docs/threshold-benchmark.md).
It is also possible to use the the repository as a library (see the example in [examples/distributed_decryption.rs](examples/distributed_decryption.rs), but the public API is not well-documented yet, so use your own discretion.


To start the benchmarked system `moby` in a dockerized environment locally with 4 parties and threshold 1:
```{bash}
$ cargo make tfhe-docker-image
$ cargo make tfhe-bench-run
```

You can then start interacting with it via the `mobygo` cli.
- Initiate an __insecure__ Key Generation
```{bash}
$ cargo run --bin mobygo --features="choreographer" -- -c temp/tfhe-bench-run.toml threshold-key-gen-result --sid 1  --storage-path temp --generate-params bc-params-sam-sns
```

- Initialize PRSS (one time setup)
```{bash}
$ cargo run --bin mobygo --features="choreographer" -- -c temp/tfhe-bench-run.toml prss-init --ring residue-poly-z128 --sid 2
```

- Perform 10 distributed decryptions
```{bash}
# Prepare correlated randomness
$ cargo run --bin mobygo --features="choreographer" -- -c temp/tfhe-bench-run.toml preproc-decrypt --decryption-mode noise-flood-small --path-pubkey temp/pk.bin --tfhe-type u16 --num-ctxts 10 --sid 3

# Perform online phase
$ cargo run --bin mobygo --features="choreographer" -- -c temp/tfhe-bench-run.toml threshold-decrypt --decryption-mode noise-flood-small --path-pubkey temp/pk.bin --tfhe-type u16 --num-ctxts 10 --sid 4  --preproc-sid 3

# Check the status
$ cargo run --bin mobygo --features="choreographer" -- -c temp/tfhe-bench-run.toml status-check --sid 4  --keep-retry true

# Fetch the result
$ cargo run --bin mobygo --features="choreographer" -- -c temp/tfhe-bench-run.toml threshold-decrypt-result --sid 4
```

### Resources

- Blog post *TODO link*
- The [Noah's ark](https://eprint.iacr.org/2023/815) paper contains the technical details of some of our protocols
- An [initial, preliminary version of our proposed NIST submission](docs/CryptographicDocumentation.pdf), which contains the detailed specification of all contained protocols

### Documentation

Documentation is current limited to the [docs](./docs/) repository. It will be extended when we open-source our larger repositoru.

## Working with threshold-fhe

### Citations

To cite threshold-fhe in academic papers, please use the following entry:

```text
@Misc{ZamaThresholdFHE,
  title={threshold-fhe: Threshold MPC protocols for FHE},
  author={Zama},
  year={2025},
  note={\url{https://github.com/zama-ai/threshold-fhe}},
}
```

### Contributing

This repository is currently not open to external contributions, but we receive feedback as issues or messages (see the [Support](#support) section).<br></br>

### License

This software is distributed under the **BSD-3-Clause-Clear** license. Read [this](LICENSE) for more details.

#### FAQ

**Is Zama’s technology free to use?**

> Zama’s libraries are free to use under the BSD 3-Clause Clear license only for development, research, prototyping, and experimentation purposes. However, for any commercial use of Zama's open source code, companies must purchase Zama’s commercial patent license.
>
> All our work is open source and we strive for full transparency about Zama's IP strategy. To know more about what this means for Zama product users, read about how we monetize our open source products in [this blog post](https://www.zama.ai/post/open-source).

**What do I need to do if I want to use Zama’s technology for commercial purposes?**

> To commercially use Zama’s technology you need to be granted Zama’s patent license. Please contact us at hello@zama.ai for more information.

**Do you file IP on your technology?**

> Yes, all of Zama’s technologies are patented.

**Can you customize a solution for my specific use case?**

> We are open to collaborating and advancing the FHE space with our partners. If you have specific needs, please email us at hello@zama.ai.

## Support

<a target="_blank" href="https://zama.ai/community-channels">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/zama-ai/concrete-ml/assets/157474013/86502167-4ea4-49e9-a881-0cf97d141818">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/zama-ai/concrete-ml/assets/157474013/3dcf41e2-1c00-471b-be53-2c804879b8cb">
  <img alt="Support">
</picture>
</a>

🌟 If you find this project helpful or interesting, please consider giving it a star on GitHub! Your support helps to grow the community and motivates further development.
