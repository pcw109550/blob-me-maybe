# Blob Me Maybe

This repository stores CTF challenge `Blob Me Maybe`, which appeared at 2023 [WACON](https://wacon.world/) Finals. You may learn how Ethereum's [EIP-4844](https://www.eip4844.com/) is secure, based on [KZG ceremony](https://ceremony.ethereum.org/).

Category: `Blockchain` + `Crypto`

## Description

$\tau = 13371337$

## Author's Intention

Challenge name/idea inspired by [blob-me-baby](https://github.com/MariusVanDerWijden/blob-me-baby).

EIP-4844 scales Etheurem using [KZG Commitments](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf) and brings blobs. This setup, unfortunately requires toxic waste, $\tau$. If $\tau$ is leaked, anyone can forge KZG commitments. $\tau$ generation is sealed by On-chain KZG Setup Ceremony, which is based on zero knowledge proof. Refer [a16z's tech report](https://github.com/a16z/evm-powers-of-tau/blob/master/techreport/main.pdf) to find out the mathematical details. In short, we are safe($\tau$ is secret to everyone) if any single participant when $\tau$ is generated is honest.

This challenge asks to forge a KZG proof when $\tau$ is leaked. Challenge source is based on [go-kzg-4844], which is a cryptography library that is used in Ethereum execution clients. The challenge implements a simple HTTP server written in Golang, which exposes three APIs:
- `/admin/eval`: Input: $x$. Output: $P(x)$ where $P$ is admin's polynomial.
- `/admin/verify`: Input: $x, P(x)$, proof $\pi$. Output: Boolean where verification succeeded or not based on admin's polynomial.
- `/admin/flag`: Input: $x, z, P(x) \neq z$, proof $\pi$. Output: Boolean where $P(x) \neq z$ and proof $\pi$ is valid.

There were CTF challenges where participants were asked to forge a KZG proof when $\tau$ leaked([ZKCTF 2023 - Loki's Vault](https://github.com/ingonyama-zk/zkctf-2023-writeups/blob/main/loki%27s_vault.md)). However, this challenge is based on the actual codebase that Ethereum uses, [go-kzg-4844]. I authored in this way to ask the participants to see some real-world cryptography libraries, not just distributing sagemath scripts. Also, I believe [Linus' Law](https://en.wikipedia.org/wiki/Linus%27s_law): _given enough eyeballs, all bugs are shallow_. Based on this challenge, Ethereum became more secure because I have made more eyeballs!

[go-kzg-4844]: https://github.com/crate-crypto/go-kzg-4844

### Blobs

Blob is a $4096$ field element over modulo $p$ where $p$ is prime, which are 32 bytes each. Each field is a value of polynomial $P$ evaluation. Let $\omega$ be a nontrival root of equation $x^{4096} = 1 (\mod p)$. The $4096$ field elements are $P(\omega^{i})$, where $i \in [0, 4096)$. Therefore, If we interpolate these points, we recover polynomial $P$. We can store information in $P$'s coefficients and encode them to blobs. The reason why we store points in which $x$ coords are $w^{i}$ is that interpolating via FFT is faster than Lagrange interpolation. Refer [here](https://hackmd.io/@lyronctk/rklKFtDb3) for more mathematical details.

TL, DR: Blob is an encoded polynomial, which holds information big enough to scale Ethereum.

### KZG

The entire blob(an encoded form of polynomial $P$) will be stored on chain in a consensus layer. Execution layer only keeps the KZG commitment $C$ of a blob, which is constant size. The size of a commitment is important because if commitment size is proportional to the origin data, it will become hard to scale. If we want to prove an evaluation $P(x) = y$ on a blob(evaluating polynomials) to the execution layer, we must provide KZG proof to it. If the execution layer has proof $\pi$, commitment $C$, and evaluation $P(x) = y$, the execution layer can verify without needing the entire blob. Refer to Scroll's [KZG in practice article](https://scroll.io/blog/kzg) for mathematical details or check out the [original KZG paper](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf).

TL, DR: KZG is a tool that helps to verify evaluation using proof based on committed information, with no need for the entire information.

### Trusted Setup Initialization

You can create your own trusted setup by selecting your own $\tau$. [Ref](https://github.com/ethereum/consensus-specs/blob/ef434e87165e9a4c82a99f54ffd4974ae113f732/Makefile#L210C1-L210C1) on [consensus-specs](https://github.com/ethereum/consensus-specs). Tweak `--secret` flag in the Makefile,

```Makefile
gen_kzg_setups:
    cd $(SCRIPTS_DIR); \
    if ! test -d venv; then python3 -m venv venv; fi; \
    . venv/bin/activate; \
    pip3 install -r requirements.txt; \
    python3 ./gen_kzg_trusted_setups.py --secret=1337 --g1-length=4 --g2-length=65 --output-dir ${CURRENT_DIR}/presets/minimal/trusted_setups; \
    python3 ./gen_kzg_trusted_setups.py --secret=1337 --g1-length=4096 --g2-length=65 --output-dir ${CURRENT_DIR}/presets/mainnet/trusted_setups
```

I set $\tau=13371337$ for this challenge and gave this info in the challenge description.

## Flag

```
WACON2023{eip4844-fun-with-kzg-and-trusted-setup-ceremony}
```

## Solution

1. Call `/admin/eval` 4096 times to fetch information to extract and interpolate admin's polynomial $P$.
2. Evaluate commitment $C$ based on $P$ and trusted setup.
3. Forge proof $\pi$ based on $z, x, P(x)$ where $P(x) \neq z$, using leaked toxic waste $\tau = 13371337$.
    - $\pi = (C - z * G_{1}) / (\tau - x)$ where $G_{1}$ is the BLS12-381 Generator.
4. Call `/admin/flag` with $\pi, x, z$ and get flag.

## Challenge setup

Deploy [dist](dist) directory as tarball. Includes trusted setup based on $\tau$.

Distribute http endpoint.

## Challenge deploy

Go to [src](src)

```
docker compose build --no-cache
docker compose up -d
```
