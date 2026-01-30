#!/bin/sh

# Script to generate test vectors in this repo based on post-quantum-cryptography/KAT (submoduled for convenience)

# Just in case this repo got cloned but without --recurse-submodules.
git submodule sync
git submodule update

go run ./cmd/testvectorconverter --path ./pqc-kat/MLDSA/kat_MLDSA_44_hedged_pure.rsp > ./MLDSA-44.json
go run ./cmd/testvectorconverter --path ./pqc-kat/MLDSA/kat_MLDSA_65_hedged_pure.rsp > ./MLDSA-65.json
go run ./cmd/testvectorconverter --path ./pqc-kat/MLDSA/kat_MLDSA_87_hedged_pure.rsp > ./MLDSA-87.json
