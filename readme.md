# ML-DSA Test Vectors

I found that in my own testing, I need ML-DSA test vectors with the following combination:

- Private key (as a **seed**)
- Randomness provided
- External µ provided

I have created these test vectors based on:

- https://github.com/post-quantum-cryptography/KAT (which contains test vectors with keys-as-seeds and given randomness)
- https://github.com/nsmithuk/ml-dsa (which implements support for External Mu to check my µ math)

as a first-pass consistency check. They are not intended to be a substitute for
[CAVP](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigGen-FIPS204),
or [CCTV](https://github.com/C2SP/CCTV), or
[Wycheproof](https://github.com/C2SP/wycheproof/tree/main/testvectors_v1),
which are actively maintained and include carefully considered edge cases.
