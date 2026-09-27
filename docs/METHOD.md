# Method

## Functional dependence instead of physical labels

Unknown scan ordering removes a register's structural label, but not necessarily its dependence on plaintext and key. SAGE uses that dependence as a label: vary one plaintext byte, group observations that respond, then compare their signatures with AES templates.

The experiment models initial AddRoundKey, first-round SubBytes and first-round ShiftRows. Visible bits have an anonymous permutation that stays fixed throughout a trial. Plaintexts can be chosen, and a plaintext/ciphertext pair is available for final verification.

```text
d(delta) = f(P) XOR f(P with one byte changed by delta)
signature = [d(delta_1), ..., d(delta_K)]
```

With the implementation's all-zero baseline, a SubBytes output follows a bit of `S(k) XOR S(k XOR delta)`. ShiftRows changes position but preserves that byte-local function. Initial AddRoundKey has key-independent differential templates.

## Recovery

1. Collect a baseline and K differences for each of sixteen plaintext bytes.
2. Group active observations by the changed byte.
3. Filter signatures compatible with initial AddRoundKey.
4. Generate eight S-box output-bit templates for each candidate byte value and test consistent assignments.
5. Enumerate combinations from the sixteen candidate sets and verify full keys with AES.

The matching code permits two observations per S-box-bit template, accounting for corresponding SubBytes and ShiftRows bits. Hamming-distance tolerance supports approximate matching.

## Measurements

- **Plaintexts:** logical acquisition budget `1 + 16K`, not scan-clock count.
- **Candidate sizes:** surviving values for each key byte.
- **Search-space bits:** `sum(log2(candidate_count[j]))`, the logarithm of the Cartesian search-space size, not a probabilistically estimated entropy.
- **DFS evaluations:** complete keys tested before the verifier accepts one.
- **Recovery:** recovered key checked against the generated test key.

## Observation assumptions

The generator knows the simulated state to construct observations. The sparse fixture uses that state to select one informative SubBytes/ShiftRows tap per byte-dependency group before anonymizing it. This evaluates recovery given coverage, not blind physical tap selection.

At 50% visibility, bits are retained independently with probability 0.5; the count need not be exactly 192. In the noise experiment, signature bits are flipped after noiseless activity classification. Acquisition/grouping errors are not separately modeled.

The implementation studies the inference mechanism; physical scan insertion, trace capture, and general multiround leakage are not included.
