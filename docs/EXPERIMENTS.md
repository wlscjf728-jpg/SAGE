# Experiments

From the repository root:

```sh
python3 scripts/reproduce.py
# Keep a separate run:
python3 scripts/reproduce.py --output-dir results/my-run
```

The launcher runs eight unit checks, parses the hybrid experiment output, and requires ten successful trials in each of five configurations. The base seed is 20260625; per-configuration offsets are in `tests/test_hybrid.cpp`.

| Output | Contents |
|---|---|
| `unit_tests_and_build.txt` | Build output and unit-test results |
| `hybrid_output.txt` | Complete hybrid stdout |
| `trials.csv` | Trial status, query budget, candidate sizes, search-space bits and DFS count |
| `summary.csv` | Per-configuration recovery and search statistics |

A captured run is included in `evidence/reproduced/`. Normal runs write to ignored `results/` directories.

## Configurations and observations

The five configurations are full visibility with K=4, full visibility with K=8, Bernoulli 50% visibility with K=8, 1% signature noise with K=8, and sixteen informative observations with K=12. Noise matching uses Hamming-distance tolerance one. Each configuration uses ten randomly generated keys with fixed seed sequences.

The captured run recovered all fifty keys. Mean search-space bits were approximately 10.9844, 0, 0, 4 and 8.7189 respectively. These describe the packaged configuration, not every possible parameter setting.

## Exploring the code

- `tests/test_hybrid.cpp`: differences, visibility/noise, observation selection, matching and DFS.
- `tests/test_main.cpp`: AES known-answer checks and signature properties.
- `src/aes128.cpp`: AES and subround checkpoints.
- `src/main.cpp`: auxiliary signature-sweep driver, separate from the five-condition experiment.

Increasing K can reduce candidate collisions while increasing acquisition cost. Missing byte-group coverage can leave key bytes unconstrained; the sixteen-tap fixture deliberately supplies informative coverage.

For a new experiment, change the hybrid settings or add another driver while retaining explicit assumptions. If you change the number of configurations/trials, update the launcher's validation too.
