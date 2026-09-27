#!/usr/bin/env python3
"""Run five SAGE configurations and summarize recovery and search cost."""
import argparse
import csv
import math
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, default=ROOT/'results/reproduced')
    args = parser.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    build = subprocess.run(['make', 'test', 'bin/test_hybrid'], cwd=ROOT, check=True,
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out/'unit_tests_and_build.txt').write_text(build.stdout)
    print(build.stdout, end='')
    result = subprocess.run([str(ROOT/'bin/test_hybrid')], cwd=ROOT, check=True,
                            text=True, capture_output=True, timeout=300)
    (out/'hybrid_output.txt').write_text(result.stdout)
    rows = []
    condition = None
    for line in result.stdout.splitlines():
        heading = re.match(r'--- CONDITION (\d+):', line)
        if heading:
            condition = int(heading[1])
        trial = re.match(r'\s*(\d+)\s*\|\s*(SUCCESS|FAILED)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*([\d.]+) bits\s*\|\s*\[([^]]+)\]', line)
        if trial:
            sizes = [int(n) for n in trial[6].split(',')]
            if len(sizes) != 16 or min(sizes) < 1:
                raise RuntimeError('Malformed byte-candidate sets')
            rows.append(dict(condition=condition, trial=int(trial[1]), status=trial[2],
                             dfs_evaluations=int(trial[3]), differences=int(trial[4]),
                             plaintexts=1+16*int(trial[4]),
                             search_space_bits=sum(math.log2(n) for n in sizes),
                             candidate_sizes=';'.join(map(str,sizes))))
    if len(rows) != 50 or any(r['status'] != 'SUCCESS' for r in rows):
        raise RuntimeError('Expected fifty successful trials; inspect captured log')
    with (out/'trials.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    labels=['full_K4','full_K8','partial_50pct_K8','signature_noise_1pct_K8','selected_16_taps_K12']
    summaries=[]
    for i in range(1,6):
        group=[r for r in rows if r['condition']==i]
        if len(group)!=10 or {r['trial'] for r in group}!=set(range(10)):
            raise RuntimeError('Missing or duplicate trials')
        mean=sum(r['search_space_bits'] for r in group)/10
        maximum=max(r['dfs_evaluations'] for r in group)
        summaries.append(dict(condition=i,label=labels[i-1],trials=10,recovered=10,
                              plaintexts=group[0]['plaintexts'],mean_search_space_bits=mean,
                              max_dfs_evaluations=maximum))
    with (out/'summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(summaries[0])); w.writeheader(); w.writerows(summaries)
    for row in summaries:
        print(f"{row['label']}: 10/10 recovered; search-space bits={row['mean_search_space_bits']:.6f}; "
              f"max DFS={row['max_dfs_evaluations']}")
    print(f'Results written to {out}; see summary.csv and trials.csv.')

if __name__=='__main__':
    main()
