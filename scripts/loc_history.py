# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

"""Plots the lines of code in this repository over time.

Requires scc tool in $PATH, then run:

python scripts/for_each_commit.py https://github.com/tobanteEmbedded/tetl --branch linalg --dest some-scratch-dir/tetl --cmd "scc -f json2 --exclude-dir arm_make -o ../out/{date}-{commit}.json ."
"""

import glob
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def main():
    json_dir = Path(sys.argv[1])
    json_files = [
        Path(f) for f in sorted(glob.glob("*.json", root_dir=json_dir))
    ]

    results = []
    for json_file in json_files:
        with open(json_dir/json_file, 'r') as f:
            content = json.load(f)

        file_sum = 0
        for lang in content['languageSummary']:
            file_sum += lang['Lines']

        date_and_commit = json_file.stem.rsplit('-', 1)
        results.append({
            'date': date_and_commit[0],
            'commit': date_and_commit[1],
            'lines': file_sum,
        })

    df = pd.DataFrame.from_records(results)
    df['date'] = pd.to_datetime(df['date'], utc=True)
    df.to_csv("loc.csv", encoding='utf-8', sep=';', index=False)
    print(df)
    print(df.dtypes)

    plt.plot(df['date'], df['lines'])
    plt.xlabel('Date')
    plt.ylabel('LOC')
    plt.grid(which='both')
    plt.show()


if __name__ == "__main__":
    main()
