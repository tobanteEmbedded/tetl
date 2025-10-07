# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

"""Plots the lines of code in this repository over time.

Requires scc tool in $PATH, then run:

mkdir -p some-scratch-dir/out
python scripts/for_each_commit.py https://github.com/tobanteEmbedded/tetl --branch main --dest some-scratch-dir/tetl --cmd "scc -f json2 --exclude-dir arm_make -o ../out/{date}-{commit}.json ."
python scripts/loc_history.py some-scratch-dir/out
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

        total_lines = 0
        code_lines = 0
        comment_lines = 0
        blank_lines = 0
        for lang in content['languageSummary']:
            total_lines += lang['Lines']
            code_lines += lang['Code']
            comment_lines += lang['Comment']
            blank_lines += lang['Blank']

        date_and_commit = json_file.stem.rsplit('-', 1)
        results.append({
            'date': date_and_commit[0],
            'commit': date_and_commit[1],
            'total': total_lines,
            'code': code_lines,
            'comment': comment_lines,
            'blank': blank_lines,
        })

    df = pd.DataFrame.from_records(results)
    df['date'] = pd.to_datetime(df['date'], utc=True)
    df['delta'] = df['total'].diff()
    print(df)
    print(df.dtypes)

    plt.plot(df['date'], df['total'], label='Total')
    plt.plot(df['date'], df['code'], label='Code')
    plt.plot(df['date'], df['comment'], label='Comment')
    plt.plot(df['date'], df['blank'], label='Blank')
    plt.xlabel('Date')
    plt.ylabel('LOC')
    plt.grid(which='both')
    plt.legend()
    plt.show()


if __name__ == "__main__":
    main()
