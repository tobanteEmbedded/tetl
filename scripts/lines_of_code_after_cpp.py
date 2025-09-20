# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
"""Compare the code size of each header vs. the STL after the preprocessor ran.
"""
import subprocess

import matplotlib.pyplot as plt
import pandas as pd


def lines_of_code_after_preprocessor(header: str) -> int:
    cpp_file = './.work/test.cpp'
    with open(cpp_file, 'w') as cpp:
        cpp.write(f'#include <{header}>\n')

    command = [
        '/home/tobante/bin/ATfE-20.1.0-Linux-x86_64/bin/clang++',
        '-stdlib=libc++',
        '--target=armv7m-none-eabi',
        # '-mcpu=cortex-m7',
        # '-mthumb',
        # '-mfloat-abi=hard',
        # '-mfpu=fpv5-d16',
        '-ffreestanding',
        '-std=c++26',
        '-Iinclude',
        '-fno-exceptions',
        '-fno-rtti',
        '-E',
        '-P',
        cpp_file
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr)
        return 0
    return len(result.stdout.splitlines())


def main():
    all_headers = [
        'algorithm',
        'array',
        'bit',
        'bitset',
        'cassert',
        'cctype',
        'cfloat',
        'charconv',
        'chrono',
        'climits',
        'cmath',
        'compare',
        'complex',
        'concepts',
        # 'contracts',
        'coroutine',
        'cstddef',
        'cstdint',
        'cstdio',
        'cstdlib',
        'cstring',
        'ctime',
        'cwchar',
        'cwctype',
        # 'debugging',
        'exception',
        'execution',
        'expected',
        # 'flat_set',
        'functional',
        # 'inplace_vector',
        'ios',
        'iterator',
        'limits',
        # 'linalg',
        # 'mdarray',
        # 'mdspan',
        'memory',
        # 'mpl',
        'mutex',
        'new',
        'numbers',
        'numeric',
        'optional',
        'random',
        'ranges',
        'ratio',
        # 'scope',
        'set',
        'source_location',
        'span',
        'stack',
        'stdexcept',
        'string',
        'string_view',
        # 'strings',
        'system_error',
        'tuple',
        'type_traits',
        'utility',
        'variant',
        'vector',
        # 'version',
    ]

    counts = []
    for header in all_headers:
        print(f'<{header}>')
        std_lines = lines_of_code_after_preprocessor(header)
        etl_lines = lines_of_code_after_preprocessor(f'etl/{header}.hpp')
        counts.append({
            'header': header,
            'std': std_lines,
            'etl': etl_lines,
        })

    df = pd.DataFrame.from_records(counts)
    df['diff'] = df['std']-df['etl']
    df.sort_values(by='diff', ascending=False, inplace=True)
    print(df)

    plt.bar(df['header'], df['diff'])
    plt.grid(which='both')
    plt.show()


if __name__ == "__main__":
    main()
