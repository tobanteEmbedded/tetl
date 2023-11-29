import subprocess
import json
import os
import sys

cxx17_headers = [
    'algorithm',
    'array',
    'bitset',
    'cassert',
    'cctype',
    'cfloat',
    'charconv',
    'chrono',
    'climits',
    'cmath',
    'complex',
    'cstdarg',
    'cstddef',
    'cstdint',
    'cstdio',
    'cstdlib',
    'cstring',
    'ctime',
    'cwchar',
    'cwctype',
    'exception',
    'functional',
    'ios',
    'iterator',
    'limits',
    'memory',
    'mutex',
    'new',
    'numbers',
    'numeric',
    'optional',
    'random',
    'ratio',
    'set',
    'span',
    'stack',
    'stdexcept',
    'string',
    'string_view',
    'system_error',
    'tuple',
    'type_traits',
    'utility',
    'variant',
    'vector',
    'version',
]

cxx20_headers = [
    'bit',
    'compare',
    'concepts',
    # 'coroutine',
    # 'format',
    'ranges',
    # 'source_location',
]

cxx23_headers = [
    'expected',
    'scope',
    'simd',
]


def delete_file(path: str):
    if os.path.exists(path):
        os.remove(path)


def write_benchmark_file(name: str, content: str):
    with open(f'{name}.cpp', 'w') as f:
        f.write(content)


def make_hpp(name: str, use_std: bool):
    include = f'<{name}>' if use_std else f'<etl/{name}.hpp>'
    return f'#include {include}'


def total_source_time(trace):
    for event in trace['traceEvents']:
        if event['name'] == 'Total Source':
            return event['args']['avg ms']


def parse_trace_file(file: str):
    with open(file, 'r') as f:
        data = json.load(f)
        return total_source_time(data)


def execute_compiler(file: str, options, define=None):
    compiler = 'clang++'
    args = [
        compiler,
        '-c',
        '-I',
        '../../include',
        f"-std={options['cxx_version']}",
        f"-{options['optimization']}",
        '-ftime-trace',
        f'{file}.cpp',
    ]

    if define:
        args.append('-D')
        args.append(f'{define}')

    ret = subprocess.run(args, capture_output=True)
    if ret.returncode != 0:
        print(ret.stderr)
        raise Exception('Compilation failed')

    milliseconds = parse_trace_file(f'{file}.json')
    return float(milliseconds)


def run_file(name: str, options, define=None):
    results = []
    for _ in range(3):
        milliseconds = execute_compiler(name, options, define)
        results.append(milliseconds)

    delete_file(f'{name}.o')
    delete_file(f'{name}.json')

    return sum(results) / len(results)


def run_generated(name: str, content: str, options):
    write_benchmark_file(name, content=content)
    result = run_file(name,  options)
    delete_file(f'{name}.cpp')
    return result


def print_header_result(name, result):
    try:
        factor = result['std'] / result['etl']
        millis = result['std'] - result['etl']
        print(f'{name}: {factor:.2f} x faster ({millis:.0f} ms)')
    except Exception as e:
        print(f'{name}: failed with: {e}')


def run_all_benchmarks(cpp_std, o):
    print(f'\nRunning benchmarks with C++{cpp_std} and {o}')
    results = {}
    opt = {'cxx_version': f'c++{cpp_std}', 'optimization': o}

    for cpp in [
        'all_headers.bench',
        'array.bench',
        'string.bench',
        'tuple.bench'
    ]:
        std = run_file(f"{cpp}", opt, define='TETL_BENCH_USE_STD=1')
        etl = run_file(f"{cpp}", opt)
        results[cpp] = {'std': std, 'etl': etl}
        print_header_result(cpp, results[cpp])

    for hpp in cxx17_headers:
        std = run_generated(f"std_{hpp}", make_hpp(f"{hpp}", True), opt)
        etl = run_generated(f"etl_{hpp}", make_hpp(f"{hpp}", False), opt)
        results[hpp] = {'std': std, 'etl': etl}
        print_header_result(hpp, results[hpp])

    if cpp_std in ['20', '2b']:
        for hpp in cxx20_headers:
            std = run_generated(f"std_{hpp}", make_hpp(f"{hpp}", True), opt)
            etl = run_generated(f"etl_{hpp}", make_hpp(f"{hpp}", False), opt)
            results[hpp] = {'std': std, 'etl': etl}
            print_header_result(hpp, results[hpp])


def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} [20,2b]')
        exit(-1)

    valid_cxx_std = ['20', '2b']
    if sys.argv[1] not in valid_cxx_std:
        print(f'Usage: {sys.argv[0]} [20,2b]')
        exit(-1)

    run_all_benchmarks(sys.argv[1], 'O0')
    run_all_benchmarks(sys.argv[1], 'O3')
    run_all_benchmarks(sys.argv[1], 'Oz')


main()
