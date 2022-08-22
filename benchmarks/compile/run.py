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
    'map',
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
    'coroutine',
    'format',
    'ranges',
    'source_location',
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


def make_include(name: str, use_std: bool):
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
    factor = result['std'] / result['etl']
    millis = result['std'] - result['etl']
    print(f'{name}: {factor:.2f} x faster ({millis:.0f} ms)')


def run_all_benchmarks(cpp_std):
    print(f'Running benchmarks with C++{cpp_std}')
    results = {}
    opt = {'cxx_version': f'c++{cpp_std}', 'optimization': 'Oz'}

    for cpp in ['all_headers.bench', 'array.bench', 'tuple.bench']:
        std = run_file(f"{cpp}", opt, define='TETL_BENCH_USE_STD=1')
        etl = run_file(f"{cpp}", opt)
        results[cpp] = {'std': std, 'etl': etl}
        print_header_result(cpp, results[cpp])

    for hpp in cxx17_headers:
        std = run_generated(f"std_{hpp}", make_include(f"{hpp}", True), opt)
        etl = run_generated(f"etl_{hpp}", make_include(f"{hpp}", False), opt)
        results[hpp] = {'std': std, 'etl': etl}
        print_header_result(hpp, results[hpp])


def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} [17,20,2b]')
        exit(-1)
    run_all_benchmarks(sys.argv[1])


main()
