import os

headers = [
    'algorithm',
    'array',
    'bit',
    'bitset',
    # 'cassert',
    'cctype',
    'cfloat',
    'charconv',
    'chrono',
    'climits',
    'cmath',
    'complex',
    'concepts',
    'cstdarg',
    'cstddef',
    'cstdint',
    # 'cstdio',
    'cstdlib',
    'cstring',
    'ctime',
    'cwchar',
    'exception',
    'expected',
    'format',
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
    'ratio',
    'scope',
    'set',
    'source_location',
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
    'warning',

]

for header in headers:
    filenames = []
    for file in os.listdir(f'./etl/_{header}'):
        if file.endswith('.hpp'):
            filenames.append(os.path.join(f'./etl/_{header}', file))

    header_content = ''

    for names in filenames:
        with open(names) as infile:
            header_content += infile.read()

    with open(f'cmake-build-doxygen/pre/{header}.hpp', 'w') as outfile:
        outfile.write(header_content)
        outfile.write('\n')

    bad_words = [
        '#include',
        '_HPP',
        '\\module',
        '\\group',
        '\\exclude',
        '\\complexity',
        '\\requires',
        '\\synopsis',
    ]
    with open(f'cmake-build-doxygen/pre/{header}.hpp') as oldfile, open(f'cmake-build-doxygen/etl/{header}.hpp', 'w') as newfile:
        newfile.write(f'/// \\addtogroup {header}\n///  @{{\n\n')
        for line in oldfile:
            if not any(bad_word in line for bad_word in bad_words):
                newfile.write(line)
        newfile.write('/// @}\n\n')
