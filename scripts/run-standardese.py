#!/usr/bin/env python
import os


def bootstrap_urls():
    with open('./scripts/bootstrap-cdn.txt') as f:
        return f.read()


def replace(filename, old, new):
    # Safely read the input filename using 'with'
    with open(filename) as f:
        s = f.read()
        if old not in s:
            print('"{old}" not found in {filename}.'.format(**locals()))
            return

    # Safely write the changed content, if found in the file
    with open(filename, 'w') as f:
        print(f'Changing {filename}')
        s = s.replace(old, new)
        f.write(s)


def main():
    directory = r'./cmake-build-docs'
    for entry in os.scandir(directory):
        if (entry.path.endswith(".html") and entry.is_file()):
            replace(entry.path, r'<body>', r'<body class="container">')
            replace(entry.path, r'</body>', bootstrap_urls() + r'</body>')
            replace(entry.path, r'standardese-language-cpp',
                    r'standardese-language-cpp language-cpp')


main()
