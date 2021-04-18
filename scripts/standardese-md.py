#!/usr/bin/env python

import os


def add_header(entry):
    if ("experimental" not in entry.name) and "doc_" in entry.name:
        header = entry.name.replace("doc_", "")
        header = header.replace(".md", "")
        header_tag = f"---\ntitle: \"{header}.hpp\"\n---\n\n"
        with open(entry.path, 'r+') as file:
            readcontent = file.read()
            file.seek(0, 0)
            file.write(header_tag)
            file.write(readcontent)


def remove_newlines(entry):
    remove_indices = []
    lines = []
    with open(entry.path, "r") as f:
        lines = f.readlines()
        for id in range(len(lines)):
            if lines[id].startswith('#include') and lines[id-1] == '\n':
                remove_indices.append(id-1)
            if 'using ' in lines[id] and lines[id-1] == '\n':
                remove_indices.append(id-1)

    lines = [i for j, i in enumerate(lines) if j not in remove_indices]

    with open(entry.path, "w") as f:
        for line in lines:
            f.write(line)


def main():
    directory = r'./cmake-build-docs'
    for entry in os.scandir(directory):
        if entry.path.endswith(".md") and entry.is_file():
            add_header(entry)
            remove_newlines(entry)


main()
