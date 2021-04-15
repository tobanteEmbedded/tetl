import os


def main():
    directory = r'./cmake-build-docs'
    for entry in os.scandir(directory):
        if entry.path.endswith(".md") and entry.is_file():
            if ("experimental" not in entry.name) and "doc_" in entry.name:
                header = entry.name.replace("doc_", "")
                header = header.replace(".md", "")
                header_tag = f"---\ntitle: \"{header}.hpp\"\n---\n\n"
                with open(entry.path, 'r+') as file:
                    readcontent = file.read()
                    file.seek(0, 0)
                    file.write(header_tag)
                    file.write(readcontent)


main()
