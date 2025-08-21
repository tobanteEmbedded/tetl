"""List all files that only have #include's and no import statements.
"""

import os

def check_files(root_dir: str) -> None:
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.lower().endswith('.cpp'):
                file_path = os.path.join(dirpath, filename)
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                if '#include <etl' in content and 'import ' not in content:
                    print(file_path)

if __name__ == "__main__":
    project_dir = "tests"
    check_files(project_dir)
