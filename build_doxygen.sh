#!/bin/sh
# This script can be run from a unix shell or git-bash on windows


# CHECK IF DOXYGEN IS INSTALLED
if ! [ -x "$(command -v doxygen)" ]; then
    echo 'Error: doxygen is not installed.' >&2
    exit 1
fi

echo "Cleaning old documentation files"
cd docs
rm -rf doc-build

echo "Running doxygen"
doxygen Doxyfile.in