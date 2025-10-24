#!/bin/sh
# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

set -e

export CC="clang-21"
export CXX="clang++-21"

export CXXFLAGS="-march=native"
export CMAKE_BUILD_TYPE="RelWithDebInfo"
export CMAKE_GENERATOR="Ninja"

BUILD_DIR="cmake-build-fuzzing"
BRANCH_COVERAGE=0

rm -rf "$BUILD_DIR"

cmake -S fuzzing -B "$BUILD_DIR" -D CMAKE_CXX_STANDARD=26 -D CMAKE_CXX_SCAN_FOR_MODULES=OFF
cmake --build "$BUILD_DIR"

lcov --gcov-tool ./scripts/llvm-gcov.sh -c -i -d "$BUILD_DIR" --base-directory fuzzing -o "$BUILD_DIR/base_cov.info" --ignore-errors inconsistent --rc branch_coverage=$BRANCH_COVERAGE

ctest --test-dir "$BUILD_DIR" --output-on-failure -j $(nproc)

lcov --gcov-tool ./scripts/llvm-gcov.sh -c -d "$BUILD_DIR" --base-directory fuzzing -o "$BUILD_DIR/fuzz_cov.info" --ignore-errors inconsistent --rc branch_coverage=$BRANCH_COVERAGE
lcov --gcov-tool ./scripts/llvm-gcov.sh -a "$BUILD_DIR/base_cov.info" -a "$BUILD_DIR/fuzz_cov.info" -o "$BUILD_DIR/cov.info" --ignore-errors inconsistent --rc branch_coverage=$BRANCH_COVERAGE
lcov --gcov-tool ./scripts/llvm-gcov.sh --remove "$BUILD_DIR/cov.info" "*fuzzing*" -o "$BUILD_DIR/cov.info" --ignore-errors inconsistent --rc branch_coverage=$BRANCH_COVERAGE
lcov --gcov-tool ./scripts/llvm-gcov.sh --remove "$BUILD_DIR/cov.info" "*clang*" -o "$BUILD_DIR/cov.info" --ignore-errors inconsistent --rc branch_coverage=$BRANCH_COVERAGE
lcov --gcov-tool ./scripts/llvm-gcov.sh --remove "$BUILD_DIR/cov.info" "*c++*" -o "$BUILD_DIR/cov.info" --ignore-errors inconsistent --rc branch_coverage=$BRANCH_COVERAGE

genhtml "$BUILD_DIR/cov.info" --output-directory "$BUILD_DIR/html" --ignore-errors inconsistent --rc genhtml_branch_coverage=$BRANCH_COVERAGE
