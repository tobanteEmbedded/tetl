#!/bin/sh
# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

rm -rf cmake-build-atfe
cmake -S . -B cmake-build-atfe \
    -G Ninja -D CMAKE_BUILD_TYPE=Release \
    --toolchain cmake/toolchain/arm-atfe.cmake \
    -D ATFE_TOOLCHAIN=/home/tobante/bin/ATfE-21.1.1-Linux-x86_64 \
    -D CMAKE_CROSSCOMPILING_EMULATOR="qemu-system-arm;-M;microbit;-semihosting;-nographic;-kernel" \
    -D CMAKE_CXX_STANDARD=26 \
    -D CMAKE_COMPILE_WARNING_AS_ERROR=ON \
    -D CMAKE_CXX_SCAN_FOR_MODULES=OFF \
    -D TETL_BUILD_CONTRACT_CHECKS=OFF

cmake --build cmake-build-atfe --target help
ctest --test-dir cmake-build-atfe --output-on-failure -j 16
