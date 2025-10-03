# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
cmake_minimum_required(VERSION 3.28)
project(tetl-fuzzing LANGUAGES CXX)

if(NOT (CMAKE_CXX_COMPILER_ID MATCHES "Clang"))
    message(FATAL_ERROR "tetl-fuzzing needs to build with clang & libFuzzer")
endif()

find_program(CCACHE ccache)
if(CCACHE)
    set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE})
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=fuzzer,address,undefined -ftest-coverage -fcoverage-mapping -fprofile-arcs -fprofile-instr-generate")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

enable_testing()

function(tetl_add_fuzz_test _target)
    set(target_name "${_target}.fuzz")

    add_executable(${target_name} "src/${target_name}.cpp")
    target_include_directories(${target_name} PRIVATE "./include" "../include")
    target_compile_options(${target_name} PRIVATE
        "-Werror"
        "-Weverything"
        "-Wno-c++98-compat-pedantic"
        "-Wno-c++98-compat"
        "-Wno-ctad-maybe-unsupported"
        "-Wno-exit-time-destructors"
        "-Wno-float-equal"
        "-Wno-implicit-int-conversion"
        "-Wno-missing-prototypes"
        "-Wno-padded"
        "-Wno-unsafe-buffer-usage"
    )

    add_test(NAME "${target_name}" COMMAND ${target_name} -max_total_time=60)
    set_tests_properties("${target_name}" PROPERTIES ENVIRONMENT "LLVM_PROFILE_FILE=raw/%p-%m.profraw")
    set_tests_properties("${target_name}" PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
endfunction()

tetl_add_fuzz_test("algorithm.adjacent_find")
tetl_add_fuzz_test("algorithm.binary_search")
tetl_add_fuzz_test("algorithm.bubble_sort")
tetl_add_fuzz_test("algorithm.equal_range")
tetl_add_fuzz_test("algorithm.equal")
tetl_add_fuzz_test("algorithm.exchange_sort")
tetl_add_fuzz_test("algorithm.gnome_sort")
tetl_add_fuzz_test("algorithm.insertion_sort")
tetl_add_fuzz_test("algorithm.is_partitioned")
tetl_add_fuzz_test("algorithm.is_permutation")
tetl_add_fuzz_test("algorithm.lexicographical_compare")
tetl_add_fuzz_test("algorithm.max_element")
tetl_add_fuzz_test("algorithm.merge_sort")
tetl_add_fuzz_test("algorithm.min_element")
tetl_add_fuzz_test("algorithm.minmax_element")
tetl_add_fuzz_test("algorithm.mismatch")
# tetl_add_fuzz_test("algorithm.nth_element")
tetl_add_fuzz_test("algorithm.partition")
tetl_add_fuzz_test("algorithm.quick_sort")
tetl_add_fuzz_test("algorithm.reverse")
tetl_add_fuzz_test("algorithm.search")
tetl_add_fuzz_test("algorithm.set_difference")
tetl_add_fuzz_test("algorithm.set_intersection")
tetl_add_fuzz_test("algorithm.set_symmetric_difference")
tetl_add_fuzz_test("algorithm.set_union")
tetl_add_fuzz_test("algorithm.shift_left")
# tetl_add_fuzz_test("algorithm.shift_right")
tetl_add_fuzz_test("bit.bit_ceil")
tetl_add_fuzz_test("bit.bit_floor")
tetl_add_fuzz_test("bit.bit_width")
tetl_add_fuzz_test("bit.byteswap")
tetl_add_fuzz_test("bit.countl_one")
tetl_add_fuzz_test("bit.countl_zero")
tetl_add_fuzz_test("bit.countr_one")
tetl_add_fuzz_test("bit.countr_zero")
tetl_add_fuzz_test("bit.has_single_bit")
tetl_add_fuzz_test("bit.popcount")
tetl_add_fuzz_test("bitset")
tetl_add_fuzz_test("cctype")
tetl_add_fuzz_test("charconv.from_chars")
tetl_add_fuzz_test("charconv.to_chars")
tetl_add_fuzz_test("cmath.lerp")
tetl_add_fuzz_test("numeric.midpoint")
tetl_add_fuzz_test("random.uniform_int_distribution")
tetl_add_fuzz_test("random.uniform_real_distribution")
tetl_add_fuzz_test("string_view.contains")
tetl_add_fuzz_test("string_view.ends_with")
tetl_add_fuzz_test("string_view.find_first_not_of")
tetl_add_fuzz_test("string_view.find_first_of")
tetl_add_fuzz_test("string_view.find_last_not_of")
tetl_add_fuzz_test("string_view.find_last_of")
tetl_add_fuzz_test("string_view.find")
tetl_add_fuzz_test("string_view.rfind")
tetl_add_fuzz_test("string_view.starts_with")
tetl_add_fuzz_test("string")
