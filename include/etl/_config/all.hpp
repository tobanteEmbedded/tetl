// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CONFIG_ALL_HPP
#define TETL_CONFIG_ALL_HPP

// clang-format off
#include <etl/_config/compiler.hpp>
#include <etl/_config/preprocessor.hpp>
#include <etl/_config/attributes.hpp>
#include <etl/_config/builtin_types.hpp>
#include <etl/_config/builtin_functions.hpp>
#include <etl/_config/debug_trap.hpp>
#include <etl/_config/version.hpp>
#include <etl/_config/workarounds.hpp>
#include <etl/_config/docs.hpp>
#include <etl/_config/user.hpp>
// clang-format on

#if __has_include(<version>)
    #include <version>
#endif

#endif // TETL_CONFIG_ALL_HPP
