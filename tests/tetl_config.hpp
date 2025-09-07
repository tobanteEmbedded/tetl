// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CONFIG_FOR_UNIT_TESTS_HPP
#define TETL_CONFIG_FOR_UNIT_TESTS_HPP

#define TETL_ENABLE_ASSERTIONS
#define TETL_ENABLE_CUSTOM_ASSERT_HANDLER
#define TETL_ENABLE_CUSTOM_EXCEPTION_HANDLER
#define TETL_FREERTOS_USE_STUBS

#include <stdio.h>
#include <stdlib.h>

#include <etl/_config/_workarounds/001_avr_macros.hpp>

namespace etl {

template <typename Exception>
[[noreturn]] inline auto exception_handler(Exception const& e) -> void
{
    ::puts(e.what());
#if defined(__cpp_exceptions)
    throw e;
#else
    ::exit(1); // NOLINT
#endif
}

template <typename Assertion>
[[noreturn]] auto assert_handler(Assertion const& msg) -> void
{
    ::printf("ASSERTION: %s:%d - %s\n", msg.file, msg.line, msg.func);
    ::exit(1); // NOLINT
}

} // namespace etl

#endif // TETL_CONFIG_FOR_UNIT_TESTS_HPP
