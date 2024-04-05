// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONFIG_FOR_UNIT_TESTS_HPP
#define TETL_CONFIG_FOR_UNIT_TESTS_HPP

#define TETL_ENABLE_ASSERTIONS
#define TETL_ENABLE_CUSTOM_ASSERT_HANDLER
#define TETL_ENABLE_CUSTOM_EXCEPTION_HANDLER

#include <etl/cassert.hpp>

#include <etl/_config/_workarounds/001_avr_macros.hpp>

#include <stdio.h>
#include <stdlib.h>

namespace etl {

template <typename Exception>
[[noreturn]] inline auto tetl_exception_handler(Exception const& e) -> void
{
    ::puts(e.what());
#if defined(__cpp_exceptions)
    throw e;
#else
    ::exit(1); // NOLINT
#endif
}

[[noreturn]] auto tetl_assert_handler(assert_msg const& msg) -> void
{
    ::printf("ASSERTION: %s:%d - %s\n", msg.file, msg.line, msg.func);
    ::exit(1); // NOLINT
}
} // namespace etl

#endif // TETL_CONFIG_FOR_UNIT_TESTS_HPP
