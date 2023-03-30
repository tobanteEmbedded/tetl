// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONFIG_FOR_UNIT_TESTS_HPP
#define TETL_CONFIG_FOR_UNIT_TESTS_HPP

#include <stdio.h>
#include <stdlib.h>

#include "etl/_config/_workarounds/001_avr_macros.hpp"

#define TETL_ENABLE_CUSTOM_ASSERT_HANDLER 1
#define TETL_ENABLE_CUSTOM_EXCEPTION_HANDLER 1

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

template <typename Assertion>
[[noreturn]] auto tetl_assert_handler(Assertion const& msg) -> void
{
    ::printf("ASSERTION: %s:%d\n", msg.file, msg.line);
    ::exit(1); // NOLINT
}
} // namespace etl

#endif // TETL_CONFIG_FOR_UNIT_TESTS_HPP
