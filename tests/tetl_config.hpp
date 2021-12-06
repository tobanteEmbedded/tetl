/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONFIG_FOR_CATCH2_BASED_TESTS_HPP
#define TETL_CONFIG_FOR_CATCH2_BASED_TESTS_HPP

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
    throw e;
}

template <typename Assertion>
[[noreturn]] auto tetl_assert_handler(Assertion const& msg) -> void
{
    ::printf("EXCEPTION: %s:%d\n", msg.file, msg.line);
    ::exit(1); // NOLINT
}
} // namespace etl

#endif // TETL_CONFIG_FOR_CATCH2_BASED_TESTS_HPP