// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

// If you disabled the next line, the default expetion handler will be called at
// runtime which will exit the program with code 1. If an assertion is triggered
// in a constexpr context, you will get a compiler error.
//
// If you enabled the custom handler in your projects, please define the macro
// below in your build system and not in your source code to avoid mixing
// configurations.
#define TETL_ENABLE_CUSTOM_ASSERT_HANDLER
#include <etl/cassert.hpp> // for assert

#include <stdio.h>  // for printf
#include <stdlib.h> // for exit

#if defined(TETL_COMPILER_MSVC)
    #pragma warning(disable: 4127) // Conditional expression is constant
#endif

namespace etl {
template <typename Assertion>
[[noreturn]] auto assert_handler(Assertion const& msg) -> void
{
    ::printf("EXCEPTION: %s:%d\n", msg.file, msg.line);
    ::exit(1); // NOLINT
}

} // namespace etl

auto main() -> int
{
    assert(2 == 2);      // success, nothing is printed
    assert(2 == 3);      // failure, the assert handler is invoked
    return EXIT_SUCCESS; // unreachable
}

#if defined(TETL_COMPILER_MSVC)
    #pragma warning(default: 4127) // Conditional expression is constant
#endif
