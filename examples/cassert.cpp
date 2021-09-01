/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

// If you disabled the next line, the default expetion handler will be called at
// runtime which will exit the program with code 1. If an assertion is triggered
// in a constexpr context, you will get a compiler error.
//
// If you enabled the custom handler in your projects, please define the macro
// below in your build system and not in your source code to avoid mixing
// configurations.
#define TETL_ENABLE_CUSTOM_ASSERT_HANDLER 1

#undef NDEBUG              // force assertions in release build
#include "etl/cassert.hpp" // for TETL_ASSERT

#include <stdio.h>  // for printf
#include <stdlib.h> // for exit

#if defined(TETL_MSVC)
    #pragma warning(disable : 4127) // Conditional expression is constant
#endif

namespace etl {
template <typename Assertion>
[[noreturn]] auto tetl_assert_handler(Assertion const& msg) -> void
{
    ::printf("EXCEPTION: %s:%d\n", msg.file, msg.line);
    ::exit(1); // NOLINT
}

} // namespace etl

auto main() -> int
{
    TETL_ASSERT(2 == 2); // success, nothing is printed
    TETL_ASSERT(2 == 3); // failure, the assert handler is invoked
    return EXIT_SUCCESS; // unreachable
}

#if defined(TETL_MSVC)
    #pragma warning(default : 4127) // Conditional expression is constant
#endif