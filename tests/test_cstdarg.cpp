/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cstdarg.hpp"

#include "catch2/catch_template_test_macros.hpp"

// TODO: Fix on MSVC
#if not defined(TETL_MSVC)

namespace {
template <typename T>
[[nodiscard]] auto test_va_list(T count, ...) -> T // NOLINT
{
    T result = 0;
    etl::va_list args;
    va_start(args, count);
    for (T i = 0; i < count; ++i) { result += va_arg(args, T); }
    va_end(args);
    return result;
}
} // namespace

TEMPLATE_TEST_CASE("cstdarg: va_list", "[cstdarg]", int, long, long long,
    unsigned, unsigned long, unsigned long long)
{
    CHECK(test_va_list<TestType>(3, 25, 25, 50) == 100);
    CHECK(test_va_list<TestType>(4, 25, 25, 50, 50) == 150);
}

#endif
