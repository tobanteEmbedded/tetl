/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cstdarg.hpp"

#include "etl/cstdint.hpp"

#include "testing/testing.hpp"

// TODO: Fix on MSVC
// #if not defined(TETL_MSVC)
#if 0

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

template <typename T>
auto test() -> bool
{
    assert(test_va_list<T>(3, 25, 25, 50) == 100);
    assert(test_va_list<T>(4, 25, 25, 50, 25) == 125);
    return true;
}

static auto test_all() -> bool
{
    // Smaller types get promoted when used with va_list
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    return 0;
}
#else
auto main() -> int { return 0; }
#endif
