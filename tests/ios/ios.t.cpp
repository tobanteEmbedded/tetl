/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/ios.hpp"

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    assert(etl::is_bitmask_type_v<etl::ios_base::openmode>);
    assert(etl::is_bitmask_type_v<etl::ios_base::fmtflags>);
    assert(etl::is_bitmask_type_v<etl::ios_base::iostate>);
    etl::ignore_unused(etl::basic_stringbuf<char, 16> {});
    etl::ignore_unused(etl::basic_stringbuf<wchar_t, 16> {});
    return true;
}

auto main() -> int
{
    assert(test());
    // static_assert(test());
    return 0;
}