// SPDX-License-Identifier: BSL-1.0

#include <etl/ios.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    CHECK(etl::is_bitmask_type_v<etl::ios_base::openmode>);
    CHECK(etl::is_bitmask_type_v<etl::ios_base::fmtflags>);
    CHECK(etl::is_bitmask_type_v<etl::ios_base::iostate>);
    etl::ignore_unused(etl::basic_stringbuf<char, 16>{});
    etl::ignore_unused(etl::basic_stringbuf<wchar_t, 16>{});
    return true;
}

auto main() -> int
{
    CHECK(test());
    // static_assert(test());
    return 0;
}
