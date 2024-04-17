// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include "testing/testing.hpp"

template <typename String>
constexpr auto test() -> bool
{
    auto str = String();
    CHECK(str == U"");
    CHECK(str.empty());
    CHECK(str.size() == 0); // NOLINT
    CHECK(size(str) == 0);  // NOLINT

    str = str + U"tes";
    CHECK(str == U"tes");

    str = str + char32_t('t');
    CHECK(str == U"test");

    str = str + String{U"_foo"};
    CHECK(str == U"test_foo");

    str = U"__" + str;
    CHECK(str == U"__test_foo");

    str = char32_t('a') + str;
    CHECK(str == U"a__test_foo");
    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::inplace_u32string<16>>());
    CHECK(test<etl::inplace_u32string<17>>());
    CHECK(test<etl::inplace_u32string<18>>());
    CHECK(test<etl::inplace_u32string<24>>());
    CHECK(test<etl::inplace_u32string<32>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
