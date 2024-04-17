// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include "testing/testing.hpp"

template <typename String>
constexpr auto test() -> bool
{
    using namespace etl::string_view_literals;

    auto str = String();
    CHECK(str == u8"");
    CHECK(str.empty());
    CHECK(str.size() == 0); // NOLINT
    CHECK(size(str) == 0);  // NOLINT

    str = str + u8"tes";
    CHECK(str == u8"tes");

    str = str + char8_t('t');
    CHECK(str == u8"test");

    str = str + String{u8"_foo"};
    CHECK(str == u8"test_foo");

    str = u8"__" + str;
    CHECK(str == u8"__test_foo");

    str = char8_t('a') + str;
    CHECK(str == u8"a__test_foo"_sv);

    auto view = etl::u8string_view{str};
    CHECK(str == view);
    CHECK(view == str);

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::inplace_u8string<16>>());
    CHECK(test<etl::inplace_u8string<17>>());
    CHECK(test<etl::inplace_u8string<18>>());
    CHECK(test<etl::inplace_u8string<24>>());
    CHECK(test<etl::inplace_u8string<32>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
