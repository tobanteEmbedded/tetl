// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include "testing/testing.hpp"

template <typename String>
constexpr auto test() -> bool
{
    auto str = String();
    CHECK(str == u"");
    CHECK(str.empty());
    CHECK(str.size() == 0); // NOLINT
    CHECK(size(str) == 0);  // NOLINT

    str = str + u"tes";
    CHECK(str == u"tes");

    str = str + char16_t('t');
    CHECK(str == u"test");

    str = str + String{u"_foo"};
    CHECK(str == u"test_foo");

    str = u"__" + str;
    CHECK(str == u"__test_foo");

    str = char16_t('a') + str;
    CHECK(str == u"a__test_foo");

    auto view = etl::u16string_view{str};
    CHECK(str == view);
    CHECK(view == str);

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::inplace_u16string<16>>());
    CHECK(test<etl::inplace_u16string<17>>());
    CHECK(test<etl::inplace_u16string<18>>());
    CHECK(test<etl::inplace_u16string<24>>());
    CHECK(test<etl::inplace_u16string<32>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
