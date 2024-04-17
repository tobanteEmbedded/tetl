// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include "testing/testing.hpp"

template <typename String>
constexpr auto test() -> bool
{
    using namespace etl::string_view_literals;

    auto str = String();
    CHECK(str == L"");
    CHECK(str.empty());
    CHECK(str.size() == 0); // NOLINT
    CHECK(size(str) == 0);  // NOLINT

    str = str + L"tes";
    CHECK(str == L"tes");

    str = str + wchar_t('t');
    CHECK(str == L"test");

    str = str + String{L"_foo"};
    CHECK(str == L"test_foo");

    str = L"__" + str;
    CHECK(str == L"__test_foo");

    str = wchar_t('a') + str;
    CHECK(str == L"a__test_foo"_sv);

    auto view = etl::wstring_view{str};
    CHECK(str == view);
    CHECK(view == str);

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::inplace_wstring<16>>());
    CHECK(test<etl::inplace_wstring<17>>());
    CHECK(test<etl::inplace_wstring<18>>());
    CHECK(test<etl::inplace_wstring<24>>());
    CHECK(test<etl::inplace_wstring<32>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
