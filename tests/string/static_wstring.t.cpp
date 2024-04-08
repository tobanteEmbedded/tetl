// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto str = T();
    CHECK(str == L"");
    CHECK(str.empty());
    CHECK(str.size() == 0); // NOLINT
    CHECK(size(str) == 0);  // NOLINT

    str = str + L"tes";
    CHECK(str == L"tes");

    str = str + wchar_t('t');
    CHECK(str == L"test");

    str = str + T{L"_foo"};
    CHECK(str == L"test_foo");

    str = L"__" + str;
    CHECK(str == L"__test_foo");

    str = wchar_t('a') + str;
    CHECK(str == L"a__test_foo");
    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::static_wstring<16>>());
    CHECK(test<etl::static_wstring<17>>());
    CHECK(test<etl::static_wstring<18>>());
    CHECK(test<etl::static_wstring<24>>());
    CHECK(test<etl::static_wstring<32>>());
    CHECK(test<etl::static_wstring<64>>());
    CHECK(test<etl::static_wstring<128>>());
    CHECK(test<etl::static_wstring<256>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
