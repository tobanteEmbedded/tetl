// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto str = T();
    assert(str == L"");
    assert(str.empty());
    assert(str.size() == 0); // NOLINT
    assert(size(str) == 0);  // NOLINT

    str = str + L"tes";
    assert(str == L"tes");

    str = str + wchar_t('t');
    assert(str == L"test");

    str = str + T {L"_foo"};
    assert(str == L"test_foo");

    str = L"__" + str;
    assert(str == L"__test_foo");

    str = wchar_t('a') + str;
    assert(str == L"a__test_foo");
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::static_wstring<16>>());
    assert(test<etl::static_wstring<17>>());
    assert(test<etl::static_wstring<18>>());
    assert(test<etl::static_wstring<24>>());
    assert(test<etl::static_wstring<32>>());
    assert(test<etl::static_wstring<64>>());
    assert(test<etl::static_wstring<128>>());
    assert(test<etl::static_wstring<256>>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    // static_assert(test_all());
    return 0;
}
