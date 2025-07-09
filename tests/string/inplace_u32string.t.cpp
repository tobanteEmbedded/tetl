// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.iterator;
import etl.string;
import etl.string_view;
#else
    #include <etl/iterator.hpp>
    #include <etl/string.hpp>
    #include <etl/string_view.hpp>
#endif

template <typename String>
static constexpr auto test() -> bool
{
    using namespace etl::string_view_literals;

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
    CHECK(str == U"a__test_foo"_sv);

    auto view = etl::u32string_view{str};
    CHECK(str == view);
    CHECK(view == str);

    return true;
}

static constexpr auto test_all() -> bool
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
