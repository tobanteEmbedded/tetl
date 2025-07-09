// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.cstddef;
import etl.string;
import etl.utility;
#else
    #include <etl/cstddef.hpp>
    #include <etl/string.hpp>
    #include <etl/utility.hpp>
#endif

template <typename Float, typename String>
static constexpr auto test(auto func) -> bool
{
    {
        auto count = etl::size_t(0);
        CHECK(func(String{"0"}, &count) == Float(0));
        CHECK(count == 1);
    }

    {
        auto count = etl::size_t(0);
        CHECK(func(String{" 123.0"}, &count) == Float(123));
        CHECK(count == 6);
    }

    CHECK(func(String{" 0"}) == Float(0));
    CHECK(func(String{" 0 "}) == Float(0));
    CHECK(func(String{"1"}) == Float(1));
    CHECK(func(String{"2"}) == Float(2));

    // CHECK(func(String{"-1"}) == Float(-1));
    // CHECK(func(String{" -1"}) == Float(-1));
    // CHECK(func(String{" -1 "}) == Float(-1));

    return true;
}

static constexpr auto test_all() -> bool
{
    auto stof = []<typename... Args>(Args&&... args) { return etl::stof(etl::forward<Args>(args)...); };
    CHECK(test<float, etl::inplace_string<7>>(stof));
    CHECK(test<float, etl::inplace_string<8>>(stof));
    CHECK(test<float, etl::inplace_string<9>>(stof));
    CHECK(test<float, etl::inplace_string<16>>(stof));
    CHECK(test<float, etl::inplace_string<17>>(stof));

    auto stod = []<typename... Args>(Args&&... args) { return etl::stod(etl::forward<Args>(args)...); };
    CHECK(test<double, etl::inplace_string<7>>(stod));
    CHECK(test<double, etl::inplace_string<8>>(stod));
    CHECK(test<double, etl::inplace_string<9>>(stod));
    CHECK(test<double, etl::inplace_string<16>>(stod));
    CHECK(test<double, etl::inplace_string<17>>(stod));

    auto stold = []<typename... Args>(Args&&... args) { return etl::stold(etl::forward<Args>(args)...); };
    CHECK(test<long double, etl::inplace_string<7>>(stold));
    CHECK(test<long double, etl::inplace_string<8>>(stold));
    CHECK(test<long double, etl::inplace_string<9>>(stold));
    CHECK(test<long double, etl::inplace_string<16>>(stold));
    CHECK(test<long double, etl::inplace_string<17>>(stold));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
