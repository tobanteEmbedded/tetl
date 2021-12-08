/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/ratio.hpp"

#include "etl/warning.hpp"

#include "testing/testing.hpp"

using etl::ratio;
using etl::ratio_greater;
using etl::ratio_greater_equal;
using etl::ratio_greater_equal_v;
using etl::ratio_greater_v;
using etl::ratio_less_equal;
using etl::ratio_less_equal_v;

constexpr auto test() -> bool
{

    {
        etl::ratio<1, 1> r {};
        etl::ignore_unused(r);
    }

    {
        assert((etl::ratio<1, 2>::type::num == 1));
        assert((etl::ratio<1, 2>::type::den == 2));
        assert((etl::ratio<3, 6>::type::num == 1));
        assert((etl::ratio<3, 6>::type::den == 2));
        assert((etl::ratio<2, 8>::type::num == 1));
        assert((etl::ratio<2, 8>::type::den == 4));
    }

    // "1/4 + 1/6 = 5/12"
    {
        using one_fourth = etl::ratio<1, 4>;
        using one_sixth  = etl::ratio<1, 6>;
        using sum        = etl::ratio_add<one_fourth, one_sixth>;
        assert((sum::num == 5));
        assert((sum::den == 12));
    }

    // "2/3 + 1/6 = 5/6"
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using sum       = etl::ratio_add<two_third, one_sixth>;
        assert((sum::num == 5));
        assert((sum::den == 6));
    }

    // "1/4 - 1/6 = 1/12"
    {
        using one_fourth = etl::ratio<1, 4>;
        using one_sixth  = etl::ratio<1, 6>;
        using sum        = etl::ratio_subtract<one_fourth, one_sixth>;
        assert((sum::num == 1));
        assert((sum::den == 12));
    }

    // "2/3 - 1/6 = 3/6 = 1/2"
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using sum       = etl::ratio_subtract<two_third, one_sixth>;
        assert((sum::num == 1));
        assert((sum::den == 2));
    }

    // "1/12 * 1/2 = 1/2"
    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;
        using res         = etl::ratio_multiply<one_twelfth, one_half>;
        assert((res::num == 1));
        assert((res::den == 24));
    }

    // "2/3 * 1/6 = 1/9"
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using res       = etl::ratio_multiply<two_third, one_sixth>;
        assert((res::num == 1));
        assert((res::den == 9));
    }

    // "1/12 / 1/6 = 1/2"
    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_sixth   = etl::ratio<1, 6>;
        using res         = etl::ratio_divide<one_twelfth, one_sixth>;
        assert((res::num == 1));
        assert((res::den == 2));
    }

    // "2/3 / 1/6 = 4/1"
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using res       = etl::ratio_divide<two_third, one_sixth>;
        assert((res::num == 4));
        assert((res::den == 1));
    }

    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        assert((etl::ratio_equal_v<one_half, one_half>));
        assert((etl::ratio_equal_v<one_half, etl::ratio<2, 4>>));
        assert((etl::ratio_equal_v<one_half, etl::ratio<3, 6>>));
        assert((etl::ratio_equal_v<one_twelfth, one_twelfth>));
        assert((etl::ratio_equal_v<one_twelfth, etl::ratio<2, 24>>));
        assert((etl::ratio_equal_v<one_twelfth, etl::ratio<3, 36>>));

        assert(!(etl::ratio_equal_v<one_half, one_twelfth>));
        assert(!(etl::ratio_equal_v<one_twelfth, one_half>));
        assert(!(etl::ratio_equal_v<one_twelfth, etl::ratio<2, 23>>));
        assert(!(etl::ratio_equal_v<one_twelfth, etl::ratio<3, 35>>));
    }

    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        assert(!(etl::ratio_not_equal_v<one_half, one_half>));
        assert(!(etl::ratio_not_equal_v<one_half, etl::ratio<2, 4>>));
        assert(!(etl::ratio_not_equal_v<one_half, etl::ratio<3, 6>>));
        assert(!(etl::ratio_not_equal_v<one_twelfth, one_twelfth>));
        assert(!(etl::ratio_not_equal_v<one_twelfth, etl::ratio<2, 24>>));
        assert(!(etl::ratio_not_equal_v<one_twelfth, etl::ratio<3, 36>>));

        assert((etl::ratio_not_equal_v<one_half, one_twelfth>));
        assert((etl::ratio_not_equal_v<one_twelfth, one_half>));
        assert((etl::ratio_not_equal_v<one_twelfth, etl::ratio<2, 23>>));
        assert((etl::ratio_not_equal_v<one_twelfth, etl::ratio<3, 35>>));
    }

    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        assert(!(etl::ratio_less_v<one_half, one_half>));
        assert(!(etl::ratio_less_v<one_half, etl::ratio<2, 4>>));
        assert(!(etl::ratio_less_v<one_half, etl::ratio<3, 6>>));
        assert(!(etl::ratio_less_v<one_twelfth, one_twelfth>));
        assert(!(etl::ratio_less_v<one_twelfth, etl::ratio<2, 24>>));
        assert(!(etl::ratio_less_v<one_twelfth, etl::ratio<3, 36>>));
        assert(!(etl::ratio_less_v<one_half, one_twelfth>));

        assert((etl::ratio_less_v<one_twelfth, one_half>));
        assert((etl::ratio_less_v<one_twelfth, etl::ratio<2, 23>>));
        assert((etl::ratio_less_v<one_twelfth, etl::ratio<3, 35>>));
    }

    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        assert((ratio_less_equal<one_half, etl::ratio<3, 4>>::value));
        assert((ratio_less_equal_v<one_half, one_half>));
        assert((ratio_less_equal_v<one_half, etl::ratio<2, 4>>));
        assert((ratio_less_equal_v<one_half, etl::ratio<3, 6>>));
        assert((ratio_less_equal_v<one_twelfth, one_twelfth>));

        assert((ratio_less_equal_v<etl::ratio<10, 11>, etl::ratio<11, 12>>));
        assert((ratio_less_equal_v<one_twelfth, one_half>));
        assert((ratio_less_equal_v<one_twelfth, etl::ratio<2, 23>>));
        assert((ratio_less_equal_v<one_twelfth, etl::ratio<3, 35>>));

        assert(!(ratio_less_equal_v<one_half, one_twelfth>));
    }

    {

        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        assert(!(etl::ratio_greater_v<one_half, one_half>));
        assert(!(etl::ratio_greater_v<one_half, etl::ratio<2, 4>>));
        assert(!(etl::ratio_greater_v<one_half, etl::ratio<3, 6>>));
        assert(!(etl::ratio_greater_v<one_twelfth, one_twelfth>));
        assert(!(etl::ratio_greater_v<one_twelfth, etl::ratio<2, 24>>));
        assert(!(etl::ratio_greater_v<one_twelfth, etl::ratio<3, 36>>));
        assert(!(etl::ratio_greater_v<one_twelfth, one_half>));

        assert((etl::ratio_greater_v<one_half, one_twelfth>));
        assert((etl::ratio_greater_v<etl::ratio<2, 23>, one_twelfth>));
        assert((etl::ratio_greater_v<etl::ratio<3, 35>, one_twelfth>));
    }

    {

        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        assert((ratio_greater_equal_v<one_half, one_half>));
        assert((ratio_greater_equal_v<one_half, ratio<2, 4>>));
        assert((ratio_greater_equal_v<one_half, ratio<3, 6>>));
        assert((ratio_greater_equal_v<one_twelfth, one_twelfth>));
        assert((ratio_greater_equal_v<one_twelfth, ratio<2, 24>>));
        assert((ratio_greater_equal_v<one_twelfth, ratio<3, 36>>));
        assert((ratio_greater_equal_v<one_half, one_twelfth>));
        assert((ratio_greater_equal_v<ratio<2, 23>, one_twelfth>));
        assert((ratio_greater_equal_v<ratio<3, 35>, one_twelfth>));

        assert(!(ratio_greater_equal_v<one_twelfth, one_half>));
    }

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}