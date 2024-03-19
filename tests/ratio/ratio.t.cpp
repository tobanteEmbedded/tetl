// SPDX-License-Identifier: BSL-1.0

#include <etl/ratio.hpp>

#include <etl/warning.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{

    {
        etl::ratio<1, 1> r{};
        etl::ignore_unused(r);
    }

    {
        CHECK(etl::ratio<1, 2>::type::num == 1);
        CHECK(etl::ratio<1, 2>::type::den == 2);
        CHECK(etl::ratio<3, 6>::type::num == 1);
        CHECK(etl::ratio<3, 6>::type::den == 2);
        CHECK(etl::ratio<2, 8>::type::num == 1);
        CHECK(etl::ratio<2, 8>::type::den == 4);
    }

    // "1/4 + 1/6 = 5/12"
    {
        using one_fourth = etl::ratio<1, 4>;
        using one_sixth  = etl::ratio<1, 6>;
        using sum        = etl::ratio_add<one_fourth, one_sixth>;
        CHECK(sum::num == 5);
        CHECK(sum::den == 12);
    }

    // "2/3 + 1/6 = 5/6"
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using sum       = etl::ratio_add<two_third, one_sixth>;
        CHECK(sum::num == 5);
        CHECK(sum::den == 6);
    }

    // "1/4 - 1/6 = 1/12"
    {
        using one_fourth = etl::ratio<1, 4>;
        using one_sixth  = etl::ratio<1, 6>;
        using sum        = etl::ratio_subtract<one_fourth, one_sixth>;
        CHECK(sum::num == 1);
        CHECK(sum::den == 12);
    }

    // "2/3 - 1/6 = 3/6 = 1/2"
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using sum       = etl::ratio_subtract<two_third, one_sixth>;
        CHECK(sum::num == 1);
        CHECK(sum::den == 2);
    }

    // "1/12 * 1/2 = 1/2"
    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;
        using res         = etl::ratio_multiply<one_twelfth, one_half>;
        CHECK(res::num == 1);
        CHECK(res::den == 24);
    }

    // "2/3 * 1/6 = 1/9"
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using res       = etl::ratio_multiply<two_third, one_sixth>;
        CHECK(res::num == 1);
        CHECK(res::den == 9);
    }

    // "1/12 / 1/6 = 1/2"
    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_sixth   = etl::ratio<1, 6>;
        using res         = etl::ratio_divide<one_twelfth, one_sixth>;
        CHECK(res::num == 1);
        CHECK(res::den == 2);
    }

    // "2/3 / 1/6 = 4/1"
    {
        using two_third = etl::ratio<2, 3>;
        using one_sixth = etl::ratio<1, 6>;
        using res       = etl::ratio_divide<two_third, one_sixth>;
        CHECK(res::num == 4);
        CHECK(res::den == 1);
    }

    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        CHECK(etl::ratio_equal_v<one_half, one_half>);
        CHECK(etl::ratio_equal_v<one_half, etl::ratio<2, 4>>);
        CHECK(etl::ratio_equal_v<one_half, etl::ratio<3, 6>>);
        CHECK(etl::ratio_equal_v<one_twelfth, one_twelfth>);
        CHECK(etl::ratio_equal_v<one_twelfth, etl::ratio<2, 24>>);
        CHECK(etl::ratio_equal_v<one_twelfth, etl::ratio<3, 36>>);

        CHECK(!(etl::ratio_equal_v<one_half, one_twelfth>));
        CHECK(!(etl::ratio_equal_v<one_twelfth, one_half>));
        CHECK(!(etl::ratio_equal_v<one_twelfth, etl::ratio<2, 23>>));
        CHECK(!(etl::ratio_equal_v<one_twelfth, etl::ratio<3, 35>>));
    }

    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        CHECK(!(etl::ratio_not_equal_v<one_half, one_half>));
        CHECK(!(etl::ratio_not_equal_v<one_half, etl::ratio<2, 4>>));
        CHECK(!(etl::ratio_not_equal_v<one_half, etl::ratio<3, 6>>));
        CHECK(!(etl::ratio_not_equal_v<one_twelfth, one_twelfth>));
        CHECK(!(etl::ratio_not_equal_v<one_twelfth, etl::ratio<2, 24>>));
        CHECK(!(etl::ratio_not_equal_v<one_twelfth, etl::ratio<3, 36>>));

        CHECK(etl::ratio_not_equal_v<one_half, one_twelfth>);
        CHECK(etl::ratio_not_equal_v<one_twelfth, one_half>);
        CHECK(etl::ratio_not_equal_v<one_twelfth, etl::ratio<2, 23>>);
        CHECK(etl::ratio_not_equal_v<one_twelfth, etl::ratio<3, 35>>);
    }

    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        CHECK(!(etl::ratio_less_v<one_half, one_half>));
        CHECK(!(etl::ratio_less_v<one_half, etl::ratio<2, 4>>));
        CHECK(!(etl::ratio_less_v<one_half, etl::ratio<3, 6>>));
        CHECK(!(etl::ratio_less_v<one_twelfth, one_twelfth>));
        CHECK(!(etl::ratio_less_v<one_twelfth, etl::ratio<2, 24>>));
        CHECK(!(etl::ratio_less_v<one_twelfth, etl::ratio<3, 36>>));
        CHECK(!(etl::ratio_less_v<one_half, one_twelfth>));

        CHECK(etl::ratio_less_v<one_twelfth, one_half>);
        CHECK(etl::ratio_less_v<one_twelfth, etl::ratio<2, 23>>);
        CHECK(etl::ratio_less_v<one_twelfth, etl::ratio<3, 35>>);
    }

    {
        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        CHECK(etl::ratio_less_equal_v<one_half, etl::ratio<3, 4>>);
        CHECK(etl::ratio_less_equal_v<one_half, one_half>);
        CHECK(etl::ratio_less_equal_v<one_half, etl::ratio<2, 4>>);
        CHECK(etl::ratio_less_equal_v<one_half, etl::ratio<3, 6>>);
        CHECK(etl::ratio_less_equal_v<one_twelfth, one_twelfth>);

        CHECK(etl::ratio_less_equal_v<etl::ratio<10, 11>, etl::ratio<11, 12>>);
        CHECK(etl::ratio_less_equal_v<one_twelfth, one_half>);
        CHECK(etl::ratio_less_equal_v<one_twelfth, etl::ratio<2, 23>>);
        CHECK(etl::ratio_less_equal_v<one_twelfth, etl::ratio<3, 35>>);

        CHECK(!(etl::ratio_less_equal_v<one_half, one_twelfth>));
    }

    {

        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        CHECK(!(etl::ratio_greater_v<one_half, one_half>));
        CHECK(!(etl::ratio_greater_v<one_half, etl::ratio<2, 4>>));
        CHECK(!(etl::ratio_greater_v<one_half, etl::ratio<3, 6>>));
        CHECK(!(etl::ratio_greater_v<one_twelfth, one_twelfth>));
        CHECK(!(etl::ratio_greater_v<one_twelfth, etl::ratio<2, 24>>));
        CHECK(!(etl::ratio_greater_v<one_twelfth, etl::ratio<3, 36>>));
        CHECK(!(etl::ratio_greater_v<one_twelfth, one_half>));

        CHECK(etl::ratio_greater_v<one_half, one_twelfth>);
        CHECK(etl::ratio_greater_v<etl::ratio<2, 23>, one_twelfth>);
        CHECK(etl::ratio_greater_v<etl::ratio<3, 35>, one_twelfth>);
    }

    {

        using one_twelfth = etl::ratio<1, 12>;
        using one_half    = etl::ratio<1, 2>;

        CHECK(etl::ratio_greater_equal_v<one_half, one_half>);
        CHECK(etl::ratio_greater_equal_v<one_half, etl::ratio<2, 4>>);
        CHECK(etl::ratio_greater_equal_v<one_half, etl::ratio<3, 6>>);
        CHECK(etl::ratio_greater_equal_v<one_twelfth, one_twelfth>);
        CHECK(etl::ratio_greater_equal_v<one_twelfth, etl::ratio<2, 24>>);
        CHECK(etl::ratio_greater_equal_v<one_twelfth, etl::ratio<3, 36>>);
        CHECK(etl::ratio_greater_equal_v<one_half, one_twelfth>);
        CHECK(etl::ratio_greater_equal_v<etl::ratio<2, 23>, one_twelfth>);
        CHECK(etl::ratio_greater_equal_v<etl::ratio<3, 35>, one_twelfth>);

        CHECK(!(etl::ratio_greater_equal_v<one_twelfth, one_half>));
    }

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
