// SPDX-License-Identifier: BSL-1.0

#undef NDEBUG

#include <etl/cassert.hpp>
#include <etl/cmath.hpp>
#include <etl/warning.hpp>

constexpr auto test() -> bool
{
    etl::ignore_unused(etl::exp(1.0F));
    etl::ignore_unused(etl::exp(1.0));

    etl::ignore_unused(etl::round(1.4F));
    etl::ignore_unused(etl::round(1.4));

    etl::ignore_unused(etl::log(1.4F));
    etl::ignore_unused(etl::log(1.4));

    etl::ignore_unused(etl::floor(1.4F));
    etl::ignore_unused(etl::floor(1.4));

    etl::ignore_unused(etl::ceil(1.4F));
    etl::ignore_unused(etl::ceil(1.4));

    etl::ignore_unused(etl::trunc(1.4F));
    etl::ignore_unused(etl::trunc(1.4));

    etl::ignore_unused(etl::tan(1.4F));
    etl::ignore_unused(etl::tan(1.4));

    etl::ignore_unused(etl::cos(1.4F));
    etl::ignore_unused(etl::cos(1.4));

    etl::ignore_unused(etl::sin(1.4F));
    etl::ignore_unused(etl::sin(1.4));

    etl::ignore_unused(etl::tanh(1.4F));
    etl::ignore_unused(etl::tanh(1.4));

    etl::ignore_unused(etl::cosh(1.4F));
    etl::ignore_unused(etl::cosh(1.4));

    etl::ignore_unused(etl::sinh(1.4F));
    etl::ignore_unused(etl::sinh(1.4));

    etl::ignore_unused(etl::acos(1.4F));
    etl::ignore_unused(etl::acos(1.4));

    etl::ignore_unused(etl::asin(1.4F));
    etl::ignore_unused(etl::asin(1.4));

    etl::ignore_unused(etl::asinh(1.4F));
    etl::ignore_unused(etl::asinh(1.4));

    etl::ignore_unused(etl::hypotf(1.0F, 1.0F));
    etl::ignore_unused(etl::hypot(1.0F, 1.0F));
    etl::ignore_unused(etl::hypot(1.0, 1.0));

    return true;
}

auto main() -> int
{
    TETL_ASSERT(test());
    static_assert(test());
    return 0;
}
