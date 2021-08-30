/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#undef NDEBUG

#include "etl/cmath.hpp"
#include "etl/cassert.hpp"
#include "etl/warning.hpp"

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
    return true;
}

auto main() -> int
{
    TETL_ASSERT(test());
    static_assert(test());
    return 0;
}