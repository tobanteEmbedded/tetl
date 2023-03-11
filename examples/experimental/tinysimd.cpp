/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#undef NDEBUG

#include <etl/cassert.hpp> // for TETL_ASSERT
#include <etl/simd.hpp>    // for etl::tinysimd

#include <stdio.h>  // for printf
#include <stdlib.h> // for EXIT_SUCCESS

template <typename FloatType>
FloatType exp_impl(FloatType x)
{
    auto numerator   = 1680 + x * (840 + x * (180 + x * (20 + x)));
    auto denominator = 1680 + x * (-840 + x * (180 + x * (-20 + x)));
    return numerator / denominator;
}

[[maybe_unused]] static auto exp(float x) { return exp_impl(x); }
[[maybe_unused]] static auto exp(etl::tinysimd::simd<float, 4> x) { return exp_impl(x); }

auto main() -> int { return EXIT_SUCCESS; }
