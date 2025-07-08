// SPDX-License-Identifier: BSL-1.0

#include "testing/approx.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.cmath;
#else
    #include <etl/cmath.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK_APPROX(etl::copysign(T(0), T(1)), T(0));
    CHECK_APPROX(etl::copysign(T(1), T(1)), T(1));
    CHECK_APPROX(etl::copysign(T(1), T(-1)), T(-1));
    CHECK_APPROX(etl::copysign(T(2), T(-2)), T(-2));
    CHECK_APPROX(etl::copysign(T(-2), T(-2)), T(-2));
    CHECK_APPROX(etl::copysign(T(-2), T(2)), T(2));

    CHECK_APPROX(etl::copysignf(+0.0F, +1.0F), +0.0F);
    CHECK_APPROX(etl::copysignf(+1.0F, +1.0F), +1.0F);
    CHECK_APPROX(etl::copysignf(+1.0F, -1.0F), -1.0F);
    CHECK_APPROX(etl::copysignf(+2.0F, -2.0F), -2.0F);
    CHECK_APPROX(etl::copysignf(-2.0F, -2.0F), -2.0F);
    CHECK_APPROX(etl::copysignf(-2.0F, +2.0F), +2.0F);

    CHECK_APPROX(etl::copysignl(+0.0L, +1.0L), +0.0L);
    CHECK_APPROX(etl::copysignl(+1.0L, +1.0L), +1.0L);
    CHECK_APPROX(etl::copysignl(+1.0L, -1.0L), -1.0L);
    CHECK_APPROX(etl::copysignl(+2.0L, -2.0L), -2.0L);
    CHECK_APPROX(etl::copysignl(-2.0L, -2.0L), -2.0L);
    CHECK_APPROX(etl::copysignl(-2.0L, +2.0L), +2.0L);

    CHECK_APPROX(etl::detail::copysign_fallback(T(0), T(1)), T(0));
    CHECK_APPROX(etl::detail::copysign_fallback(T(1), T(1)), T(1));
    CHECK_APPROX(etl::detail::copysign_fallback(T(1), T(-1)), T(-1));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
