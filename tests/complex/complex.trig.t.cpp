// SPDX-License-Identifier: BSL-1.0

#include "testing/approx.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.cmath;
import etl.complex;
import etl.concepts;
import etl.utility;
#else
    #include <etl/cmath.hpp>
    #include <etl/complex.hpp>
    #include <etl/concepts.hpp>
    #include <etl/utility.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{

    CHECK_APPROX(etl::abs(etl::complex(T(3), T(2))), etl::sqrt(T(13)));
    CHECK_APPROX(etl::arg(etl::complex(T(3), T(2))), T(0.588003));

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    auto const cos = etl::cos(etl::complex(T(3), T(2)));
    CHECK_APPROX(cos.real(), T(-3.72455));
    CHECK_APPROX(cos.imag(), T(-0.511823));

    auto const sin = etl::sin(etl::complex(T(3), T(2)));
    CHECK_APPROX(sin.real(), T(0.530921));
    CHECK_APPROX(sin.imag(), T(-3.59056));

    auto const cosh = etl::cosh(etl::complex(T(3), T(2)));
    CHECK_APPROX(cosh.real(), T(-4.18963));
    CHECK_APPROX(cosh.imag(), T(9.10923));

    auto const sinh = etl::sinh(etl::complex(T(3), T(2)));
    CHECK_APPROX(sinh.real(), T(-4.16891));
    CHECK_APPROX(sinh.imag(), T(9.1545));

    auto const log = etl::log(etl::complex(T(3), T(2)));
    CHECK_APPROX(log.real(), T(1.28247));
    CHECK_APPROX(log.imag(), T(0.588003));

    auto const log10 = etl::log10(etl::complex(T(3), T(2)));
    CHECK_APPROX(log10.real(), T(0.556972));
    CHECK_APPROX(log10.imag(), T(0.255366));

    auto const tan = etl::tan(etl::complex(T(3), T(2)));
    CHECK_APPROX(tan.real(), T(-0.00988438));
    CHECK_APPROX(tan.imag(), T(0.965386));

    auto const tanh = etl::tanh(etl::complex(T(3), T(2)));
    CHECK_APPROX(tanh.real(), T(1.00324));
    CHECK_APPROX(tanh.imag(), T(-0.00376403));
#endif

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
