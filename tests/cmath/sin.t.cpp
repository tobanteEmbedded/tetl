// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::sin(short{0}) == 0.0);
    CHECK(etl::sinl(0) == 0.0L);
    CHECK(etl::sin(T(0)) == T(0));

    CHECK_APPROX(etl::sin(T(1)), T(0.841471));
    CHECK_APPROX(etl::sin(T(2)), T(0.909297));

    CHECK_APPROX(etl::sin(static_cast<T>(etl::numbers::pi)), T(0));

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    CHECK(test<float>());
    CHECK(test<double>());

#if not defined(TETL_COMPILER_MSVC)
    // TODO
    // static_assert(test<long double>());
    // CHECK(test<long double>());
#endif
    return 0;
}
