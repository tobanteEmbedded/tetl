// SPDX-License-Identifier: BSL-1.0

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.array;
import etl.cstdint;
import etl.functional;
import etl.numeric;
#else
    #include <etl/array.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/functional.hpp>
    #include <etl/numeric.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    auto const nop = etl::identity();
    auto const vec = etl::array{T(1), T(2), T(3), T(4)};

    CHECK(etl::transform_reduce(vec.begin(), vec.end(), T(0), etl::plus(), nop) == T(10));
    CHECK(etl::transform_reduce(vec.begin(), vec.end(), T(0), etl::minus(), nop) == T(-10));
    CHECK(etl::transform_reduce(FwdIter(vec.begin()), FwdIter(vec.end()), T(0), etl::minus(), nop) == T(-10));

    CHECK(etl::transform_reduce(vec.begin(), vec.end(), vec.begin(), T(0)) == T(30));
    CHECK(etl::transform_reduce(FwdIter(vec.begin()), FwdIter(vec.end()), FwdIter(vec.begin()), T(0)) == T(30));
    CHECK(etl::transform_reduce(vec.begin(), vec.end(), vec.begin(), T(0), etl::minus(), etl::multiplies()) == T(-30));

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
