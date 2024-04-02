// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/array.hpp>
#include <etl/functional.hpp>

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto const nop = etl::identity();
    auto const vec = etl::array{T(1), T(2), T(3), T(4)};

    CHECK(etl::transform_reduce(vec.begin(), vec.end(), T(0), etl::plus(), nop) == T(10));
    CHECK(etl::transform_reduce(vec.begin(), vec.end(), T(0), etl::minus(), nop) == T(-10));
    CHECK(etl::transform_reduce(forward_iter(vec.begin()), forward_iter(vec.end()), T(0), etl::minus(), nop) == T(-10));

    CHECK(etl::transform_reduce(vec.begin(), vec.end(), vec.begin(), T(0)) == T(30));
    CHECK(
        etl::transform_reduce(forward_iter(vec.begin()), forward_iter(vec.end()), forward_iter(vec.begin()), T(0))
        == T(30)
    );
    CHECK(etl::transform_reduce(vec.begin(), vec.end(), vec.begin(), T(0), etl::minus(), etl::multiplies()) == T(-30));

    return true;
}

constexpr auto test_all() -> bool
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
