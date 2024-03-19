// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/iterator_types.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto data     = etl::array{T(1), T(2), T(3), T(4)};
    auto const p1 = [](T a) { return etl::abs(a) > T(0); };
    auto const p2 = [](T a) { return etl::abs(a) > T(10); };
    auto const p3 = [](T a) { return a < T(10); };

    CHECK(etl::all_of(data.begin(), data.end(), p1));
    CHECK(!etl::all_of(data.begin(), data.end(), p2));
    CHECK(etl::all_of(InIter(data.begin()), InIter(data.end()), p1));

    CHECK(etl::any_of(data.begin(), data.end(), p1));
    CHECK(!etl::any_of(data.begin(), data.end(), p2));
    CHECK(etl::any_of(InIter(data.begin()), InIter(data.end()), p1));

    CHECK(etl::none_of(data.begin(), data.end(), p2));
    CHECK(!etl::none_of(data.begin(), data.end(), p3));
    CHECK(etl::none_of(InIter(data.begin()), InIter(data.end()), p2));

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    CHECK(test_all());
    static_assert(test_all());
    return 0;
}
