/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/numeric.hpp"
#include "etl/vector.hpp"

#include "testing/iterator_types.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto data     = etl::array { T(1), T(2), T(3), T(4) };
    auto const p1 = [](T a) { return etl::abs(a) > T(0); };
    auto const p2 = [](T a) { return etl::abs(a) > T(10); };
    auto const p3 = [](T a) { return a < T(10); };

    assert(etl::all_of(data.begin(), data.end(), p1));
    assert(!etl::all_of(data.begin(), data.end(), p2));
    assert(etl::all_of(InIter(data.begin()), InIter(data.end()), p1));

    assert(etl::any_of(data.begin(), data.end(), p1));
    assert(!etl::any_of(data.begin(), data.end(), p2));
    assert(etl::any_of(InIter(data.begin()), InIter(data.end()), p1));

    assert(etl::none_of(data.begin(), data.end(), p2));
    assert(!etl::none_of(data.begin(), data.end(), p3));
    assert(etl::none_of(InIter(data.begin()), InIter(data.end()), p2));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
