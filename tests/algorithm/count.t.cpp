/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/iterator.hpp"
#include "etl/numeric.hpp"

#include "testing/iterator_types.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto src = etl::array<T, 4> {};
    etl::iota(begin(src), end(src), T { 0 });

    assert(etl::count(begin(src), end(src), T { 0 }) == 1);
    assert(etl::count(begin(src), end(src), T { 1 }) == 1);
    assert(etl::count(begin(src), end(src), T { 2 }) == 1);
    assert(etl::count(begin(src), end(src), T { 3 }) == 1);
    assert(etl::count(begin(src), end(src), T { 4 }) == 0);

    // input iterator
    assert(etl::count(InIter(begin(src)), InIter(end(src)), T(0)) == 1);
    // forward iterator
    assert(etl::count(FwdIter(begin(src)), FwdIter(end(src)), T(0)) == 1);

    auto p1 = [](auto val) { return val < T { 2 }; };
    auto p2 = [](auto val) -> bool { return static_cast<int>(val) % 2; };

    assert(etl::count_if(begin(src), end(src), p1) == 2);
    assert(etl::count_if(begin(src), end(src), p2) == 2);

    // input iterator
    assert(etl::count_if(InIter(begin(src)), InIter(end(src)), p1) == 2);
    // forward iterator
    assert(etl::count_if(FwdIter(begin(src)), FwdIter(end(src)), p1) == 2);

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