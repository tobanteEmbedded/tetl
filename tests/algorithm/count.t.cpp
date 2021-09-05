/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/iterator.hpp"
#include "etl/numeric.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        auto data = etl::array<T, 4> {};
        etl::iota(begin(data), end(data), T { 0 });
        assert(etl::count(begin(data), end(data), T { 0 }) == 1);
        assert(etl::count(begin(data), end(data), T { 1 }) == 1);
        assert(etl::count(begin(data), end(data), T { 2 }) == 1);
        assert(etl::count(begin(data), end(data), T { 3 }) == 1);
        assert(etl::count(begin(data), end(data), T { 4 }) == 0);
    }

    {
        auto data = etl::array<T, 4> {};
        etl::iota(begin(data), end(data), T { 0 });

        auto p1 = [](auto val) { return val < T { 2 }; };
        auto p2 = [](auto val) -> bool { return static_cast<int>(val) % 2; };

        assert(etl::count_if(begin(data), end(data), p1) == 2);
        assert(etl::count_if(begin(data), end(data), p2) == 2);
    }
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