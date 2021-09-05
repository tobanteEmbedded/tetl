/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/iterator.hpp"
#include "etl/vector.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // empty range
    {
        auto data = etl::static_vector<T, 4> {};
        auto* res = etl::remove(begin(data), end(data), T { 1 });
        assert(res == end(data));
        assert(data.empty());
    }

    // found
    {
        auto data = etl::static_vector<T, 4> {};
        data.push_back(T { 1 });
        data.push_back(T { 0 });
        data.push_back(T { 0 });
        data.push_back(T { 0 });

        auto* res = etl::remove(begin(data), end(data), T { 1 });
        assert(res == end(data) - 1);
        assert(data[0] == 0);
    }
    // empty range
    {
        auto s = etl::static_vector<T, 4> {};
        auto d = etl::static_vector<T, 4> {};
        etl::remove_copy(begin(s), end(s), etl::back_inserter(d), T(1));
        assert(d.empty());
    }

    // range
    {
        auto s = etl::array { T(1), T(2), T(3), T(4) };
        auto d = etl::static_vector<T, 4> {};
        etl::remove_copy(begin(s), end(s), etl::back_inserter(d), T(1));
        assert(!d.empty());
        assert(d.size() == 3);
        assert(etl::all_of(begin(d), end(d), [](auto v) { return v > T(1); }));
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