/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/numeric.hpp"
#include "etl/vector.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        etl::static_vector<T, 16> vec;
        vec.push_back(1);
        vec.push_back(2);
        vec.push_back(3);
        vec.push_back(4);

        auto const p1 = [](auto a) { return etl::abs(a) > 0; };
        assert(etl::all_of(vec.begin(), vec.end(), p1));

        auto const p2 = [](auto a) { return etl::abs(a) > 10; };
        assert(!etl::all_of(vec.begin(), vec.end(), p2));
    }

    {
        etl::static_vector<T, 16> vec;
        vec.push_back(1);
        vec.push_back(2);
        vec.push_back(3);
        vec.push_back(4);

        auto const p1 = [](auto a) { return etl::abs(a) > 0; };
        assert(etl::any_of(vec.begin(), vec.end(), p1));
        auto const p2 = [](auto a) { return etl::abs(a) > 10; };
        assert(!etl::any_of(vec.begin(), vec.end(), p2));
    }

    {
        etl::static_vector<T, 16> vec;
        vec.push_back(1);
        vec.push_back(2);
        vec.push_back(3);
        vec.push_back(4);

        auto const p1 = [](auto a) { return etl::abs(a) > 10; };
        assert(etl::none_of(vec.begin(), vec.end(), p1));

        auto const p2 = [](auto a) { return a < 10; };
        assert(!etl::none_of(vec.begin(), vec.end(), p2));
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