/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/numeric.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // from 0
    {
        auto data = etl::array<T, 4> {};
        etl::iota(begin(data), end(data), T { 0 });
        assert(data[0] == 0);
        assert(data[1] == 1);
        assert(data[2] == 2);
        assert(data[3] == 3);
    }

    // from 42
    {
        auto data = etl::array<T, 4> {};
        etl::iota(begin(data), end(data), T { 42 });
        assert(data[0] == 42);
        assert(data[1] == 43);
        assert(data[2] == 44);
        assert(data[3] == 45);
    }
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<etl::uint8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
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
