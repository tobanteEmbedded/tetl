/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/iterator.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto data = etl::array { T(1), T(2), T(3) };
    assert((*data.rbegin() == *etl::make_reverse_iterator(data.end())));
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

    // TODO: [tobi] Enable constexpr tests. Fails gcc-9,
    // but passes gcc-11 & clang-13
    // static_assert(test_all());
    return 0;
}