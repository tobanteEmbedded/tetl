// SPDX-License-Identifier: BSL-1.0

#include <etl/iterator.hpp>

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/cstddef.hpp>
#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::same_as<etl::iter_value_t<typename etl::array<T, 2>::iterator>, T>);
    assert(etl::same_as<etl::iter_value_t<typename etl::array<T, 2>::const_iterator>, T>);
    assert(etl::same_as<etl::iter_value_t<typename etl::array<T, 2>::const_iterator>, T>);

    assert(etl::same_as<etl::iter_difference_t<typename etl::array<T, 2>::iterator>, etl::ptrdiff_t>);
    assert(etl::same_as<etl::iter_difference_t<typename etl::array<T, 2>::const_iterator>, etl::ptrdiff_t>);
    assert(etl::same_as<etl::iter_difference_t<typename etl::array<T, 2>::const_iterator>, etl::ptrdiff_t>);
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