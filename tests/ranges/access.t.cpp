// SPDX-License-Identifier: BSL-1.0

#include <etl/ranges.hpp>

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>
#include <etl/memory.hpp>
#include <etl/string_view.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::ranges::range<etl::string_view>);
    assert(etl::ranges::sized_range<etl::string_view>);
    assert(etl::same_as<etl::ranges::range_size_t<etl::string_view>, etl::size_t>);
    assert(etl::same_as<etl::ranges::sentinel_t<etl::string_view>, etl::ranges::iterator_t<etl::string_view>>);

    {
        T data[2] {T(1), T(2)};
        assert(etl::ranges::range<decltype(data)>);
        assert(etl::ranges::sized_range<decltype(data)>);
        assert(etl::same_as<etl::ranges::range_size_t<decltype(data)>, etl::size_t>);
        assert(etl::same_as<etl::ranges::sentinel_t<decltype(data)>, etl::ranges::iterator_t<decltype(data)>>);
        assert(etl::ranges::size(data) == 2);
        assert(etl::ranges::begin(data) == etl::addressof(data[0]));
        assert(etl::ranges::end(data) == etl::next(etl::addressof(data[0]), 2));
    }

    {
        auto data = etl::to_array<T>({1, 2, 3});
        assert(etl::ranges::range<decltype(data)>);
        assert(etl::ranges::sized_range<decltype(data)>);
        assert(etl::same_as<etl::ranges::range_size_t<decltype(data)>, etl::size_t>);
        assert(etl::same_as<etl::ranges::sentinel_t<decltype(data)>, etl::ranges::iterator_t<decltype(data)>>);
        assert(etl::ranges::begin(data) == data.begin());
        assert(etl::ranges::end(data) == data.end());
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
