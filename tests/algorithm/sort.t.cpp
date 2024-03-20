// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/functional.hpp>
#include <etl/iterator.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test_sort() -> bool
{

    // already sorted
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{2};
        src[2]   = T{3};
        src[3]   = T{4};

        etl::sort(begin(src), end(src), etl::less<T>{});
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // reversed
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{4};
        src[1]   = T{3};
        src[2]   = T{2};
        src[3]   = T{1};

        etl::sort(begin(src), end(src));
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // custom compare
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{1};
        src[2]   = T{56};
        src[3]   = T{42};

        etl::sort(begin(src), end(src), [](auto const& lhs, auto const& rhs) { return lhs > rhs; });
        CHECK(src[0] == T{56});
        CHECK(src[1] == T{42});
        CHECK(src[2] == T{1});
        CHECK(src[3] == T{1});
    }

    // empty range
    {
        auto src = etl::static_vector<T, 4>{};
        CHECK(src.empty());
        etl::stable_sort(begin(src), end(src), etl::less<T>{});
        CHECK(src.empty());
    }

    // already sorted
    {
        auto src = etl::array<T, 4>{T{1}, T{2}, T{3}, T{4}};
        etl::stable_sort(begin(src), end(src));
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // reversed
    {
        auto src = etl::array<T, 4>{T{4}, T{3}, T{2}, T{1}};
        etl::stable_sort(begin(src), end(src));
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // empty range
    {
        auto src = etl::static_vector<T, 4>{};
        CHECK(src.empty());
        etl::partial_sort(begin(src), begin(src), end(src), etl::less<T>{});
        CHECK(src.empty());
    }

    // already sorted
    {
        auto src = etl::array<T, 4>{T{1}, T{2}, T{3}, T{4}};
        etl::partial_sort(begin(src), begin(src) + 2, end(src));
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
    }

    // reversed
    {
        auto src = etl::array<T, 4>{T{4}, T{3}, T{2}, T{1}};
        etl::partial_sort(begin(src), begin(src) + 2, end(src));
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
    }

    // empty range
    {
        auto src = etl::static_vector<T, 4>{};
        CHECK(src.empty());
        etl::nth_element(begin(src), begin(src), end(src));
        CHECK(src.empty());
    }

    // already sorted
    {
        auto src = etl::array<T, 4>{T{1}, T{2}, T{3}, T{4}};
        etl::nth_element(begin(src), begin(src) + 1, end(src), etl::less{});
        CHECK(src[1] == T{2});
    }

    // reversed
    {
        auto src = etl::array<T, 4>{T{4}, T{3}, T{2}, T{1}};
        etl::nth_element(begin(src), begin(src) + 1, end(src));
        CHECK(src[1] == T{2});
    }

    // already is_sorteded
    {
        auto src = etl::array<T, 4>{
            T{1},
            T{2},
            T{3},
            T{4},
        };

        CHECK(etl::is_sorted(begin(src), end(src), etl::less<T>{}));
    }

    // reversed
    {
        auto src = etl::array<T, 4>{
            T{4},
            T{3},
            T{2},
            T{1},
        };

        CHECK(etl::is_sorted(begin(src), end(src), etl::greater{}));
        CHECK_FALSE(etl::is_sorted(begin(src), end(src)));
    }

    // custom compare
    {
        auto src = etl::array<T, 4>{
            T{1},
            T{1},
            T{56},
            T{42},
        };

        CHECK_FALSE(etl::is_sorted(begin(src), end(src), etl::greater{}));
    }

    // empty range always returns true
    {
        auto data      = etl::static_vector<T, 1>{};
        auto predicate = [](auto const& val) { return val < T(1); };
        CHECK(etl::is_partitioned(begin(data), end(data), predicate));
    }

    // true
    {
        auto predicate = [](auto const& val) { return val < T(1); };

        auto test1 = etl::array{T(2), T(2), T(2)};
        CHECK(etl::is_partitioned(begin(test1), end(test1), predicate));

        auto test2 = etl::array{T(0), T(0), T(2), T(3)};
        CHECK(etl::is_partitioned(begin(test2), end(test2), predicate));

        auto test3 = etl::array{T(1), T(1), T(2)};
        CHECK(etl::is_partitioned(begin(test3), end(test3), predicate));
    }

    // false
    {
        auto predicate = [](auto const& val) { return val < T(1); };

        auto test1 = etl::array{T(2), T(0), T(2)};
        CHECK_FALSE(etl::is_partitioned(begin(test1), end(test1), predicate));

        auto test2 = etl::array{T(0), T(0), T(2), T(0)};
        CHECK_FALSE(etl::is_partitioned(begin(test2), end(test2), predicate));
    }

    return true;
}

template <typename T>
constexpr auto test_bubble_sort() -> bool
{

    // already bubble_sorted
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{2};
        src[2]   = T{3};
        src[3]   = T{4};

        etl::bubble_sort(begin(src), end(src), etl::less<T>{});
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // reversed
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{4};
        src[1]   = T{3};
        src[2]   = T{2};
        src[3]   = T{1};

        etl::bubble_sort(begin(src), end(src));
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // custom compare
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{1};
        src[2]   = T{56};
        src[3]   = T{42};

        etl::bubble_sort(begin(src), end(src), [](auto const& lhs, auto const& rhs) { return lhs > rhs; });
        CHECK(src[0] == T{56});
        CHECK(src[1] == T{42});
        CHECK(src[2] == T{1});
        CHECK(src[3] == T{1});
    }

    return true;
}

template <typename T>
constexpr auto test_insertion_sort() -> bool
{

    // already insertion_sorted
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{2};
        src[2]   = T{3};
        src[3]   = T{4};

        etl::insertion_sort(begin(src), end(src), etl::less<T>{});
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // reversed
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{4};
        src[1]   = T{3};
        src[2]   = T{2};
        src[3]   = T{1};

        etl::insertion_sort(begin(src), end(src));
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // custom compare
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{1};
        src[2]   = T{56};
        src[3]   = T{42};

        etl::insertion_sort(begin(src), end(src), [](auto const& lhs, auto const& rhs) { return lhs > rhs; });
        CHECK(src[0] == T{56});
        CHECK(src[1] == T{42});
        CHECK(src[2] == T{1});
        CHECK(src[3] == T{1});
    }

    return true;
}

template <typename T>
constexpr auto test_merge_sort() -> bool
{

    // already merge_sorted
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{2};
        src[2]   = T{3};
        src[3]   = T{4};

        etl::merge_sort(begin(src), end(src), etl::less<T>{});
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // reversed
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{4};
        src[1]   = T{3};
        src[2]   = T{2};
        src[3]   = T{1};

        etl::merge_sort(begin(src), end(src));
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // custom compare
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{1};
        src[2]   = T{56};
        src[3]   = T{42};

        etl::merge_sort(begin(src), end(src), [](auto const& lhs, auto const& rhs) { return lhs > rhs; });
        CHECK(src[0] == T{56});
        CHECK(src[1] == T{42});
        CHECK(src[2] == T{1});
        CHECK(src[3] == T{1});
    }

    return true;
}

template <typename T>
constexpr auto test_gnome_sort() -> bool
{

    // already gnome_sorted
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{2};
        src[2]   = T{3};
        src[3]   = T{4};

        etl::gnome_sort(begin(src), end(src), etl::less<T>{});
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // reversed
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{4};
        src[1]   = T{3};
        src[2]   = T{2};
        src[3]   = T{1};

        etl::gnome_sort(begin(src), end(src));
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // custom compare
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{1};
        src[2]   = T{56};
        src[3]   = T{42};

        etl::gnome_sort(begin(src), end(src), [](auto const& lhs, auto const& rhs) { return lhs > rhs; });
        CHECK(src[0] == T{56});
        CHECK(src[1] == T{42});
        CHECK(src[2] == T{1});
        CHECK(src[3] == T{1});
    }

    return true;
}

template <typename T>
constexpr auto test_exchange_sort() -> bool
{

    // already exchange_sorted
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{2};
        src[2]   = T{3};
        src[3]   = T{4};

        etl::exchange_sort(begin(src), end(src), etl::less<T>{});
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // reversed
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{4};
        src[1]   = T{3};
        src[2]   = T{2};
        src[3]   = T{1};

        etl::exchange_sort(begin(src), end(src));
        CHECK(src[0] == T{1});
        CHECK(src[1] == T{2});
        CHECK(src[2] == T{3});
        CHECK(src[3] == T{4});
    }

    // custom compare
    {
        auto src = etl::array<T, 4>{};
        src[0]   = T{1};
        src[1]   = T{1};
        src[2]   = T{56};
        src[3]   = T{42};

        etl::exchange_sort(begin(src), end(src), [](auto const& lhs, auto const& rhs) { return lhs > rhs; });
        CHECK(src[0] == T{56});
        CHECK(src[1] == T{42});
        CHECK(src[2] == T{1});
        CHECK(src[3] == T{1});
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test_sort<etl::uint8_t>());
    CHECK(test_sort<etl::int8_t>());
    CHECK(test_sort<etl::uint16_t>());
    CHECK(test_sort<etl::int16_t>());
    CHECK(test_sort<etl::uint32_t>());
    CHECK(test_sort<etl::int32_t>());
    CHECK(test_sort<etl::uint64_t>());
    CHECK(test_sort<etl::int64_t>());
    CHECK(test_sort<float>());
    CHECK(test_sort<double>());

    CHECK(test_bubble_sort<etl::uint8_t>());
    CHECK(test_bubble_sort<etl::int8_t>());
    CHECK(test_bubble_sort<etl::uint16_t>());
    CHECK(test_bubble_sort<etl::int16_t>());
    CHECK(test_bubble_sort<etl::uint32_t>());
    CHECK(test_bubble_sort<etl::int32_t>());
    CHECK(test_bubble_sort<etl::uint64_t>());
    CHECK(test_bubble_sort<etl::int64_t>());
    CHECK(test_bubble_sort<float>());
    CHECK(test_bubble_sort<double>());

    CHECK(test_insertion_sort<etl::uint8_t>());
    CHECK(test_insertion_sort<etl::int8_t>());
    CHECK(test_insertion_sort<etl::uint16_t>());
    CHECK(test_insertion_sort<etl::int16_t>());
    CHECK(test_insertion_sort<etl::uint32_t>());
    CHECK(test_insertion_sort<etl::int32_t>());
    CHECK(test_insertion_sort<etl::uint64_t>());
    CHECK(test_insertion_sort<etl::int64_t>());
    CHECK(test_insertion_sort<float>());
    CHECK(test_insertion_sort<double>());

    CHECK(test_merge_sort<etl::uint8_t>());
    CHECK(test_merge_sort<etl::int8_t>());
    CHECK(test_merge_sort<etl::uint16_t>());
    CHECK(test_merge_sort<etl::int16_t>());
    CHECK(test_merge_sort<etl::uint32_t>());
    CHECK(test_merge_sort<etl::int32_t>());
    CHECK(test_merge_sort<etl::uint64_t>());
    CHECK(test_merge_sort<etl::int64_t>());
    CHECK(test_merge_sort<float>());
    CHECK(test_merge_sort<double>());

    CHECK(test_gnome_sort<etl::uint8_t>());
    CHECK(test_gnome_sort<etl::int8_t>());
    CHECK(test_gnome_sort<etl::uint16_t>());
    CHECK(test_gnome_sort<etl::int16_t>());
    CHECK(test_gnome_sort<etl::uint32_t>());
    CHECK(test_gnome_sort<etl::int32_t>());
    CHECK(test_gnome_sort<etl::uint64_t>());
    CHECK(test_gnome_sort<etl::int64_t>());
    CHECK(test_gnome_sort<float>());
    CHECK(test_gnome_sort<double>());

    CHECK(test_exchange_sort<etl::uint8_t>());
    CHECK(test_exchange_sort<etl::int8_t>());
    CHECK(test_exchange_sort<etl::uint16_t>());
    CHECK(test_exchange_sort<etl::int16_t>());
    CHECK(test_exchange_sort<etl::uint32_t>());
    CHECK(test_exchange_sort<etl::int32_t>());
    CHECK(test_exchange_sort<etl::uint64_t>());
    CHECK(test_exchange_sort<etl::int64_t>());
    CHECK(test_exchange_sort<float>());
    CHECK(test_exchange_sort<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
