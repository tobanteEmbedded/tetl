// SPDX-License-Identifier: BSL-1.0

#include <etl/iterator.hpp>

#include <etl/algorithm.hpp>
#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/string_view.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using etl::all_of;
    using etl::as_const;

    // "C array"
    {
        T data[4] = {T(1), T(2), T(3), T(4)};
        CHECK(*etl::rbegin(data) == T(4));
        CHECK(*(++etl::rbegin(data)) == T(3)); // NOLINT
    }

    // "array"
    {
        auto data = etl::array{T(1), T(2), T(3), T(4)};
        CHECK(*etl::rbegin(data) == T(4));
        CHECK(*etl::rbegin(as_const(data)) == T(4));
        CHECK(*etl::crbegin(data) == T(4));
        CHECK(*(++rbegin(data)) == T(3)); // NOLINT Found via ADL
    }

    // "C array"
    {
        T data[4] = {T(0), T(0), T(0), T(0)};
        auto cmp  = [](auto val) { return val == T(0); };
        CHECK(all_of(etl::rbegin(data), etl::rend(data), cmp));
        CHECK(all_of(etl::crbegin(data), etl::crend(data), cmp));
    }

    // "array"
    {
        auto data = etl::array{T(0), T(0), T(0), T(0)};
        auto cmp  = [](auto val) { return val == T(0); };
        CHECK(all_of(rbegin(data), rend(data), cmp));
        CHECK(all_of(crbegin(data), crend(data), cmp));
        CHECK(all_of(rbegin(as_const(data)), rend(as_const(data)), cmp));
    }

    // "iterator: size
    {
        int carr[4] = {};
        CHECK(etl::size(carr) == 4);

        auto arr = etl::array<int, 5>{};
        CHECK(etl::size(arr) == 5);

        auto sv1 = etl::string_view{"test"};
        CHECK(etl::size(sv1) == 4);

        auto const sv2 = etl::string_view{};
        CHECK(etl::size(sv2) == 0);
    }

    // "iterator: empty
    {
        int carr[4] = {};
        CHECK(!etl::empty(carr));

        auto arr = etl::array<int, 5>{};
        CHECK(!etl::empty(arr));

        auto sv1 = etl::string_view{"test"};
        CHECK(!etl::empty(sv1));

        auto const sv2 = etl::string_view{};
        CHECK(etl::empty(sv2));
    }

    // "iterator: data
    {
        int carr[4] = {};
        CHECK(etl::data(carr) != nullptr);

        auto arr = etl::array<int, 5>{};
        CHECK(etl::data(arr) != nullptr);

        auto sv1 = etl::string_view{"test"};
        CHECK(etl::data(sv1) != nullptr);

        auto const sv2 = etl::string_view{};
        CHECK(etl::data(sv2) == nullptr);
    }

    // "random access iterator"
    {
        auto arr = etl::array<T, 5>{};
        CHECK(etl::distance(begin(arr), begin(arr)) == 0);
        CHECK(etl::distance(end(arr), end(arr)) == 0);
        CHECK(etl::distance(begin(arr), begin(arr) + 2) == 2);
        CHECK(etl::distance(begin(arr), end(arr)) == 5);
    }

    // "random access iterator"
    {
        auto arr = etl::array<T, 5>{};
        auto* p  = arr.begin();

        etl::advance(p, 1);
        CHECK(p != begin(arr));
        CHECK(p == &arr[1]);

        etl::advance(p, 2);
        CHECK(p == &arr[3]);
    }

    // "random access iterator"
    {
        auto arr = etl::array<T, 5>{};
        auto* p  = arr.begin();
        auto* n1 = etl::next(p);
        CHECK(n1 != begin(arr));
        CHECK(n1 == &arr[1]);

        auto* n2 = etl::next(n1);
        CHECK(n2 != begin(arr));
        CHECK(n2 == &arr[2]);
    }

    // "random access iterator"
    {
        auto arr = etl::array<T, 5>{};
        auto* p  = arr.end();
        auto* n1 = etl::prev(p);
        CHECK(n1 != end(arr));
        CHECK(n1 == &arr[4]);

        auto* n2 = etl::prev(n1);
        CHECK(n2 != end(arr));
        CHECK(n2 == &arr[3]);
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<float>());
    CHECK(test<double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
