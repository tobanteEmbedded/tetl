/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/iterator.hpp"

#include "etl/algorithm.hpp"
#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/string_view.hpp"
#include "etl/utility.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using etl::all_of;
    using etl::as_const;

    // "C array"
    {
        T data[4] = { T(1), T(2), T(3), T(4) };
        assert(*etl::rbegin(data) == T(4));
        assert(*(++etl::rbegin(data)) == T(3)); // NOLINT
    }

    // "array"
    {
        auto data = etl::array { T(1), T(2), T(3), T(4) };
        assert(*etl::rbegin(data) == T(4));
        assert(*etl::rbegin(as_const(data)) == T(4));
        assert(*etl::crbegin(data) == T(4));
        assert(*(++rbegin(data)) == T(3)); // NOLINT Found via ADL
    }

    // "C array"
    {
        T data[4] = { T(0), T(0), T(0), T(0) };
        auto cmp  = [](auto val) { return val == T(0); };
        assert(all_of(etl::rbegin(data), etl::rend(data), cmp));
        assert(all_of(etl::crbegin(data), etl::crend(data), cmp));
    }

    // "array"
    {
        auto data = etl::array { T(0), T(0), T(0), T(0) };
        auto cmp  = [](auto val) { return val == T(0); };
        assert(all_of(rbegin(data), rend(data), cmp));
        assert(all_of(crbegin(data), crend(data), cmp));
        assert(all_of(rbegin(as_const(data)), rend(as_const(data)), cmp));
    }

    // "iterator: size
    {
        int carr[4] = {};
        assert(etl::size(carr) == 4);

        auto arr = etl::array<int, 5> {};
        assert(etl::size(arr) == 5);

        auto sv1 = etl::string_view { "test" };
        assert(etl::size(sv1) == 4);

        auto const sv2 = etl::string_view {};
        assert(etl::size(sv2) == 0);
    }

    // "iterator: empty
    {
        int carr[4] = {};
        assert(!etl::empty(carr));

        auto arr = etl::array<int, 5> {};
        assert(!etl::empty(arr));

        auto sv1 = etl::string_view { "test" };
        assert(!etl::empty(sv1));

        auto const sv2 = etl::string_view {};
        assert(etl::empty(sv2));
    }

    // "iterator: data
    {
        int carr[4] = {};
        assert(etl::data(carr) != nullptr);

        auto arr = etl::array<int, 5> {};
        assert(etl::data(arr) != nullptr);

        auto sv1 = etl::string_view { "test" };
        assert(etl::data(sv1) != nullptr);

        auto const sv2 = etl::string_view {};
        assert(etl::data(sv2) == nullptr);
    }

    // "random access iterator"
    {
        auto arr = etl::array<T, 5> {};
        assert(etl::distance(begin(arr), begin(arr)) == 0);
        assert(etl::distance(end(arr), end(arr)) == 0);
        assert(etl::distance(begin(arr), begin(arr) + 2) == 2);
        assert(etl::distance(begin(arr), end(arr)) == 5);
    }

    // "random access iterator"
    {
        auto arr = etl::array<T, 5> {};
        auto* p  = arr.begin();

        etl::advance(p, 1);
        assert(p != begin(arr));
        assert(p == &arr[1]);

        etl::advance(p, 2);
        assert(p == &arr[3]);
    }

    // "random access iterator"
    {
        auto arr = etl::array<T, 5> {};
        auto* p  = arr.begin();
        auto* n1 = etl::next(p);
        assert(n1 != begin(arr));
        assert(n1 == &arr[1]);

        auto* n2 = etl::next(n1);
        assert(n2 != begin(arr));
        assert(n2 == &arr[2]);
    }

    // "random access iterator"
    {
        auto arr = etl::array<T, 5> {};
        auto* p  = arr.end();
        auto* n1 = etl::prev(p);
        assert(n1 != end(arr));
        assert(n1 == &arr[4]);

        auto* n2 = etl::prev(n1);
        assert(n2 != end(arr));
        assert(n2 == &arr[3]);
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