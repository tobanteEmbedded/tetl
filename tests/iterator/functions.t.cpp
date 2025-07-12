// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.algorithm;
import etl.array;
import etl.flat_set;
import etl.functional;
import etl.iterator;
import etl.string_view;
import etl.utility;
import etl.vector;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/flat_set.hpp>
    #include <etl/functional.hpp>
    #include <etl/iterator.hpp>
    #include <etl/string_view.hpp>
    #include <etl/utility.hpp>
    #include <etl/vector.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
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
        CHECK(*etl::rbegin(etl::as_const(data)) == T(4));
        CHECK(*etl::crbegin(data) == T(4));
        CHECK(*(++rbegin(data)) == T(3)); // NOLINT Found via ADL
    }

    // "C array"
    {
        T data[4] = {T(0), T(0), T(0), T(0)};
        auto cmp  = [](auto val) { return val == T(0); };
        CHECK(etl::all_of(etl::rbegin(data), etl::rend(data), cmp));
        CHECK(etl::all_of(etl::crbegin(data), etl::crend(data), cmp));
    }

    // "array"
    {
        auto data = etl::array{T(0), T(0), T(0), T(0)};
        auto cmp  = [](auto val) { return val == T(0); };
        CHECK(etl::all_of(rbegin(data), rend(data), cmp));
        CHECK(etl::all_of(crbegin(data), crend(data), cmp));
        CHECK(etl::all_of(rbegin(etl::as_const(data)), rend(etl::as_const(data)), cmp));
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
        CHECK_FALSE(etl::empty(carr));

        auto arr = etl::array<int, 5>{};
        CHECK_FALSE(etl::empty(arr));

        auto sv1 = etl::string_view{"test"};
        CHECK_FALSE(etl::empty(sv1));

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

static constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    CHECK(test<char>());
    CHECK(test<char8_t>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    CHECK(test<wchar_t>());

    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
