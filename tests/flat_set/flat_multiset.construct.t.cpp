// SPDX-License-Identifier: BSL-1.0

#include <etl/flat_set.hpp>

#include <etl/functional.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T, typename Compare>
constexpr auto test_less() -> bool
{
    using vector        = etl::static_vector<T, 4>;
    using flat_multiset = etl::flat_multiset<T, vector, Compare>;

    // default
    {
        auto set = flat_multiset{};
        CHECK(set.empty());
        CHECK(set.size() == 0); // NOLINT
        CHECK(set.begin() == set.end());
        CHECK(set.cbegin() == set.cend());
        CHECK(set.rbegin() == set.rend());
        CHECK(set.crbegin() == set.crend());

        auto const& cset = set;
        CHECK(cset.empty());
        CHECK(cset.size() == 0); // NOLINT
        CHECK(cset.begin() == cset.end());
        CHECK(cset.cbegin() == cset.cend());
        CHECK(cset.rbegin() == cset.rend());
        CHECK(cset.crbegin() == cset.crend());
    }

    // from container
    {
        auto empty = flat_multiset{vector({})};
        CHECK(empty.empty());

        auto set = flat_multiset{vector({T(1), T(0), T(2), T(1)})};
        CHECK_FALSE(set.empty());
        CHECK(set.size() == 4);
        CHECK(*set.begin() == T(0));
        CHECK(*etl::prev(set.end()) == T(2));
    }

    // from container sorted_equivalent
    {
        auto set = flat_multiset{vector({T(0), T(1), T(1), T(2)})};
        CHECK_FALSE(set.empty());
        CHECK(set.size() == 4);
        CHECK(*set.begin() == T(0));
        CHECK(*etl::prev(set.end()) == T(2));
    }

    return true;
}

template <typename T, typename Compare>
constexpr auto test_greater() -> bool
{
    using vector        = etl::static_vector<T, 4>;
    using flat_multiset = etl::flat_multiset<T, vector, Compare>;

    // default
    {
        auto set = flat_multiset{};
        CHECK(set.empty());
        CHECK(set.size() == 0); // NOLINT
        CHECK(set.begin() == set.end());
        CHECK(set.cbegin() == set.cend());
        CHECK(set.rbegin() == set.rend());
        CHECK(set.crbegin() == set.crend());

        auto const& cset = set;
        CHECK(cset.empty());
        CHECK(cset.size() == 0); // NOLINT
        CHECK(cset.begin() == cset.end());
        CHECK(cset.cbegin() == cset.cend());
        CHECK(cset.rbegin() == cset.rend());
        CHECK(cset.crbegin() == cset.crend());
    }

    // from container
    {
        auto empty = flat_multiset{vector({})};
        CHECK(empty.empty());

        auto set = flat_multiset{vector({T(1), T(0), T(2), T(1)})};
        CHECK_FALSE(set.empty());
        CHECK(set.size() == 4);
        CHECK(*set.begin() == T(2));
        CHECK(*etl::prev(set.end()) == T(0));
    }

    // from container sorted_equivalent
    {
        auto set = flat_multiset{vector({T(2), T(1), T(1), T(0)})};
        CHECK_FALSE(set.empty());
        CHECK(set.size() == 4);
        CHECK(*set.begin() == T(2));
        CHECK(*etl::prev(set.end()) == T(0));
    }

    return true;
}

template <typename T>
constexpr auto test_type() -> bool
{
    struct Less {
        [[nodiscard]] constexpr auto operator()(T lhs, T rhs) const -> bool { return lhs < rhs; }
    };

    struct Greater {
        [[nodiscard]] constexpr auto operator()(T lhs, T rhs) const -> bool { return lhs > rhs; }
    };

    test_less<T, etl::less<T>>();
    test_less<T, etl::less<>>();
    test_less<T, Less>();

    test_greater<T, etl::greater<T>>();
    test_greater<T, etl::greater<>>();
    test_greater<T, Greater>();

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test_type<signed char>());
    CHECK(test_type<signed short>());
    CHECK(test_type<signed int>());
    CHECK(test_type<signed long>());
    CHECK(test_type<signed long long>());

    CHECK(test_type<unsigned char>());
    CHECK(test_type<unsigned short>());
    CHECK(test_type<unsigned int>());
    CHECK(test_type<unsigned long>());
    CHECK(test_type<unsigned long long>());

    CHECK(test_type<char>());
    CHECK(test_type<char8_t>());
    CHECK(test_type<char16_t>());
    CHECK(test_type<char32_t>());
    CHECK(test_type<wchar_t>());

    CHECK(test_type<float>());
    CHECK(test_type<double>());
    CHECK(test_type<long double>());

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
