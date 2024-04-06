// SPDX-License-Identifier: BSL-1.0

#include <etl/flat_set.hpp>

#include <etl/utility.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T>
struct wrapper {
    explicit constexpr wrapper(T val) noexcept : value{val} { }

    friend constexpr auto operator<(wrapper lhs, T rhs) -> bool { return lhs.value < rhs; }

    friend constexpr auto operator<(T lhs, wrapper rhs) -> bool { return lhs < rhs.value; }

    T value;
};

template <typename T>
constexpr auto test() -> bool
{
    using vector_t = etl::static_vector<T, 8>;
    using set_t    = etl::flat_set<T, vector_t, etl::less<>>;

    CHECK_SAME_TYPE(typename set_t::key_type, T);
    CHECK_SAME_TYPE(typename set_t::key_compare, etl::less<>);
    CHECK_SAME_TYPE(typename set_t::value_type, T);
    CHECK_SAME_TYPE(typename set_t::value_compare, etl::less<>);
    CHECK_SAME_TYPE(typename set_t::reference, T&);
    CHECK_SAME_TYPE(typename set_t::const_reference, T const&);
    CHECK_SAME_TYPE(typename set_t::size_type, typename vector_t::size_type);
    CHECK_SAME_TYPE(typename set_t::difference_type, typename vector_t::difference_type);
    CHECK_SAME_TYPE(typename set_t::iterator, typename vector_t::iterator);
    CHECK_SAME_TYPE(typename set_t::const_iterator, typename vector_t::const_iterator);
    CHECK_SAME_TYPE(typename set_t::reverse_iterator, etl::reverse_iterator<typename vector_t::iterator>);
    CHECK_SAME_TYPE(typename set_t::const_reverse_iterator, etl::reverse_iterator<typename vector_t::const_iterator>);
    CHECK_SAME_TYPE(typename set_t::container_type, vector_t);

    auto s1 = set_t{};
    CHECK(s1.size() == 0); // NOLINT
    CHECK(s1.empty());
    CHECK(s1.begin() == s1.end());
    CHECK(etl::as_const(s1).begin() == etl::as_const(s1).end());
    CHECK(s1.cbegin() == s1.cend());
    CHECK(s1.max_size() == 8);
    CHECK_FALSE(s1.contains(T(0)));

    auto s2 = set_t{vector_t{}};
    CHECK(s2.size() == 0); // NOLINT
    CHECK(s2.begin() == s2.end());
    CHECK(s1.begin() != s2.begin());
    CHECK(s1.end() != s2.end());
    CHECK(s2.empty());
    CHECK(s2.max_size() == 8);
    CHECK(s2.find(T(42)) == etl::end(s2));
    CHECK(s2.count(T(42)) == 0);
    CHECK_FALSE(s2.contains(T(42)));
    CHECK_FALSE(s2.contains(wrapper{T(42)}));

    auto r1 = s2.emplace(T(42));
    CHECK(r1.second);
    CHECK(s2.size() == 1);
    CHECK(s2.find(T(42)) == etl::begin(s2));
    CHECK(s2.count(T(42)) == 1);
    CHECK(s2.contains(T(42)));
    CHECK(s2.contains(wrapper{T(42)}));

    auto r2 = s2.insert(T(42));
    CHECK_FALSE(r2.second);
    CHECK(s2.size() == 1);
    CHECK(s2.find(T(42)) == etl::begin(s2));

    auto v = etl::array<T, 3>{T(1), T(2), T(3)};
    s2.insert(v.begin(), v.end());
    CHECK(s2.size() == 4);
    CHECK(s2.upper_bound(T(0)) == s2.begin());
    CHECK(s2.upper_bound(wrapper{T(0)}) == s2.begin());

    auto const& cs2 = s2;
    CHECK(cs2.upper_bound(T(1)) == etl::next(cs2.begin()));
    CHECK(cs2.upper_bound(wrapper{T(1)}) == etl::next(cs2.begin()));
    CHECK(cs2 == s2);
    CHECK(cs2 != s1);

    CHECK(etl::erase_if(s2, [](auto x) { return x > T(100); }) == 0);
    CHECK(etl::erase_if(s2, [](auto x) { return x == T(3); }) == 1);
    CHECK(s2.size() == 3);

    CHECK(s2.erase(T(100)) == 0);
    CHECK(s2.erase(T(2)) == 1);
    CHECK(s2.size() == 2);

    auto other = set_t{};
    swap(other, s2);
    CHECK(s2.empty());
    CHECK(other.size() == 2);

    CHECK(*other.rbegin() == T(42));
    CHECK(*etl::next(other.rbegin()) == T(1));
    CHECK(etl::next(other.rbegin(), 2) == other.rend());
    CHECK(etl::distance(other.rbegin(), other.rend()) == 2);
    CHECK(etl::distance(etl::as_const(other).rbegin(), etl::as_const(other).rend()) == 2);
    CHECK(etl::distance(other.crbegin(), other.crend()) == 2);
    CHECK(etl::distance(other.begin(), other.end()) == 2);
    CHECK(etl::distance(other.cbegin(), other.cend()) == 2);

    auto const data = etl::array{T(1), T(2), T(3)};
    auto const s3   = set_t{etl::sorted_unique, data.begin(), data.end()};
    CHECK(s3.size() == 3);

    auto s4 = set_t{etl::sorted_unique, vector_t({T(1), T(2), T(3)})};
    CHECK(s4.size() == 3);
    CHECK(s3 == s4);
    CHECK(s3 >= s4);
    CHECK(s3 <= s4);
    CHECK_FALSE(s3 != s4);
    CHECK_FALSE(s3 < s4);
    CHECK_FALSE(s3 > s4);

    auto it = s4.insert(s4.end(), T(4));
    CHECK(*it == T(4));
    CHECK(s4.size() == 4);
    CHECK(s3 != s4);
    CHECK(s3 < s4);
    CHECK(s3 <= s4);
    CHECK_FALSE(s3 == s4);
    CHECK_FALSE(s3 >= s4);
    CHECK_FALSE(s3 > s4);

    s4.erase(it);
    CHECK(s4.size() == 3);
    CHECK(s3 == s4);

    return true;
}

constexpr auto test_all() -> bool
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
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
