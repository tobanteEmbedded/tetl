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
    using vec_t = etl::static_vector<T, 8>;
    using set_t = etl::flat_set<T, vec_t, etl::less<>>;

    auto s1 = set_t{};
    CHECK(s1.size() == 0); // NOLINT
    CHECK(s1.empty());
    CHECK(s1.begin() == s1.end());
    CHECK(etl::as_const(s1).begin() == etl::as_const(s1).end());
    CHECK(s1.cbegin() == s1.cend());
    CHECK(s1.max_size() == 8);
    CHECK_FALSE(s1.contains(T(0)));

    auto s2 = set_t{vec_t{}};
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
