// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.array;
import etl.flat_set;
import etl.functional;
import etl.iterator;
import etl.utility;
import etl.vector;
#else
    #include <etl/array.hpp>
    #include <etl/flat_set.hpp>
    #include <etl/functional.hpp>
    #include <etl/iterator.hpp>
    #include <etl/utility.hpp>
    #include <etl/vector.hpp>
#endif

namespace {

template <typename T>
struct Wrapper {
    explicit constexpr Wrapper(T val) noexcept
        : value{val}
    {
    }

    friend constexpr auto operator<(Wrapper lhs, T rhs) -> bool { return lhs.value < rhs; }

    friend constexpr auto operator<(T lhs, Wrapper rhs) -> bool { return lhs < rhs.value; }

    T value;
};

template <typename T>
constexpr auto test() -> bool
{
    using vector   = etl::static_vector<T, 8>;
    using flat_set = etl::flat_set<T, vector, etl::less<>>;

    auto s2 = flat_set{vector{}};
    CHECK(s2.size() == 0); // NOLINT
    CHECK(s2.begin() == s2.end());
    CHECK(s2.empty());
    CHECK(s2.max_size() == 8);
    CHECK(s2.find(T(42)) == etl::end(s2));
    CHECK(s2.count(T(42)) == 0);
    CHECK_FALSE(s2.contains(T(42)));
    CHECK_FALSE(s2.contains(Wrapper{T(42)}));

    auto r1 = s2.emplace(T(42));
    CHECK(r1.second);
    CHECK(s2.size() == 1);
    CHECK(s2.find(T(42)) == etl::begin(s2));
    CHECK(s2.count(T(42)) == 1);
    CHECK(s2.contains(T(42)));
    CHECK(s2.contains(Wrapper{T(42)}));

    auto r2 = s2.insert(T(42));
    CHECK_FALSE(r2.second);
    CHECK(s2.size() == 1);
    CHECK(s2.find(T(42)) == etl::begin(s2));

    auto v = etl::array<T, 3>{T(1), T(2), T(3)};
    s2.insert(v.begin(), v.end());
    CHECK(s2.size() == 4);
    CHECK(s2.upper_bound(T(0)) == s2.begin());
    CHECK(s2.upper_bound(Wrapper{T(0)}) == s2.begin());

    auto const& cs2 = s2;
    CHECK(cs2.upper_bound(T(1)) == etl::next(cs2.begin()));
    CHECK(cs2.upper_bound(Wrapper{T(1)}) == etl::next(cs2.begin()));
    CHECK(cs2 == s2);

    CHECK(etl::erase_if(s2, [](auto x) { return x > T(100); }) == 0);
    CHECK(etl::erase_if(s2, [](auto x) { return x == T(3); }) == 1);
    CHECK(s2.size() == 3);

    CHECK(s2.erase(T(100)) == 0);
    CHECK(s2.erase(T(2)) == 1);
    CHECK(s2.size() == 2);

    auto other = flat_set{};
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
    auto const s3   = flat_set{etl::sorted_unique, data.begin(), data.end()};
    CHECK(s3.size() == 3);

    auto s4 = flat_set{etl::sorted_unique, vector({T(1), T(2), T(3)})};
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

    s4.clear();
    CHECK(s4.empty());

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
