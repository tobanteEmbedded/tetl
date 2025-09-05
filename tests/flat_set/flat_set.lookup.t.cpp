// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/flat_set.hpp>
    #include <etl/functional.hpp>
    #include <etl/iterator.hpp>
    #include <etl/vector.hpp>
#endif

namespace {

template <typename T>
struct Wrapper {
    explicit constexpr Wrapper(T val) noexcept
        : value{val}
    {
    }

    friend constexpr auto operator<(Wrapper lhs, T rhs) -> bool
    {
        return lhs.value < rhs;
    }
    friend constexpr auto operator<(T lhs, Wrapper rhs) -> bool
    {
        return lhs < rhs.value;
    }

    friend constexpr auto operator>(Wrapper lhs, T rhs) -> bool
    {
        return lhs.value > rhs;
    }
    friend constexpr auto operator>(T lhs, Wrapper rhs) -> bool
    {
        return lhs > rhs.value;
    }

    T value;
};

template <typename T, typename Compare>
constexpr auto test_less() -> bool
{
    using vector   = etl::static_vector<T, 4>;
    using flat_set = etl::flat_set<T, vector, Compare>;

    // find
    {
        auto set         = flat_set{};
        auto const& cset = set;

        CHECK(set.find(T(0)) == set.end());
        CHECK(cset.find(T(0)) == cset.end());

        if constexpr (etl::detail::is_transparent_v<Compare>) {
            CHECK(set.find(Wrapper{T(0)}) == set.end());
            CHECK(cset.find(Wrapper{T(0)}) == cset.end());
        }
    }

    {
        auto set         = flat_set{vector({T(0), T(1), T(3)})};
        auto const& cset = set;

        CHECK(set.find(T(0)) == set.begin());
        CHECK(cset.find(T(0)) == cset.begin());
        CHECK(set.find(T(1)) == etl::next(set.begin()));
        CHECK(cset.find(T(1)) == etl::next(cset.begin()));
        CHECK(set.find(T(2)) == set.end());
        CHECK(cset.find(T(2)) == cset.end());

        if constexpr (etl::detail::is_transparent_v<Compare>) {
            CHECK(set.find(Wrapper{T(0)}) == set.begin());
            CHECK(cset.find(Wrapper{T(0)}) == cset.begin());
            CHECK(set.find(Wrapper{T(1)}) == etl::next(set.begin()));
            CHECK(cset.find(Wrapper{T(1)}) == etl::next(cset.begin()));
            CHECK(set.find(Wrapper{T(2)}) == set.end());
            CHECK(cset.find(Wrapper{T(2)}) == cset.end());
        }
    }

    // count
    {
        auto set         = flat_set{};
        auto const& cset = set;

        CHECK(set.count(T(0)) == 0);
        CHECK(cset.count(T(0)) == 0);

        if constexpr (etl::detail::is_transparent_v<Compare>) {
            CHECK(set.count(Wrapper{T(0)}) == 0);
            CHECK(cset.count(Wrapper{T(0)}) == 0);
        }
    }

    {
        auto set         = flat_set{vector({T(0), T(1), T(3)})};
        auto const& cset = set;

        CHECK(set.count(T(0)) == 1);
        CHECK(cset.count(T(0)) == 1);
        CHECK(set.count(T(1)) == 1);
        CHECK(cset.count(T(1)) == 1);
        CHECK(set.count(T(2)) == 0);
        CHECK(cset.count(T(2)) == 0);

        if constexpr (etl::detail::is_transparent_v<Compare>) {
            CHECK(set.count(Wrapper{T(0)}) == 1);
            CHECK(cset.count(Wrapper{T(0)}) == 1);
            CHECK(set.count(Wrapper{T(1)}) == 1);
            CHECK(cset.count(Wrapper{T(1)}) == 1);
            CHECK(set.count(Wrapper{T(2)}) == 0);
            CHECK(cset.count(Wrapper{T(2)}) == 0);
        }
    }

    return true;
}

template <typename T, typename Compare>
constexpr auto test_greater() -> bool
{
    using vector   = etl::static_vector<T, 4>;
    using flat_set = etl::flat_set<T, vector, Compare>;

    // find
    {
        auto set         = flat_set{};
        auto const& cset = set;

        CHECK(set.find(T(0)) == set.end());
        CHECK(cset.find(T(0)) == cset.end());

        if constexpr (etl::detail::is_transparent_v<Compare>) {
            CHECK(set.find(Wrapper{T(0)}) == set.end());
            CHECK(cset.find(Wrapper{T(0)}) == cset.end());
        }
    }

    {
        auto set         = flat_set{vector({T(0), T(1), T(3)})};
        auto const& cset = set;

        CHECK(set.find(T(3)) == set.begin());
        CHECK(cset.find(T(3)) == cset.begin());
        CHECK(set.find(T(1)) == etl::next(set.begin()));
        CHECK(cset.find(T(1)) == etl::next(cset.begin()));
        CHECK(set.find(T(2)) == set.end());
        CHECK(cset.find(T(2)) == cset.end());

        if constexpr (etl::detail::is_transparent_v<Compare>) {
            CHECK(set.find(Wrapper{T(3)}) == set.begin());
            CHECK(cset.find(Wrapper{T(3)}) == cset.begin());
            CHECK(set.find(Wrapper{T(1)}) == etl::next(set.begin()));
            CHECK(cset.find(Wrapper{T(1)}) == etl::next(cset.begin()));
            CHECK(set.find(Wrapper{T(2)}) == set.end());
            CHECK(cset.find(Wrapper{T(2)}) == cset.end());
        }
    }

    // count
    {
        auto set         = flat_set{};
        auto const& cset = set;

        CHECK(set.count(T(0)) == 0);
        CHECK(cset.count(T(0)) == 0);

        if constexpr (etl::detail::is_transparent_v<Compare>) {
            CHECK(set.count(Wrapper{T(0)}) == 0);
            CHECK(cset.count(Wrapper{T(0)}) == 0);
        }
    }

    {
        auto set         = flat_set{vector({T(0), T(1), T(3)})};
        auto const& cset = set;

        CHECK(set.count(T(0)) == 1);
        CHECK(cset.count(T(0)) == 1);
        CHECK(set.count(T(1)) == 1);
        CHECK(cset.count(T(1)) == 1);
        CHECK(set.count(T(2)) == 0);
        CHECK(cset.count(T(2)) == 0);

        if constexpr (etl::detail::is_transparent_v<Compare>) {
            CHECK(set.count(Wrapper{T(0)}) == 1);
            CHECK(cset.count(Wrapper{T(0)}) == 1);
            CHECK(set.count(Wrapper{T(1)}) == 1);
            CHECK(cset.count(Wrapper{T(1)}) == 1);
            CHECK(set.count(Wrapper{T(2)}) == 0);
            CHECK(cset.count(Wrapper{T(2)}) == 0);
        }
    }

    return true;
}

template <typename T>
constexpr auto test_type() -> bool
{
    struct Less {
        [[nodiscard]] constexpr auto operator()(T lhs, T rhs) const -> bool
        {
            return lhs < rhs;
        }
    };

    struct Greater {
        [[nodiscard]] constexpr auto operator()(T lhs, T rhs) const -> bool
        {
            return lhs > rhs;
        }
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
