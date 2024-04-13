// SPDX-License-Identifier: BSL-1.0

#include <etl/span.hpp>

#include <etl/algorithm.hpp>
#include <etl/iterator.hpp>
#include <etl/type_traits.hpp>
#include <etl/utility.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        // P2251R1
        CHECK(etl::is_trivially_copyable_v<etl::span<T>>);
        CHECK(etl::is_trivially_copyable_v<etl::span<T const>>);
        CHECK(etl::is_trivially_copyable_v<etl::span<T, 16>>);
        CHECK(etl::is_trivially_copyable_v<etl::span<T const, 16>>);
    }

    {
        CHECK(etl::ranges::borrowed_range<etl::span<T>>);
        CHECK(etl::ranges::borrowed_range<etl::span<T const>>);
        CHECK(etl::ranges::borrowed_range<etl::span<T, 16>>);
        CHECK(etl::ranges::borrowed_range<etl::span<T const, 16>>);
    }

    // ranged-for
    {
        auto data = etl::array<T, 4>{};
        auto sp   = etl::span<T>{etl::begin(data), etl::size(data)};
        CHECK_FALSE(sp.begin() == sp.end());
        CHECK_FALSE(etl::begin(sp) == etl::end(sp));

        auto counter = 0;
        for (auto const& x : sp) {
            etl::ignore_unused(x);
            counter++;
        }
        CHECK(counter == 4);
    }

    // algorithm
    {
        auto data = etl::array<T, 4>{};
        auto sp   = etl::span<T>{etl::begin(data), etl::size(data)};
        CHECK_FALSE(sp.begin() == sp.end());
        CHECK_FALSE(etl::begin(sp) == etl::end(sp));

        auto counter = 0;
        etl::for_each(etl::begin(sp), etl::end(sp), [&counter](auto /*unused*/) { counter++; });
        CHECK(counter == 4);
    }

    {
        auto rng = [i = T{127}]() mutable { return T{i--}; };
        auto vec = etl::static_vector<T, 8>{};
        etl::generate_n(etl::back_inserter(vec), 4, rng);
        auto sp = etl::span<T>{etl::begin(vec), etl::size(vec)};
        CHECK(sp[0] == T{127});
        CHECK(sp[1] == T{126});
        CHECK(sp[2] == T{125});
        CHECK(sp[3] == T{124});

        auto const csp = etl::span{sp};
        CHECK(csp[0] == T{127});
        CHECK(csp[1] == T{126});
        CHECK(csp[2] == T{125});
        CHECK(csp[3] == T{124});
    }

    {
        auto vec = etl::static_vector<T, 6>{};
        etl::generate_n(etl::back_inserter(vec), 4, []() { return T{42}; });
        auto sp = etl::span<T>{etl::begin(vec), etl::size(vec)};

        CHECK(sp.size_bytes() == 4 * sizeof(T));
    }

    {
        auto data = etl::array{T(0), T(1), T(2), T(3), T(4), T(5), T(6)};
        auto sp   = etl::span<T>{data};

        auto one = sp.first(1);
        CHECK(one.size() == 1);
        CHECK(one[0] == T(0));

        auto two = sp.first(2);
        CHECK(two.size() == 2);
        CHECK(two[0] == T(0));
        CHECK(two[1] == T(1));

        auto onet = sp.template first<1>();
        CHECK(onet.size() == 1);
        CHECK(onet[0] == T(0));

        auto twot = sp.template first<2>();
        CHECK(twot.size() == 2);
        CHECK(twot[0] == T(0));
        CHECK(twot[1] == T(1));
    }

    {
        auto data = etl::array{T(0), T(1), T(2), T(3), T(4), T(5), T(6)};
        auto sp   = etl::span<T>{data};

        auto one = sp.last(1);
        CHECK(one.size() == 1);
        CHECK(one[0] == T(6));

        auto two = sp.last(2);
        CHECK(two.size() == 2);
        CHECK(two[0] == T(5));
        CHECK(two[1] == T(6));

        auto onet = sp.template last<1>();
        CHECK(onet.size() == 1);
        CHECK(onet[0] == T(6));

        auto twot = sp.template last<2>();
        CHECK(twot.size() == 2);
        CHECK(twot[0] == T(5));
        CHECK(twot[1] == T(6));
    }

    {
        auto data = etl::array{T(0), T(1), T(2), T(3), T(4), T(5), T(6)};
        auto sp   = etl::span<T>{data};

        auto first = sp.subspan(0, 1);
        CHECK(first.size() == 1);
        CHECK(first[0] == T(0));

        auto first2 = sp.subspan(1, 2);
        CHECK(first2.size() == 2);
        CHECK(first2[0] == T(1));
        CHECK(first2[1] == T(2));

        auto mid = sp.template subspan<0, 1>();
        CHECK(mid.extent == 1);
    }

    return true;
}

template <typename T>
static auto test_as_bytes() -> bool
{
    auto data = etl::array<T, 6>{};
    auto sp   = etl::span<T>{data};
    CHECK(etl::as_bytes(sp).size() == sizeof(T) * data.size());
    CHECK(etl::as_writable_bytes(sp).size() == sizeof(T) * data.size());
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

auto main() -> int
{
    STATIC_CHECK(test_all());

    CHECK(test_as_bytes<signed char>());
    CHECK(test_as_bytes<signed short>());
    CHECK(test_as_bytes<signed int>());
    CHECK(test_as_bytes<signed long>());
    CHECK(test_as_bytes<signed long long>());

    CHECK(test_as_bytes<unsigned char>());
    CHECK(test_as_bytes<unsigned short>());
    CHECK(test_as_bytes<unsigned int>());
    CHECK(test_as_bytes<unsigned long>());
    CHECK(test_as_bytes<unsigned long long>());

    CHECK(test_as_bytes<char>());
    CHECK(test_as_bytes<char8_t>());
    CHECK(test_as_bytes<char16_t>());
    CHECK(test_as_bytes<char32_t>());
    CHECK(test_as_bytes<wchar_t>());

    CHECK(test_as_bytes<float>());
    CHECK(test_as_bytes<double>());
    CHECK(test_as_bytes<long double>());
    return 0;
}
