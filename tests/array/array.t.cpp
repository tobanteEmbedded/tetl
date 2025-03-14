// SPDX-License-Identifier: BSL-1.0

#include <etl/array.hpp>

#include <etl/algorithm.hpp>
#include <etl/numeric.hpp>
#include <etl/type_traits.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    {
        etl::array<T, 0> a{};
        etl::array<T, 0> b{};
        auto const& ca = a;
        auto const& cb = b;

        CHECK(a.empty());
        CHECK(a.size() == 0);
        CHECK(a.max_size() == 0);

        CHECK(ca.empty());
        CHECK(ca.size() == 0);
        CHECK(ca.max_size() == 0);

        CHECK(a.begin() == a.end());
        CHECK(a.begin() == b.begin());
        CHECK(a.begin() == b.end());

        CHECK(ca.begin() == ca.end());
        CHECK(ca.begin() == cb.begin());
        CHECK(ca.begin() == cb.end());
    }

    {
        etl::array<T, 2> a{};
        CHECK(a.empty() == false);
        CHECK(a.size() == 2);
        CHECK(a.max_size() == 2);
        CHECK(a[0] == T{0});
        CHECK(a[1] == T{0});
    }

    {
        auto const x = T{10};
        auto a       = etl::array{T{1}, T{2}, x};
        CHECK(a.size() == 3);
        CHECK(a.max_size() == 3);

        CHECK(a.front() == T{1});
        CHECK(a.back() == x);
        CHECK(a[0] == T{1});
        CHECK(a[1] == T{2});
        CHECK(a[2] == x);

        auto const& ac = a;
        CHECK(ac.front() == T{1});
        CHECK(ac.back() == x);
        CHECK(ac[0] == T{1});
        CHECK(ac[1] == T{2});
        CHECK(ac[2] == x);
    }

    {
        etl::array<T, 4> arr{};
        etl::iota(etl::begin(arr), etl::end(arr), T{0});

        CHECK(*arr.data() == T(0));
        CHECK(arr.front() == T(0));
        CHECK(arr.back() == T(3));

        auto counter = 0;
        for (auto& x : arr) {
            CHECK(x == static_cast<T>(counter));
            ++counter;
        }

        counter = 0;
        for (auto const x : etl::as_const(arr)) {
            CHECK(x == static_cast<T>(counter));
            ++counter;
        }
    }

    {
        // swap
        etl::array<T, 4> a{};
        a.fill(T{1});
        etl::array<T, 4> b{};

        CHECK(etl::all_of(a.begin(), a.end(), [](auto val) { return val == 1; }));
        CHECK(etl::all_of(begin(b), end(b), [](auto val) { return val == 0; }));

        a.swap(b);
        CHECK(etl::all_of(a.begin(), a.end(), [](auto val) { return val == 0; }));
        CHECK(etl::all_of(begin(b), end(b), [](auto val) { return val == 1; }));

        etl::swap(a, b);
        CHECK(etl::all_of(a.begin(), a.end(), [](auto val) { return val == 1; }));
        CHECK(etl::all_of(begin(b), end(b), [](auto val) { return val == 0; }));
    }

    {
        auto arr = etl::array{T(1), T(2), T(3)};
        auto it  = arr.rbegin();

        CHECK(*it == T(3));
        ++it;
        CHECK(*it == T(2));
        it++;
        CHECK(*it == T(1));
    }

    { // not eqaul
        etl::array<T, 3> lhs{T{1}, T{2}, T{3}};
        etl::array<T, 3> rhs{T{7}, T{8}, T{9}};

        CHECK_FALSE(lhs == rhs);
        CHECK(lhs != rhs);
        CHECK(lhs < rhs);
        CHECK(lhs <= rhs);
        CHECK_FALSE(lhs > rhs);
        CHECK_FALSE(lhs >= rhs);
    }

    {
        // eqaul
        etl::array<T, 3> lhs{T{1}, T{2}, T{3}};
        etl::array<T, 3> rhs{T{1}, T{2}, T{3}};

        CHECK(lhs == rhs);
        CHECK_FALSE(lhs != rhs);
        CHECK_FALSE(lhs < rhs);
        CHECK(lhs <= rhs);
        CHECK_FALSE(lhs > rhs);
        CHECK(lhs >= rhs);
    }

    {
        // tuple_size
        CHECK(etl::tuple_size<etl::array<T, 1>>::value == 1);

        CHECK(etl::tuple_size_v<etl::array<T, 2>> == 2);
        CHECK(etl::tuple_size_v<etl::array<T, 3>> == 3);

        auto arr4 = etl::array{T(1), T(2), T(3), T(4)};
        CHECK(etl::tuple_size_v<decltype(arr4)> == 4);

        auto arr5 = etl::array{1, 2, 3, 4, 5};
        CHECK(etl::tuple_size_v<decltype(arr5)> == 5);
    }

    {
        CHECK_SAME_TYPE(typename etl::tuple_element<1, etl::array<T, 2>>::type, T);
    }

    {
        // get
        auto a         = etl::array<T, 3>{};
        auto const& ca = a;

        etl::get<0>(a) = T{1};
        etl::get<1>(a) = T{2};
        etl::get<2>(a) = T{3};

        CHECK(etl::get<0>(a) == T{1});
        CHECK(etl::get<1>(a) == T{2});
        CHECK(etl::get<2>(a) == T{3});

        CHECK(etl::get<0>(ca) == T{1});
        CHECK(etl::get<1>(ca) == T{2});
        CHECK(etl::get<2>(ca) == T{3});

        CHECK(etl::get<0>(etl::array{T(0), T(1)}) == T{0});
        CHECK(etl::get<1>(etl::array{T(0), T(1)}) == T{1});
    }
    {
        // to_array

        // copies a string literal
        auto a1 = etl::to_array("foo");
        CHECK(a1.size() == 4);

        // deduces both element type and length
        auto a2 = etl::to_array({0, 2, 1, 3});
        CHECK_SAME_TYPE(decltype(a2), etl::array<int, 4>);

        // deduces length with element type specified
        // implicit conversion happens
        auto a3 = etl::to_array<T>({0, 1, 3});
        CHECK_SAME_TYPE(decltype(a3), etl::array<T, 3>);

        auto a4 = etl::to_array<etl::pair<T, float>>({
            {T{3},    0.0F},
            {T{4},    0.1F},
            {T{4}, 0.1e23F},
        });
        CHECK(a4.size() == 3);

        struct non_copy {
            T val;

            constexpr non_copy(T init)
                : val{init}
            {
            }

            non_copy(non_copy&&) noexcept                    = default;
            non_copy(non_copy const&)                        = delete;
            auto operator=(non_copy&&) noexcept -> non_copy& = default;
            auto operator=(non_copy const&) -> non_copy&     = delete;
        };

        // creates a non-copyable etl::array
        auto a5 = etl::to_array({non_copy(T{42})});
        CHECK(a5.size() == 1);
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
