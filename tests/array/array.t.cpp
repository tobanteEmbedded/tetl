// SPDX-License-Identifier: BSL-1.0

#include <etl/array.hpp>

#include <etl/algorithm.hpp>
#include <etl/cstdint.hpp>
#include <etl/numeric.hpp>
#include <etl/type_traits.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test_builtin_types() -> bool
{
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
        CHECK(a.at(0) == T{1});
        CHECK(a.at(1) == T{2});
        CHECK(a.at(2) == x);
        CHECK(a[0] == T{1});
        CHECK(a[1] == T{2});
        CHECK(a[2] == x);

        auto const& ac = a;
        CHECK(ac.front() == T{1});
        CHECK(ac.back() == x);
        CHECK(ac.at(0) == T{1});
        CHECK(ac.at(1) == T{2});
        CHECK(ac.at(2) == x);
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

        CHECK(etl::all_of(begin(a), end(a), [](auto val) { return val == 1; }));
        CHECK(etl::all_of(begin(b), end(b), [](auto val) { return val == 0; }));

        a.swap(b);
        CHECK(etl::all_of(begin(a), end(a), [](auto val) { return val == 0; }));
        CHECK(etl::all_of(begin(b), end(b), [](auto val) { return val == 1; }));

        etl::swap(a, b);
        CHECK(etl::all_of(begin(a), end(a), [](auto val) { return val == 1; }));
        CHECK(etl::all_of(begin(b), end(b), [](auto val) { return val == 0; }));
    }

    {
        // TODO: [tobi] Fails in a static_assertion
        // gcc: error: ‘it.etl::reverse_iterator<unsigned char*>::operator*()’
        // is not a constant expression
        // auto arr = etl::array { T(1), T(2), T(3) };
        // auto it  = arr.rbegin();

        // CHECK(*it == T(3));
        // ++it;
        // CHECK(*it == T(2));
        // it++;
        // CHECK(*it == T(1));
    }

    { // not eqaul
        etl::array<T, 3> lhs{T{1}, T{2}, T{3}};
        etl::array<T, 3> rhs{T{7}, T{8}, T{9}};

        CHECK(!(lhs == rhs));
        CHECK(lhs != rhs);
        CHECK(lhs < rhs);
        CHECK(lhs <= rhs);
        CHECK(!(lhs > rhs));
        CHECK(!(lhs >= rhs));
    }

    {
        // eqaul
        etl::array<T, 3> lhs{T{1}, T{2}, T{3}};
        etl::array<T, 3> rhs{T{1}, T{2}, T{3}};

        CHECK(lhs == rhs);
        CHECK(!(lhs != rhs));
        CHECK(!(lhs < rhs));
        CHECK(lhs <= rhs);
        CHECK(!(lhs > rhs));
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
        CHECK(etl::is_same_v<typename etl::tuple_element<1, etl::array<T, 2>>::type, T>);
    }

    {
        // get
        auto a = etl::array<T, 3>{};

        etl::get<0>(a) = T{1};
        etl::get<1>(a) = T{2};
        etl::get<2>(a) = T{3};

        CHECK(etl::get<0>(a) == T{1});
        CHECK(etl::get<1>(a) == T{2});
        CHECK(etl::get<2>(a) == T{3});
    }
    {
        // to_array

        // copies a string literal
        auto a1 = etl::to_array("foo");
        CHECK(a1.size() == 4);

        // deduces both element type and length
        auto a2 = etl::to_array({0, 2, 1, 3});
        CHECK(etl::is_same_v<decltype(a2), etl::array<int, 4>>);

        // deduces length with element type specified
        // implicit conversion happens
        auto a3 = etl::to_array<T>({0, 1, 3});
        CHECK(etl::is_same_v<decltype(a3), etl::array<T, 3>>);

        auto a4 = etl::to_array<etl::pair<T, float>>({
            {T{3},    0.0F},
            {T{4},    0.1F},
            {T{4}, 0.1e23F},
        });
        CHECK(a4.size() == 3);

        struct non_copy {
            T val;

            constexpr non_copy(T init) : val{init} { }

            non_copy(non_copy&&) noexcept                    = default;
            non_copy(non_copy const&)                        = delete;
            auto operator=(non_copy&&) noexcept -> non_copy& = default;
            auto operator=(non_copy const&) -> non_copy&     = delete;
        };

        // creates a non-copyable etl::array
        auto a5 = etl::to_array({non_copy(T{42})});
        CHECK(a5.size() == 1);

        // error: copying multidimensional arrays is not supported
        //    char s[2][6] = {"nice", "thing"};
        //    auto a6      = etl::to_array(s);
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test_builtin_types<etl::uint8_t>());
    CHECK(test_builtin_types<etl::int8_t>());
    CHECK(test_builtin_types<etl::uint16_t>());
    CHECK(test_builtin_types<etl::int16_t>());
    CHECK(test_builtin_types<etl::uint32_t>());
    CHECK(test_builtin_types<etl::int32_t>());
    CHECK(test_builtin_types<etl::uint64_t>());
    CHECK(test_builtin_types<etl::int64_t>());
    CHECK(test_builtin_types<float>());
    CHECK(test_builtin_types<double>());
    CHECK(test_builtin_types<long double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
