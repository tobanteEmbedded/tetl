// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/numeric.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // built-in
    {
        auto data = etl::array<T, 4>{};
        etl::iota(data.begin(), data.end(), T{0});
        etl::reverse(data.begin(), data.end());

        CHECK(data[0] == 3);
        CHECK(data[1] == 2);
        CHECK(data[2] == 1);
        CHECK(data[3] == 0);
    }

    // struct
    {
        struct S {
            T data;
        };

        auto arr = etl::array{
            S{T(1)},
            S{T(2)},
        };

        etl::reverse(begin(arr), end(arr));

        CHECK(arr[0].data == T(2));
        CHECK(arr[1].data == T(1));
    }
    // built-in
    {
        auto source = etl::array<T, 4>{};
        etl::iota(source.begin(), source.end(), T{0});

        auto destination = etl::array<T, 4>{};
        etl::reverse_copy(source.begin(), source.end(), begin(destination));

        CHECK(destination[0] == 3);
        CHECK(destination[1] == 2);
        CHECK(destination[2] == 1);
        CHECK(destination[3] == 0);
    }

    // struct
    {
        struct S {
            T data;
        };

        auto source = etl::array{
            S{T(1)},
            S{T(2)},
        };

        decltype(source) destination{};
        etl::reverse_copy(source.begin(), source.end(), begin(destination));

        CHECK(destination[0].data == T(2));
        CHECK(destination[1].data == T(1));
    }

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
    return 0;
}
