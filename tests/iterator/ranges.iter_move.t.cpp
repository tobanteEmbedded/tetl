// SPDX-License-Identifier: BSL-1.0

#include <etl/iterator.hpp>

#include <etl/array.hpp>

#include "testing/testing.hpp"

namespace {

enum struct message : int {
};

struct person {
    constexpr person() = default;

    constexpr explicit person(int a) noexcept
        : age{a}
    {
    }

    friend constexpr auto operator==(person lhs, person rhs) -> bool = default;

    int age{0};
};

template <typename T>
constexpr auto test() -> bool
{
    auto vec = etl::array{T(1), T(2), T(3), T(4)};
    CHECK_NOEXCEPT(etl::ranges::iter_move(vec.begin()));
    CHECK_SAME_TYPE(decltype(etl::ranges::iter_move(vec.begin())), etl::iter_rvalue_reference_t<decltype(vec.begin())>);

    CHECK(etl::ranges::iter_move(vec.begin()) == T(1));
    CHECK(etl::ranges::iter_move(etl::next(vec.begin())) == T(2));
    CHECK(etl::ranges::iter_move(etl::next(vec.begin(), 2)) == T(3));
    CHECK(etl::ranges::iter_move(etl::next(vec.begin(), 3)) == T(4));

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

    CHECK(test<message>());
    CHECK(test<person>());

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
