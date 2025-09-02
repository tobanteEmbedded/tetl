// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/concepts.hpp>
    #include <etl/ranges.hpp>
    #include <etl/span.hpp>
    #include <etl/type_traits.hpp>
#endif

template <typename T, etl::size_t N>
struct MyRange : etl::array<T, N> { };

template <typename T, etl::size_t N>
inline constexpr bool etl::ranges::enable_borrowed_range<MyRange<T, N>> = false;

template <typename T, etl::size_t N>
struct MyBorrowedRange : etl::span<T, N> { };

template <typename T, etl::size_t N>
inline constexpr bool etl::ranges::enable_borrowed_range<MyBorrowedRange<T, N>> = true;

namespace {

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::is_empty_v<etl::ranges::dangling>);
    CHECK(etl::constructible_from<etl::ranges::dangling, T>);
    CHECK(etl::constructible_from<etl::ranges::dangling, T*>);
    CHECK(etl::constructible_from<etl::ranges::dangling, T, T>);

    CHECK(etl::ranges::range<MyRange<T, 3>>);
    CHECK(etl::ranges::range<MyBorrowedRange<T, 3>>);
    CHECK(etl::ranges::borrowed_range<MyBorrowedRange<T, 3>>);
    CHECK_FALSE(etl::ranges::borrowed_range<MyRange<T, 3>>);

    CHECK_SAME_TYPE(etl::ranges::borrowed_iterator_t<MyRange<T, 3>>, etl::ranges::dangling);
    CHECK_SAME_TYPE(etl::ranges::borrowed_iterator_t<MyBorrowedRange<T, 3>>, typename MyBorrowedRange<T, 3>::iterator);

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
