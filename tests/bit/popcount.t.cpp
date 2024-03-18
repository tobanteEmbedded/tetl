// SPDX-License-Identifier: BSL-1.0

#include <etl/bit.hpp>

#include <etl/cstddef.hpp>
#include <etl/cstdint.hpp>
#include <etl/limits.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T>
concept has_popcount = requires(T t) { etl::popcount(t); };

template <typename T>
constexpr auto test() -> bool
{
    ASSERT_NOEXCEPT(etl::popcount(T{1}));
    ASSERT_SAME_TYPE(decltype(etl::popcount(T{1})), int);

    ASSERT(etl::popcount(T{0}) == 0);
    ASSERT(etl::popcount(T{1}) == 1);
    ASSERT(etl::popcount(T{2}) == 1);
    ASSERT(etl::popcount(T{3}) == 2);
    ASSERT(etl::popcount(T{0b11111111}) == 8);
    ASSERT(etl::popcount(etl::numeric_limits<T>::max()) == etl::numeric_limits<T>::digits);

    ASSERT(etl::detail::popcount_fallback(T{1}) == 1);
    ASSERT(etl::detail::popcount_fallback(T{2}) == 1);
    ASSERT(etl::detail::popcount_fallback(T{3}) == 2);
    ASSERT(etl::detail::popcount_fallback(T{0b11111111}) == 8);
    ASSERT(etl::detail::popcount_fallback(etl::numeric_limits<T>::max()) == etl::numeric_limits<T>::digits);

    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(has_popcount<etl::uint8_t>);
    ASSERT(has_popcount<etl::uint16_t>);
    ASSERT(has_popcount<etl::uint32_t>);
    ASSERT(has_popcount<etl::uint64_t>);

    ASSERT(has_popcount<unsigned char>);
    ASSERT(has_popcount<unsigned short>);
    ASSERT(has_popcount<unsigned int>);
    ASSERT(has_popcount<unsigned long>);
    ASSERT(has_popcount<unsigned long long>);

    ASSERT(not has_popcount<etl::int8_t>);
    ASSERT(not has_popcount<etl::int16_t>);
    ASSERT(not has_popcount<etl::int32_t>);
    ASSERT(not has_popcount<etl::int64_t>);
    ASSERT(not has_popcount<etl::ptrdiff_t>);

    ASSERT(not has_popcount<signed char>);
    ASSERT(not has_popcount<signed short>);
    ASSERT(not has_popcount<signed int>);
    ASSERT(not has_popcount<signed long>);
    ASSERT(not has_popcount<signed long long>);

    ASSERT(not has_popcount<bool>);
    ASSERT(not has_popcount<char>);
    ASSERT(not has_popcount<char8_t>);
    ASSERT(not has_popcount<char16_t>);
    ASSERT(not has_popcount<char32_t>);

    ASSERT(test<etl::uint8_t>());
    ASSERT(test<etl::uint16_t>());
    ASSERT(test<etl::uint32_t>());
    ASSERT(test<etl::uint64_t>());
    ASSERT(test<etl::size_t>());

    return true;
}

} // namespace

auto main() -> int
{
    ASSERT(test_all());
    static_assert(test_all());
    return 0;
}
