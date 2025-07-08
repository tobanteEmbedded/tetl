// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.bit;
import etl.cstdint;
import etl.cstddef;
import etl.limits;
#else
    #include <etl/bit.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/limits.hpp>
#endif

namespace {

template <typename T>
concept has_popcount = requires(T t) { etl::popcount(t); };

template <typename T>
constexpr auto test() -> bool
{
    CHECK_NOEXCEPT(etl::popcount(T{1}));
    CHECK_SAME_TYPE(decltype(etl::popcount(T{1})), int);

    CHECK(etl::popcount(T{0}) == 0);
    CHECK(etl::popcount(T{1}) == 1);
    CHECK(etl::popcount(T{2}) == 1);
    CHECK(etl::popcount(T{3}) == 2);
    CHECK(etl::popcount(T{0b11111111}) == 8);
    CHECK(etl::popcount(etl::numeric_limits<T>::max()) == etl::numeric_limits<T>::digits);

    CHECK(etl::detail::popcount_fallback(T{1}) == 1);
    CHECK(etl::detail::popcount_fallback(T{2}) == 1);
    CHECK(etl::detail::popcount_fallback(T{3}) == 2);
    CHECK(etl::detail::popcount_fallback(T{0b11111111}) == 8);
    CHECK(etl::detail::popcount_fallback(etl::numeric_limits<T>::max()) == etl::numeric_limits<T>::digits);

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(has_popcount<etl::uint8_t>);
    CHECK(has_popcount<etl::uint16_t>);
    CHECK(has_popcount<etl::uint32_t>);
    CHECK(has_popcount<etl::uint64_t>);

    CHECK(has_popcount<unsigned char>);
    CHECK(has_popcount<unsigned short>);
    CHECK(has_popcount<unsigned int>);
    CHECK(has_popcount<unsigned long>);
    CHECK(has_popcount<unsigned long long>);

    CHECK_FALSE(has_popcount<etl::int8_t>);
    CHECK_FALSE(has_popcount<etl::int16_t>);
    CHECK_FALSE(has_popcount<etl::int32_t>);
    CHECK_FALSE(has_popcount<etl::int64_t>);
    CHECK_FALSE(has_popcount<etl::ptrdiff_t>);

    CHECK_FALSE(has_popcount<signed char>);
    CHECK_FALSE(has_popcount<signed short>);
    CHECK_FALSE(has_popcount<signed int>);
    CHECK_FALSE(has_popcount<signed long>);
    CHECK_FALSE(has_popcount<signed long long>);

    CHECK_FALSE(has_popcount<bool>);
    CHECK_FALSE(has_popcount<char>);
    CHECK_FALSE(has_popcount<char8_t>);
    CHECK_FALSE(has_popcount<char16_t>);
    CHECK_FALSE(has_popcount<char32_t>);

    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::size_t>());

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
