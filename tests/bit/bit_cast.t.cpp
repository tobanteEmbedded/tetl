// SPDX-License-Identifier: BSL-1.0

#include <etl/bit.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T, typename U>
constexpr auto test() -> bool
{
    ASSERT_NOEXCEPT(etl::bit_cast<U>(T(42)));
    ASSERT_SAME_TYPE(decltype(etl::bit_cast<U>(T(42))), U);

    auto original = T{42};
    auto other    = etl::bit_cast<U>(original);
    ASSERT(etl::bit_cast<T>(other) == original);

    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(test<etl::int8_t, etl::uint8_t>());
    ASSERT(test<etl::uint8_t, etl::int8_t>());
    ASSERT(test<etl::int16_t, etl::uint16_t>());
    ASSERT(test<etl::uint16_t, etl::int16_t>());
    ASSERT(test<etl::int32_t, etl::uint32_t>());
    ASSERT(test<etl::uint32_t, etl::int32_t>());
    ASSERT(test<etl::int64_t, etl::uint64_t>());
    ASSERT(test<etl::uint64_t, etl::int64_t>());

    ASSERT(test<float, etl::uint32_t>());
    ASSERT(test<float, etl::int32_t>());
    ASSERT(test<etl::uint32_t, float>());
    ASSERT(test<etl::int32_t, float>());

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    ASSERT(test<double, etl::uint64_t>());
    ASSERT(test<double, etl::int64_t>());
    ASSERT(test<etl::uint64_t, double>());
    ASSERT(test<etl::int64_t, double>());
#endif

    return true;
}

} // namespace

auto main() -> int
{
    ASSERT(test_all());
#if __has_builtin(__builtin_bit_cast)
    static_assert(test_all());
#endif
    return 0;
}
