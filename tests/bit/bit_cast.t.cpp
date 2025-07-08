// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.bit;
import etl.cstdint;
#else
    #include <etl/bit.hpp>
    #include <etl/cstdint.hpp>
#endif

namespace {

template <typename T, typename U>
constexpr auto test() -> bool
{
    CHECK_NOEXCEPT(etl::bit_cast<U>(T(42)));
    CHECK_SAME_TYPE(decltype(etl::bit_cast<U>(T(42))), U);

    auto original = T{42};
    auto other    = etl::bit_cast<U>(original);
    CHECK(etl::bit_cast<T>(other) == original);

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t, etl::uint8_t>());
    CHECK(test<etl::uint8_t, etl::int8_t>());
    CHECK(test<etl::int16_t, etl::uint16_t>());
    CHECK(test<etl::uint16_t, etl::int16_t>());
    CHECK(test<etl::int32_t, etl::uint32_t>());
    CHECK(test<etl::uint32_t, etl::int32_t>());
    CHECK(test<etl::int64_t, etl::uint64_t>());
    CHECK(test<etl::uint64_t, etl::int64_t>());

    CHECK(test<float, etl::uint32_t>());
    CHECK(test<float, etl::int32_t>());
    CHECK(test<etl::uint32_t, float>());
    CHECK(test<etl::int32_t, float>());

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    CHECK(test<double, etl::uint64_t>());
    CHECK(test<double, etl::int64_t>());
    CHECK(test<etl::uint64_t, double>());
    CHECK(test<etl::int64_t, double>());
#endif

    return true;
}

} // namespace

auto main() -> int
{
    CHECK(test_all());
#if __has_builtin(__builtin_bit_cast)
    static_assert(test_all());
#endif
    return 0;
}
