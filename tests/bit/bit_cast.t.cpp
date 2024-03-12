// SPDX-License-Identifier: BSL-1.0

#include <etl/bit.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T, typename U>
constexpr auto test_roundtrip() -> bool
{
    auto original = T{42};
    auto other    = etl::bit_cast<U>(original);
    assert(etl::bit_cast<T>(other) == original);
    return true;
}

constexpr auto test_all() -> bool
{
    assert((test_roundtrip<float, etl::uint32_t>()));
    assert((test_roundtrip<float, etl::int32_t>()));
    assert((test_roundtrip<etl::uint32_t, float>()));
    assert((test_roundtrip<etl::int32_t, float>()));

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    assert((test_roundtrip<double, etl::uint64_t>()));
    assert((test_roundtrip<double, etl::int64_t>()));
    assert((test_roundtrip<etl::uint64_t, double>()));
    assert((test_roundtrip<etl::int64_t, double>()));
#endif

    return true;
}

auto main() -> int
{
    assert(test_all());

#if __has_builtin(__builtin_bit_cast)
    static_assert(test_all());
#endif
    return 0;
}
