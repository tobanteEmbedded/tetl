/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/bit.hpp"

#include "etl/cstdint.hpp"

#include "testing/testing.hpp"

template <typename T, typename U>
constexpr auto test_roundtrip() -> bool
{
    auto original = T { 42 };
    auto other    = etl::bit_cast<U>(original);
    assert(etl::bit_cast<T>(other) == original);
    return true;
}

constexpr auto test_all() -> bool
{
    if constexpr (sizeof(float) == sizeof(etl::uint32_t)) {
        assert((test_roundtrip<float, etl::uint32_t>()));
        assert((test_roundtrip<float, etl::int32_t>()));
        assert((test_roundtrip<etl::uint32_t, float>()));
        assert((test_roundtrip<etl::int32_t, float>()));
    }

    if constexpr (sizeof(double) == sizeof(etl::uint64_t)) {
        assert((test_roundtrip<double, etl::uint64_t>()));
        assert((test_roundtrip<double, etl::int64_t>()));
        assert((test_roundtrip<etl::uint64_t, double>()));
        assert((test_roundtrip<etl::int64_t, double>()));
    }

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