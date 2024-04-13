// SPDX-License-Identifier: BSL-1.0

#include <etl/chrono.hpp>

#include <etl/cstdint.hpp>
#include <etl/ratio.hpp>

#include "testing/testing.hpp"

template <typename T>
struct NullClock {
    using rep                             = T;
    using period                          = etl::ratio<1>;
    using duration                        = etl::chrono::duration<rep, period>;
    using time_point                      = etl::chrono::time_point<NullClock>;
    static constexpr auto const is_steady = false;

    [[nodiscard]] constexpr auto now() noexcept -> time_point { return time_point{}; }
};

template <typename T>
constexpr auto test() -> bool
{
    auto null = etl::chrono::time_point<NullClock<T>>{};
    CHECK(null.time_since_epoch().count() == T{0});
    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<float>());
    CHECK(test<double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
