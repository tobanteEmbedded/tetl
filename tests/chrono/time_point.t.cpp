/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/chrono.hpp"

#include "etl/cstdint.hpp"
#include "etl/ratio.hpp"

#include "testing.hpp"

template <typename T>
struct null_clock {
    using rep            = T;
    using period         = etl::ratio<1>;
    using duration       = etl::chrono::duration<rep, period>;
    using time_point     = etl::chrono::time_point<null_clock>;
    bool const is_steady = false;

    [[nodiscard]] constexpr auto now() noexcept -> time_point
    {
        return time_point {};
    }
};

template <typename T>
constexpr auto test() -> bool
{
    auto null = etl::chrono::time_point<null_clock<T>> {};
    assert(null.time_since_epoch().count() == T { 0 });
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<float>());
    assert(test<double>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}