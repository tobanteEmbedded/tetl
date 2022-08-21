/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/experimental/net/byte_order.hpp" // for hton, ntoh, net

#include "etl/cstdint.hpp" // for int8_t, uint16_t, uin...

#include "testing/testing.hpp"

constexpr auto test_all() -> bool
{
    using namespace etl::experimental::net;

    assert(ntoh(hton(etl::int8_t { 0 })) == 0);
    assert(ntoh(hton(etl::int8_t { 1 })) == 1);
    assert(ntoh(hton(etl::int8_t { 42 })) == 42);

    assert(ntoh(hton(etl::uint8_t { 0 })) == 0);
    assert(ntoh(hton(etl::uint8_t { 1 })) == 1);
    assert(ntoh(hton(etl::uint8_t { 42 })) == 42);

    assert(ntoh(hton(etl::uint16_t { 0 })) == 0);
    assert(ntoh(hton(etl::uint16_t { 1 })) == 1);
    assert(ntoh(hton(etl::uint16_t { 42 })) == 42);

    assert(ntoh(hton(etl::uint32_t { 0 })) == 0);
    assert(ntoh(hton(etl::uint32_t { 1 })) == 1);
    assert(ntoh(hton(etl::uint32_t { 42 })) == 42);

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
