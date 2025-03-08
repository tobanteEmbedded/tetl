// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include <etl/string_view.hpp>

#include "testing/testing.hpp"

template <typename Int>
static constexpr auto test() -> bool
{
    using namespace etl::string_view_literals;

    CHECK(etl::to_string<8>(Int(0)) == "0"_sv);
    CHECK(etl::to_string<8>(Int(1)) == "1"_sv);
    CHECK(etl::to_string<8>(Int(2)) == "2"_sv);
    CHECK(etl::to_string<8>(Int(3)) == "3"_sv);
    CHECK(etl::to_string<8>(Int(4)) == "4"_sv);
    CHECK(etl::to_string<8>(Int(5)) == "5"_sv);
    CHECK(etl::to_string<8>(Int(6)) == "6"_sv);
    CHECK(etl::to_string<8>(Int(7)) == "7"_sv);
    CHECK(etl::to_string<8>(Int(8)) == "8"_sv);
    CHECK(etl::to_string<8>(Int(9)) == "9"_sv);
    CHECK(etl::to_string<8>(Int(10)) == "10"_sv);
    CHECK(etl::to_string<8>(Int(11)) == "11"_sv);
    CHECK(etl::to_string<8>(Int(99)) == "99"_sv);
    CHECK(etl::to_string<8>(Int(100)) == "100"_sv);

    CHECK(etl::to_string<16>(Int(0)) == "0"_sv);
    CHECK(etl::to_string<16>(Int(1)) == "1"_sv);
    CHECK(etl::to_string<16>(Int(2)) == "2"_sv);
    CHECK(etl::to_string<16>(Int(3)) == "3"_sv);
    CHECK(etl::to_string<16>(Int(4)) == "4"_sv);
    CHECK(etl::to_string<16>(Int(5)) == "5"_sv);
    CHECK(etl::to_string<16>(Int(6)) == "6"_sv);
    CHECK(etl::to_string<16>(Int(7)) == "7"_sv);
    CHECK(etl::to_string<16>(Int(8)) == "8"_sv);
    CHECK(etl::to_string<16>(Int(9)) == "9"_sv);
    CHECK(etl::to_string<16>(Int(10)) == "10"_sv);
    CHECK(etl::to_string<16>(Int(11)) == "11"_sv);
    CHECK(etl::to_string<16>(Int(99)) == "99"_sv);
    CHECK(etl::to_string<16>(Int(100)) == "100"_sv);

    CHECK(etl::to_string<11>(Int(0)) == "0"_sv);
    CHECK(etl::to_string<11>(Int(1)) == "1"_sv);
    CHECK(etl::to_string<11>(Int(2)) == "2"_sv);
    CHECK(etl::to_string<11>(Int(3)) == "3"_sv);
    CHECK(etl::to_string<11>(Int(4)) == "4"_sv);
    CHECK(etl::to_string<11>(Int(5)) == "5"_sv);
    CHECK(etl::to_string<11>(Int(6)) == "6"_sv);
    CHECK(etl::to_string<11>(Int(7)) == "7"_sv);
    CHECK(etl::to_string<11>(Int(8)) == "8"_sv);
    CHECK(etl::to_string<11>(Int(9)) == "9"_sv);
    CHECK(etl::to_string<11>(Int(10)) == "10"_sv);
    CHECK(etl::to_string<11>(Int(11)) == "11"_sv);
    CHECK(etl::to_string<11>(Int(99)) == "99"_sv);
    CHECK(etl::to_string<11>(Int(100)) == "100"_sv);

    return true;
}

static constexpr auto test_all() -> bool
{
    // CHECK(test<unsigned char>());
    // CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    // CHECK(test<signed char>());
    // CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
