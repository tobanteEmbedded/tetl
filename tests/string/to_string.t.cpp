// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include <etl/cstdint.hpp>
#include <etl/string_view.hpp>

#include "testing/testing.hpp"

using namespace etl::string_view_literals;

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::to_string<8>(T{0}) == "0"_sv);
    CHECK(etl::to_string<8>(T{1}) == "1"_sv);
    CHECK(etl::to_string<8>(T{2}) == "2"_sv);
    CHECK(etl::to_string<8>(T{3}) == "3"_sv);
    CHECK(etl::to_string<8>(T{4}) == "4"_sv);
    CHECK(etl::to_string<8>(T{5}) == "5"_sv);
    CHECK(etl::to_string<8>(T{6}) == "6"_sv);
    CHECK(etl::to_string<8>(T{7}) == "7"_sv);
    CHECK(etl::to_string<8>(T{8}) == "8"_sv);
    CHECK(etl::to_string<8>(T{9}) == "9"_sv);
    CHECK(etl::to_string<8>(T{10}) == "10"_sv);
    CHECK(etl::to_string<8>(T{11}) == "11"_sv);
    CHECK(etl::to_string<8>(T{99}) == "99"_sv);
    CHECK(etl::to_string<8>(T{100}) == "100"_sv);

    CHECK(etl::to_string<16>(T{0}) == "0"_sv);
    CHECK(etl::to_string<16>(T{1}) == "1"_sv);
    CHECK(etl::to_string<16>(T{2}) == "2"_sv);
    CHECK(etl::to_string<16>(T{3}) == "3"_sv);
    CHECK(etl::to_string<16>(T{4}) == "4"_sv);
    CHECK(etl::to_string<16>(T{5}) == "5"_sv);
    CHECK(etl::to_string<16>(T{6}) == "6"_sv);
    CHECK(etl::to_string<16>(T{7}) == "7"_sv);
    CHECK(etl::to_string<16>(T{8}) == "8"_sv);
    CHECK(etl::to_string<16>(T{9}) == "9"_sv);
    CHECK(etl::to_string<16>(T{10}) == "10"_sv);
    CHECK(etl::to_string<16>(T{11}) == "11"_sv);
    CHECK(etl::to_string<16>(T{99}) == "99"_sv);
    CHECK(etl::to_string<16>(T{100}) == "100"_sv);

    CHECK(etl::to_string<11>(T{0}) == "0"_sv);
    CHECK(etl::to_string<11>(T{1}) == "1"_sv);
    CHECK(etl::to_string<11>(T{2}) == "2"_sv);
    CHECK(etl::to_string<11>(T{3}) == "3"_sv);
    CHECK(etl::to_string<11>(T{4}) == "4"_sv);
    CHECK(etl::to_string<11>(T{5}) == "5"_sv);
    CHECK(etl::to_string<11>(T{6}) == "6"_sv);
    CHECK(etl::to_string<11>(T{7}) == "7"_sv);
    CHECK(etl::to_string<11>(T{8}) == "8"_sv);
    CHECK(etl::to_string<11>(T{9}) == "9"_sv);
    CHECK(etl::to_string<11>(T{10}) == "10"_sv);
    CHECK(etl::to_string<11>(T{11}) == "11"_sv);
    CHECK(etl::to_string<11>(T{99}) == "99"_sv);
    CHECK(etl::to_string<11>(T{100}) == "100"_sv);

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int64_t>());

    // TODO: enable
    // CHECK(test<float>());
    // CHECK(test<double>());
    // CHECK(test<long double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
