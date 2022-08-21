/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/string.hpp"

#include "etl/string_view.hpp"

#include "testing/testing.hpp"

using namespace etl::string_view_literals;

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::to_string<8>(T { 0 }) == "0"_sv);
    assert(etl::to_string<8>(T { 1 }) == "1"_sv);
    assert(etl::to_string<8>(T { 2 }) == "2"_sv);
    assert(etl::to_string<8>(T { 3 }) == "3"_sv);
    assert(etl::to_string<8>(T { 4 }) == "4"_sv);
    assert(etl::to_string<8>(T { 5 }) == "5"_sv);
    assert(etl::to_string<8>(T { 6 }) == "6"_sv);
    assert(etl::to_string<8>(T { 7 }) == "7"_sv);
    assert(etl::to_string<8>(T { 8 }) == "8"_sv);
    assert(etl::to_string<8>(T { 9 }) == "9"_sv);
    assert(etl::to_string<8>(T { 10 }) == "10"_sv);
    assert(etl::to_string<8>(T { 11 }) == "11"_sv);
    assert(etl::to_string<8>(T { 99 }) == "99"_sv);
    assert(etl::to_string<8>(T { 100 }) == "100"_sv);

    assert(etl::to_string<16>(T { 0 }) == "0"_sv);
    assert(etl::to_string<16>(T { 1 }) == "1"_sv);
    assert(etl::to_string<16>(T { 2 }) == "2"_sv);
    assert(etl::to_string<16>(T { 3 }) == "3"_sv);
    assert(etl::to_string<16>(T { 4 }) == "4"_sv);
    assert(etl::to_string<16>(T { 5 }) == "5"_sv);
    assert(etl::to_string<16>(T { 6 }) == "6"_sv);
    assert(etl::to_string<16>(T { 7 }) == "7"_sv);
    assert(etl::to_string<16>(T { 8 }) == "8"_sv);
    assert(etl::to_string<16>(T { 9 }) == "9"_sv);
    assert(etl::to_string<16>(T { 10 }) == "10"_sv);
    assert(etl::to_string<16>(T { 11 }) == "11"_sv);
    assert(etl::to_string<16>(T { 99 }) == "99"_sv);
    assert(etl::to_string<16>(T { 100 }) == "100"_sv);

    assert(etl::to_string<11>(T { 0 }) == "0"_sv);
    assert(etl::to_string<11>(T { 1 }) == "1"_sv);
    assert(etl::to_string<11>(T { 2 }) == "2"_sv);
    assert(etl::to_string<11>(T { 3 }) == "3"_sv);
    assert(etl::to_string<11>(T { 4 }) == "4"_sv);
    assert(etl::to_string<11>(T { 5 }) == "5"_sv);
    assert(etl::to_string<11>(T { 6 }) == "6"_sv);
    assert(etl::to_string<11>(T { 7 }) == "7"_sv);
    assert(etl::to_string<11>(T { 8 }) == "8"_sv);
    assert(etl::to_string<11>(T { 9 }) == "9"_sv);
    assert(etl::to_string<11>(T { 10 }) == "10"_sv);
    assert(etl::to_string<11>(T { 11 }) == "11"_sv);
    assert(etl::to_string<11>(T { 99 }) == "99"_sv);
    assert(etl::to_string<11>(T { 100 }) == "100"_sv);

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());

    // TODO: enable
    // assert(test<float>());
    // assert(test<double>());
    // assert(test<long double>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
