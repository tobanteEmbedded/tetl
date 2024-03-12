// SPDX-License-Identifier: BSL-1.0

#include <etl/charconv.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/string.hpp>
#include <etl/string_view.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

constexpr auto test_chars_format() -> bool
{
    assert(etl::chars_format::scientific != etl::chars_format::hex);
    assert(etl::chars_format::scientific != etl::chars_format::fixed);
    assert(etl::chars_format::scientific != etl::chars_format::general);

    assert(etl::chars_format::hex != etl::chars_format::scientific);
    assert(etl::chars_format::hex != etl::chars_format::fixed);
    assert(etl::chars_format::hex != etl::chars_format::general);

    assert(etl::chars_format::fixed != etl::chars_format::scientific);
    assert(etl::chars_format::fixed != etl::chars_format::hex);
    assert(etl::chars_format::fixed != etl::chars_format::general);

    assert(etl::chars_format::general != etl::chars_format::scientific);
    assert(etl::chars_format::general != etl::chars_format::hex);
    assert(etl::chars_format::general != etl::chars_format::fixed);
    return true;
}

constexpr auto test_to_chars_result() -> bool
{
    {
        auto lhs = etl::to_chars_result{nullptr, etl::errc{}};
        auto rhs = etl::to_chars_result{nullptr, etl::errc{}};
        assert(lhs == rhs);
    }

    {
        char buffer[16] = {};
        auto lhs        = etl::to_chars_result{buffer, etl::errc{}};
        auto rhs        = etl::to_chars_result{buffer, etl::errc{}};
        assert(lhs == rhs);
    }

    return true;
}

constexpr auto test_from_chars_result() -> bool
{
    {
        auto lhs = etl::from_chars_result{nullptr, etl::errc{}};
        auto rhs = etl::from_chars_result{nullptr, etl::errc{}};
        assert(lhs == rhs);
    }

    {
        char buffer[16] = {};
        auto lhs        = etl::from_chars_result{buffer, etl::errc{}};
        auto rhs        = etl::from_chars_result{buffer, etl::errc{}};
        assert(lhs == rhs);
    }

    return true;
}

template <typename T>
constexpr auto test_from_chars() -> bool
{
    using namespace etl::string_view_literals;

    auto test = [](auto tc, T expected, int base) -> void {
        auto val          = T{};
        auto const result = etl::from_chars(tc.begin(), tc.end(), val, base);
        assert(static_cast<bool>(result));
        assert(result.ptr == tc.end());
        assert(val == expected);
    };

    {
        auto val = T{};

        auto foo = "foo"_sv;
        assert(not static_cast<bool>(etl::from_chars(foo.begin(), foo.end(), val)));
        assert(etl::from_chars(foo.begin(), foo.end(), val).ptr == foo.data());
        assert(etl::from_chars(foo.begin(), foo.end(), val).ec == etl::errc::invalid_argument);

        auto fourfoo      = "4foo"_sv;
        auto const result = etl::from_chars(fourfoo.begin(), fourfoo.end(), val);
        assert(static_cast<bool>(result));
        assert(result.ptr == etl::next(fourfoo.data()));
        assert(result.ec == etl::errc{});
        assert(val == T(4));
    }

    test("1"_sv, 1, 2);
    test("1"_sv, 1, 10);
    test("1"_sv, 1, 16);

    test("2"_sv, 2, 10);
    test("10"_sv, 10, 10);
    test("42"_sv, 42, 10);
    test("99"_sv, 99, 10);
    test("126"_sv, 126, 10);

    if constexpr (sizeof(T) > 1) {
        test("1000"_sv, 1000, 10);
        test("9999"_sv, 9999, 10);
    }

    if constexpr (etl::is_signed_v<T>) {
        test("-1"_sv, -1, 10);
        test("-2"_sv, -2, 10);
        test("-10"_sv, -10, 10);
        test("-42"_sv, -42, 10);
        test("-99"_sv, -99, 10);
        test("-126"_sv, -126, 10);

        if constexpr (sizeof(T) > 1) {
            test("-1000"_sv, -1000, 10);
            test("-9999"_sv, -9999, 10);
        }
    }
    return true;
}

template <typename T>
constexpr auto test_to_chars() -> bool
{
    using namespace etl::string_view_literals;

    auto test = [](T tc, etl::string_view expected) -> void {
        auto buf          = etl::array<char, 16>{};
        auto const result = etl::to_chars(buf.begin(), buf.end(), tc, 10);
        assert(static_cast<bool>(result));
        assert(result.ptr != nullptr);
        assert(buf.data() == expected);
    };

    test(1, "1"_sv);
    test(2, "2"_sv);
    test(10, "10"_sv);
    test(42, "42"_sv);
    test(99, "99"_sv);
    test(126, "126"_sv);

    if constexpr (sizeof(T) > 1) {
        test(1000, "1000"_sv);
        test(9999, "9999"_sv);
    }

    if constexpr (etl::is_signed_v<T>) {
        test(-1, "-1"_sv);
        test(-2, "-2"_sv);
        test(-10, "-10"_sv);
        test(-42, "-42"_sv);
        test(-99, "-99"_sv);
        test(-126, "-126"_sv);

        if constexpr (sizeof(T) > 1) {
            test(-1000, "-1000"_sv);
            test(-9999, "-9999"_sv);
        }
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test_chars_format());
    assert(test_to_chars_result());
    assert(test_from_chars_result());

    assert(test_from_chars<char>());
    assert(test_from_chars<unsigned char>());
    assert(test_from_chars<signed char>());

    assert(test_from_chars<unsigned short>());
    assert(test_from_chars<short>());

    assert(test_from_chars<unsigned int>());
    assert(test_from_chars<int>());

    assert(test_from_chars<unsigned long>());
    assert(test_from_chars<long>());

    assert(test_from_chars<unsigned long long>());
    assert(test_from_chars<long long>());

    assert(test_to_chars<char>());
    assert(test_to_chars<unsigned char>());
    assert(test_to_chars<signed char>());

    assert(test_to_chars<unsigned short>());
    assert(test_to_chars<short>());

    assert(test_to_chars<unsigned int>());
    assert(test_to_chars<int>());

    assert(test_to_chars<unsigned long>());
    assert(test_to_chars<long>());

    assert(test_to_chars<unsigned long long>());
    assert(test_to_chars<long long>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
