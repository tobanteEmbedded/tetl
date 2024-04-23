// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRINGS_TO_INTEGER_HPP
#define TETL_STRINGS_TO_INTEGER_HPP

#include <etl/_cctype/isalpha.hpp>
#include <etl/_cctype/isdigit.hpp>
#include <etl/_cctype/isspace.hpp>
#include <etl/_cctype/tolower.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/signed_integral.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_numeric/abs.hpp>
#include <etl/_string_view/basic_string_view.hpp>
#include <etl/_type_traits/conditional.hpp>
#include <etl/_type_traits/is_signed.hpp>

namespace etl::strings {

namespace detail {

template <etl::integral Int>
struct nop_overflow_checker {
    explicit constexpr nop_overflow_checker(Int /*base*/) noexcept { }

    [[nodiscard]] constexpr auto operator()(Int /*value*/, Int /*digit*/) const noexcept -> bool { return false; }
};

template <etl::integral Int>
struct unsigned_overflow_checker {
    explicit constexpr unsigned_overflow_checker(Int base) noexcept
        : _base{base}
    {
    }

    [[nodiscard]] constexpr auto operator()(Int value, Int digit) const noexcept -> bool
    {
        return value > _maxDivBase or (value == _maxDivBase and digit > _maxModBase);
    }

private:
    Int _base;
    Int _maxDivBase{static_cast<Int>(etl::numeric_limits<Int>::max() / _base)};
    Int _maxModBase{static_cast<Int>(etl::numeric_limits<Int>::max() % _base)};
};

template <etl::integral Int>
struct signed_overflow_checker {
    explicit constexpr signed_overflow_checker(Int base) noexcept
        : _base{base}
    {
    }

    [[nodiscard]] constexpr auto operator()(Int value, Int digit) const noexcept -> bool
    {
        return value < _minDivBase or (value == _minDivBase and digit > _minModBase);
    }

private:
    Int _base;
    Int _minDivBase{static_cast<Int>(etl::numeric_limits<Int>::min() / _base)};
    Int _minModBase{etl::abs(static_cast<Int>(etl::numeric_limits<Int>::min() % _base))};
};

template <etl::integral Int, bool Check>
using overflow_checker = etl::conditional_t<
    Check,
    etl::conditional_t<signed_integral<Int>, signed_overflow_checker<Int>, unsigned_overflow_checker<Int>>,
    nop_overflow_checker<Int>>;

} // namespace detail

struct to_integer_options {
    bool skip_whitespace = true;
    bool check_overflow  = true;
};

enum struct to_integer_error : unsigned char {
    none,
    invalid_input,
    overflow,
};

template <etl::integral Int>
struct to_integer_result {
    char const* end{nullptr};
    to_integer_error error{to_integer_error::none};
    Int value;
};

template <etl::integral Int, to_integer_options Options = to_integer_options{}>
[[nodiscard]] constexpr auto to_integer(etl::string_view str, Int base = Int(10)) noexcept -> to_integer_result<Int>
{
    auto const len = str.size();
    auto pos       = size_t{};

    if constexpr (Options.skip_whitespace) {
        while (pos != len and etl::isspace(static_cast<int>(str[pos]))) {
            ++pos;
        }
    }

    if (pos == len) {
        return {.end = str.data(), .error = to_integer_error::invalid_input, .value = Int{}};
    }

    // optional minus for signed types
    [[maybe_unused]] auto positive = true;
    if constexpr (is_signed_v<Int>) {
        if (str[pos] == '-') {
            positive = false;
            ++pos;
        }
    }

    auto const firstDigit    = pos;
    auto const wouldOverflow = detail::overflow_checker<Int, Options.check_overflow>{base};

    // loop over digits
    auto value = Int{};
    for (; pos != len; ++pos) {
        auto const ch = static_cast<int>(str[pos]);

        auto digit = Int{};
        if (etl::isdigit(ch) != 0) {
            digit = static_cast<Int>(ch - int{'0'});
        } else if (etl::isalpha(ch) != 0) {
            digit = static_cast<Int>(static_cast<Int>(etl::tolower(ch)) - Int{'a'} + Int{10});
        } else {
            if (pos == firstDigit) {
                return {.end = str.data(), .error = to_integer_error::invalid_input, .value = Int{}};
            }
            break;
        }

        if (digit >= base) {
            if (pos != firstDigit) {
                break;
            }
            return {.end = str.data(), .error = to_integer_error::invalid_input, .value = Int{}};
        }

        if (wouldOverflow(value, digit)) {
            return {.end = str.data(), .error = to_integer_error::overflow, .value = Int{}};
        }

        if constexpr (is_signed_v<Int>) {
            value = static_cast<Int>(value * base - digit);
        } else {
            value = static_cast<Int>(value * base + digit);
        }
    }

    if constexpr (is_signed_v<Int>) {
        if (positive) {
            if (value == etl::numeric_limits<Int>::min()) {
                return {.end = str.data(), .error = to_integer_error::overflow, .value = Int{}};
            }
            value *= Int(-1);
        }
    }

    auto const end = etl::next(str.data(), static_cast<etl::ptrdiff_t>(pos));
    return {.end = end, .error = to_integer_error::none, .value = value};
}

} // namespace etl::strings

#endif // TETL_STRINGS_TO_INTEGER_HPP
