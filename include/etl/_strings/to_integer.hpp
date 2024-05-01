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

namespace etl::strings {

namespace detail {

template <integral Int>
struct nop_overflow_checker {
    explicit constexpr nop_overflow_checker(Int /*base*/) noexcept { }

    [[nodiscard]] constexpr auto operator()(Int /*value*/, Int /*digit*/) const noexcept -> bool { return false; }
};

template <integral Int>
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
    Int _maxDivBase{static_cast<Int>(numeric_limits<Int>::max() / _base)};
    Int _maxModBase{static_cast<Int>(numeric_limits<Int>::max() % _base)};
};

template <integral Int>
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
    Int _minDivBase{static_cast<Int>(numeric_limits<Int>::min() / _base)};
    Int _minModBase{abs(static_cast<Int>(numeric_limits<Int>::min() % _base))};
};

template <integral Int, bool Check>
using overflow_checker = conditional_t<
    Check,
    conditional_t<signed_integral<Int>, signed_overflow_checker<Int>, unsigned_overflow_checker<Int>>,
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

template <integral Int>
struct to_integer_result {
    char const* end{nullptr};
    to_integer_error error{to_integer_error::none};
    Int value{};
};

template <integral Int, to_integer_options Options = to_integer_options{}>
[[nodiscard]] constexpr auto to_integer(string_view str, Int base = Int(10)) noexcept -> to_integer_result<Int>
{
    auto const length        = str.size();
    auto const wouldOverflow = detail::overflow_checker<Int, Options.check_overflow>{base};
    auto const makeError     = [str](auto err) { return to_integer_result<Int>{.end = str.data(), .error = err}; };
    auto const parseDigit    = [](int ch) -> Int {
        if (etl::isdigit(ch) != 0) {
            return static_cast<Int>(ch - int{'0'});
        }
        if (etl::isalpha(ch) != 0) {
            return static_cast<Int>(static_cast<Int>(etl::tolower(ch)) - Int{'a'} + Int{10});
        }
        return etl::numeric_limits<Int>::max(); // always greater than base
    };

    auto pos = size_t{};
    if constexpr (Options.skip_whitespace) {
        while (pos != length and etl::isspace(static_cast<int>(str[pos]))) {
            ++pos;
        }
    }

    // empty or only whitespace
    if (pos == length) {
        return makeError(to_integer_error::invalid_input);
    }

    // optional minus for signed types
    [[maybe_unused]] auto positive = true;
    if constexpr (signed_integral<Int>) {
        if (str[pos] == '-') {
            positive = false;
            if (++pos == length) {
                // minus "-" was last character in string
                return makeError(to_integer_error::invalid_input);
            }
        }
    }

    // first digit
    auto value = [&] {
        auto const ch    = static_cast<int>(str[pos++]);
        auto const digit = static_cast<Int>(parseDigit(ch));
        if constexpr (signed_integral<Int>) {
            return static_cast<Int>(-digit);
        } else {
            return digit;
        }
    }();

    if (etl::abs(value) >= base) {
        return makeError(to_integer_error::invalid_input);
    }

    // loop over rest of digits
    for (; pos != length; ++pos) {
        auto const digit = parseDigit(static_cast<int>(str[pos]));
        if (digit >= base) {
            break;
        }

        if (wouldOverflow(value, digit)) {
            return makeError(to_integer_error::overflow);
        }

        if constexpr (signed_integral<Int>) {
            value = static_cast<Int>(value * base - digit);
        } else {
            value = static_cast<Int>(value * base + digit);
        }
    }

    if constexpr (signed_integral<Int>) {
        if (positive) {
            if (value == numeric_limits<Int>::min()) {
                return makeError(to_integer_error::overflow);
            }
            value *= Int(-1);
        }
    }

    auto const end = etl::next(str.data(), static_cast<etl::ptrdiff_t>(pos));
    return {.end = end, .error = to_integer_error::none, .value = value};
}

} // namespace etl::strings

#endif // TETL_STRINGS_TO_INTEGER_HPP
