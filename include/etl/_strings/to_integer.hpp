// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRINGS_TO_INTEGER_HPP
#define TETL_STRINGS_TO_INTEGER_HPP

#include <etl/_cctype/isalpha.hpp>
#include <etl/_cctype/isdigit.hpp>
#include <etl/_cctype/isspace.hpp>
#include <etl/_cctype/tolower.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_string_view/basic_string_view.hpp>
#include <etl/_type_traits/is_signed.hpp>

namespace etl::strings {

struct to_integer_options {
    bool skip_whitespace = true;
    bool check_overflow  = true;
};

enum struct to_integer_error : unsigned char {
    none,
    invalid_input,
    overflow,
};

template <typename Int>
struct to_integer_result {
    char const* end{nullptr};
    to_integer_error error{to_integer_error::none};
    Int value;
};

template <typename Int, to_integer_options Options = to_integer_options{}>
[[nodiscard]] constexpr auto to_integer(etl::string_view str, Int base = Int(10)) noexcept -> to_integer_result<Int>
{
    constexpr auto const max = etl::numeric_limits<Int>::max();
    auto const wouldOverflow = [maxDivBase = max / base, maxModBase = max % base](Int val, Int digit) -> bool {
        if constexpr (Options.check_overflow) {
            return val > maxDivBase or (val == maxDivBase and digit > maxModBase);
        } else {
            return false;
        }
    };

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
    [[maybe_unused]] auto sign = Int(1);
    if constexpr (is_signed_v<Int>) {
        if (str[pos] == '-') {
            sign = Int(-1);
            ++pos;
        }
    }

    auto const firstDigit = pos;

    // loop over digits
    auto value = Int{};
    for (; pos != len; ++pos) {
        auto const ch = static_cast<int>(str[pos]);

        auto digit = Int{};
        if (etl::isdigit(ch) != 0) {
            digit = static_cast<Int>(ch - int{'0'});
        } else if (etl::isalpha(ch) != 0) {
            digit = static_cast<Int>(etl::tolower(ch) - int{'a'} + 10);
        } else {
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

        value = static_cast<Int>(value * base + digit);
    }

    if constexpr (is_signed_v<Int>) {
        value *= sign;
    }

    return {.end = &str[pos], .error = to_integer_error::none, .value = value};
}

} // namespace etl::strings

#endif // TETL_STRINGS_TO_INTEGER_HPP
