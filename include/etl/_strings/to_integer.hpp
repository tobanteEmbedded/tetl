// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRINGS_TO_INTEGER_HPP
#define TETL_STRINGS_TO_INTEGER_HPP

#include <etl/_cctype/isalpha.hpp>
#include <etl/_cctype/isdigit.hpp>
#include <etl/_cctype/isspace.hpp>
#include <etl/_cctype/tolower.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_string_view/basic_string_view.hpp>
#include <etl/_type_traits/is_signed.hpp>

namespace etl::strings {

enum struct skip_whitespace : unsigned char {
    no,
    yes,
};

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

    auto len = str.size();

    auto i = size_t{};
    if constexpr (Options.skip_whitespace) {
        while ((len != 0) and etl::isspace(static_cast<int>(str[i])) and (str[i] != char(0))) {
            ++i;
            --len;
        }
    }

    if (len == 0 or str[i] == char(0)) {
        return {.end = str.data(), .error = to_integer_error::invalid_input, .value = Int{}};
    }

    // optional minus for signed types
    [[maybe_unused]] auto sign = Int(1);
    if constexpr (is_signed_v<Int>) {
        if (((len != 0) and (str[i] != char(0))) and (str[i] == '-')) {
            sign = Int(-1);
            ++i;
            --len;
        }
    }

    auto const firstDigit = i;

    // loop over digits
    auto value = Int{};
    for (; (len != 0) and (str[i] != char(0)); ++i, --len) {

        auto digit = Int{};
        if (etl::isdigit(static_cast<int>(str[i])) != 0) {
            digit = static_cast<Int>(str[i] - '0');
        } else if (etl::isalpha(static_cast<int>(str[i])) != 0) {
            auto const x = static_cast<char>(etl::tolower(static_cast<int>(str[i])));
            digit        = static_cast<Int>(static_cast<Int>(x) - static_cast<Int>('a') + 10);
        } else {
            break;
        }

        if (digit >= base) {
            if (i != firstDigit) {
                break;
            }
            return {.end = str.data(), .error = to_integer_error::invalid_input, .value = Int{}};
        }

        if (wouldOverflow(value, digit)) {
            return {.end = str.data(), .error = to_integer_error::overflow, .value = Int{}};
        } else {
            value = static_cast<Int>(value * base + digit);
        }
    }

    if constexpr (is_signed_v<Int>) {
        value *= sign;
    }

    return {.end = etl::addressof(str[i]), .error = to_integer_error::none, .value = value};
}

} // namespace etl::strings

#endif // TETL_STRINGS_TO_INTEGER_HPP
