// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRINGS_TO_INTEGER_HPP
#define TETL_STRINGS_TO_INTEGER_HPP

#include <etl/_cctype/isalpha.hpp>
#include <etl/_cctype/isdigit.hpp>
#include <etl/_cctype/isspace.hpp>
#include <etl/_cctype/tolower.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/is_signed.hpp>

namespace etl::strings {

enum struct skip_whitespace : etl::uint8_t {
    no,
    yes,
};

enum struct to_integer_error : etl::uint8_t {
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

template <typename Int, skip_whitespace Skip = skip_whitespace::yes>
[[nodiscard]] constexpr auto
to_integer(char const* str, size_t len, Int base = Int(10)) noexcept -> to_integer_result<Int>
{
    auto i = size_t{};
    if constexpr (Skip == skip_whitespace::yes) {
        while ((len != 0) and isspace(static_cast<int>(str[i])) and (str[i] != char(0))) {
            ++i;
            --len;
        }
    }

    if (len == 0 or str[i] == char(0)) {
        return {.end = str, .error = to_integer_error::invalid_input, .value = Int{}};
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
    for (; (str[i] != char(0)) and (len != 0); ++i, --len) {

        auto digit = Int{};
        if (isdigit(static_cast<int>(str[i]))) {
            digit = static_cast<Int>(str[i] - '0');
        } else if (isalpha(static_cast<int>(str[i]))) {
            auto const x = static_cast<char>(tolower(static_cast<int>(str[i])));
            digit        = static_cast<Int>(static_cast<Int>(x) - static_cast<Int>('a') + 10);
        } else {
            break;
        }

        if (digit >= base) {
            if (i != firstDigit) {
                break;
            }
            return {
                .end   = str,
                .error = to_integer_error::invalid_input,
                .value = Int{},
            };
        }

        // TODO(tobi): Check overflow
        value = static_cast<Int>(value * base + digit);
    }

    if constexpr (is_signed_v<Int>) {
        value *= sign;
    }

    return {
        .end   = &str[i],
        .error = to_integer_error::none,
        .value = value,
    };
}

} // namespace etl::strings

#endif // TETL_STRINGS_TO_INTEGER_HPP
