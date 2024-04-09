// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRINGS_CONVERSION_HPP
#define TETL_STRINGS_CONVERSION_HPP

#include <etl/_cctype/isalpha.hpp>
#include <etl/_cctype/isdigit.hpp>
#include <etl/_cctype/isspace.hpp>
#include <etl/_cctype/tolower.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_cstdint/uint_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_type_traits/is_signed.hpp>

namespace etl::detail {

enum struct skip_whitespace : etl::uint8_t {
    no,
    yes,
};

enum struct string_to_integer_error : etl::uint8_t {
    none,
    invalid_input,
    overflow,
};

template <typename Int>
struct string_to_integer_result {
    char const* end{nullptr};
    string_to_integer_error error{string_to_integer_error::none};
    Int value;
};

template <typename Int, skip_whitespace Skip = skip_whitespace::yes>
[[nodiscard]] constexpr auto
string_to_integer(char const* str, size_t len, Int base = Int(10)) noexcept -> string_to_integer_result<Int>
{
    if (len == 0 or *str == char(0)) {
        return {.end = str, .error = string_to_integer_error::invalid_input, .value = Int{}};
    }

    auto i = size_t{};
    if constexpr (Skip == skip_whitespace::yes) {
        while (isspace(static_cast<int>(str[i])) and (len != 0) and (str[i] != char(0))) {
            ++i;
            --len;
        }
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
                .error = string_to_integer_error::invalid_input,
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
        .error = string_to_integer_error::none,
        .value = value,
    };
}

/// \brief Interprets a floating point value in a byte string pointed to by str.
/// \tparam FloatT The floating point type to convert to.
/// \param str Pointer to the null-terminated byte string to be interpreted.
/// \param last Pointer to a pointer to character.
/// \returns Floating point value corresponding to the contents of str on
/// success.
template <typename FloatT>
[[nodiscard]] constexpr auto string_to_floating_point(char const* str, char const** last = nullptr) noexcept -> FloatT
{
    auto res               = FloatT{0};
    auto div               = FloatT{1};
    auto afterDecimalPoint = false;
    auto leadingSpaces     = true;

    auto const* ptr = str;
    for (; *ptr != '\0'; ++ptr) {
        if (etl::isspace(*ptr) && leadingSpaces) {
            continue;
        }
        leadingSpaces = false;

        if (etl::isdigit(*ptr)) {
            if (!afterDecimalPoint) {
                res *= 10;         // Shift the previous digits to the left
                res += *ptr - '0'; // Add the new one
            } else {
                div *= 10;
                res += static_cast<FloatT>(*ptr - '0') / div;
            }
        } else if (*ptr == '.') {
            afterDecimalPoint = true;
        } else {
            break;
        }
    }

    if (last != nullptr) {
        *last = ptr;
    }

    return res;
}

enum struct integer_to_string_error : etl::uint8_t {
    none,
    overflow,
};

struct integer_to_string_result {
    char* end{nullptr};
    integer_to_string_error error{integer_to_string_error::none};
};

template <typename Int, bool TerminateWithNull = true>
[[nodiscard]] constexpr auto
integer_to_string(Int num, char* str, int base = 10, size_t length = etl::numeric_limits<size_t>::max())
    -> integer_to_string_result
{
    auto reverseString = [](char* string, etl::size_t len) {
        etl::size_t f = 0;
        etl::size_t l = len - 1;
        while (f < l) {
            auto const tmp = string[f];
            string[f]      = string[l];
            string[l]      = tmp;
            f++;
            l--;
        }
    };

    // Handle 0 explicitely, otherwise empty string is printed for 0
    etl::size_t i = 0;
    if (num == 0) {
        if (length < (1 + static_cast<size_t>(TerminateWithNull))) {
            return {str + length, integer_to_string_error::overflow};
        }
        str[i++] = '0';
        if constexpr (TerminateWithNull) {
            str[i] = '\0';
        }
        return {&str[i]};
    }

    bool isNegative = false;
    if constexpr (is_signed_v<Int>) {
        if (num < 0 && base == 10) {
            isNegative = true;
            num        = -num;
        }
    }

    while (num != 0) {
        auto const rem = static_cast<char>(num % static_cast<Int>(base));
        str[i++]       = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num            = num / static_cast<Int>(base);

        if (length <= i) {
            return {nullptr, integer_to_string_error::overflow};
        }
    }

    if constexpr (is_signed_v<Int>) {
        if (isNegative) {
            str[i++] = '-';
        }
    }

    if constexpr (TerminateWithNull) {
        str[i] = '\0';
    }

    reverseString(str, i);
    return {&str[i]};
}

} // namespace etl::detail

#endif // TETL_STRINGS_CONVERSION_HPP
