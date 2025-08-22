// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRINGS_CONVERSION_HPP
#define TETL_STRINGS_CONVERSION_HPP

#include <etl/_algorithm/reverse.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_math/abs.hpp>
#include <etl/_math/idiv.hpp>
#include <etl/_type_traits/is_signed.hpp>

namespace etl::strings {

struct from_integer_options {
    bool terminate_with_null = true;
};

enum struct from_integer_error : unsigned char {
    none,
    overflow,
};

struct from_integer_result {
    char* end{nullptr};
    from_integer_error error{from_integer_error::none};
};

template <integral Int, from_integer_options Options = from_integer_options{}>
[[nodiscard]] constexpr auto from_integer(Int num, char* str, size_t length, int base) -> from_integer_result
{
    // Handle 0 explicitely, otherwise empty string is printed for 0
    etl::size_t i = 0;
    if (num == 0) {
        if (length < (1 + static_cast<size_t>(Options.terminate_with_null))) {
            return {.end = str + length, .error = from_integer_error::overflow};
        }
        str[i++] = '0';
        if constexpr (Options.terminate_with_null) {
            str[i] = '\0';
        }
        return {.end = str + i, .error = from_integer_error::none};
    }

    bool isNegative = false;
    if constexpr (is_signed_v<Int>) {
        if (num < 0) {
            isNegative = true;
            str[i++]   = '-';
        }
    }

    while (num != 0) {
        auto const [quot, rem] = etl::idiv(num, static_cast<Int>(base));
        auto const digit       = static_cast<char>(etl::abs(rem));

        str[i++] = (digit > 9) ? (digit - 10) + 'a' : digit + '0';
        num      = quot;

        if (i == length) {
            if constexpr (Options.terminate_with_null) {
                return {.end = nullptr, .error = from_integer_error::overflow};
            } else {
                if (num != 0) {
                    return {.end = nullptr, .error = from_integer_error::overflow};
                } else {
                    break;
                }
            }
        }
    }

    etl::reverse(str + static_cast<size_t>(isNegative), str + i);
    if constexpr (Options.terminate_with_null) {
        str[i] = '\0';
    }

    return {.end = str + i, .error = from_integer_error::none};
}

} // namespace etl::strings

#endif // TETL_STRINGS_CONVERSION_HPP
