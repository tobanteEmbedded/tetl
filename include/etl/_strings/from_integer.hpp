// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRINGS_CONVERSION_HPP
#define TETL_STRINGS_CONVERSION_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_type_traits/is_signed.hpp>

namespace etl::strings {

enum struct from_integer_error : unsigned char {
    none,
    overflow,
};

struct from_integer_result {
    char* end{nullptr};
    from_integer_error error{from_integer_error::none};
};

template <typename Int, bool TerminateWithNull = true>
[[nodiscard]] constexpr auto
from_integer(Int num, char* str, int base = 10, size_t length = etl::numeric_limits<size_t>::max())
    -> from_integer_result
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
            return {str + length, from_integer_error::overflow};
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
            return {nullptr, from_integer_error::overflow};
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

} // namespace etl::strings

#endif // TETL_STRINGS_CONVERSION_HPP
