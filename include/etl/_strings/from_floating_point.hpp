// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRINGS_FROM_FLOATING_POINT_HPP
#define TETL_STRINGS_FROM_FLOATING_POINT_HPP

#include <etl/_algorithm/reverse.hpp>
#include <etl/_concepts/floating_point.hpp>
#include <etl/_math/ipow.hpp>
#include <etl/_span/span.hpp>
#include <etl/_type_traits/conditional.hpp>

namespace etl::strings {

struct from_floating_point_options {
    bool terminate_with_null = true;
};

enum struct from_floating_point_error : unsigned char {
    none,
    overflow,
};

struct from_floating_point_result {
    char* end{nullptr};
    from_floating_point_error error{from_floating_point_error::none};
};

template <floating_point Float, from_floating_point_options Options = from_floating_point_options{}>
[[nodiscard]] constexpr auto from_floating_point(Float val, span<char> out, int precision) -> from_floating_point_result
{
    using int_type = conditional_t<(sizeof(Float) > 4), long long, long>;

    constexpr auto toString = [](int_type x, char* str, int numDigits) -> int {
        int i = 0;
        while (x) {
            str[i++] = (x % 10) + '0';
            x        = x / 10;
        }

        // If number of digits required is more, then
        // add 0s at the beginning
        while (i < numDigits) {
            str[i++] = '0';
        }

        etl::reverse(str, str + i);
        str[i] = '\0';
        return i;
    };

    auto* res = out.data();

    auto const whole = static_cast<int_type>(val);
    auto const frac  = val - static_cast<Float>(whole);
    auto const pos   = toString(whole, res, 0);

    if (precision == 0) {
        return {};
    }

    // Get the value of fraction part upto given no.
    // of points after dot. The third parameter
    // is needed to handle cases like 233.007
    auto part = static_cast<int_type>(frac * static_cast<Float>(etl::ipow<10>(precision)));
    res[pos]  = '.';
    toString(part, res + pos + 1, precision);

    return {.end = res + pos};
}

} // namespace etl::strings

#endif // TETL_STRINGS_FROM_FLOATING_POINT_HPP
