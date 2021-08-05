#ifndef ETL_DETAIL_STRING_CONVERSION_HPP
#define ETL_DETAIL_STRING_CONVERSION_HPP

#include "etl/cassert.hpp"
#include "etl/cctype.hpp"
#include "etl/warning.hpp"

namespace etl::detail {
template <typename T>
[[nodiscard]] constexpr auto ascii_to_integer_base10(char const* str) noexcept -> T
{
    if (*str == '\0') { return 0; }

    T sign          = 1;
    ::etl::size_t i = 0;
    if constexpr (is_signed_v<T>) {
        if (str[0] == '-') {
            sign = -1;
            i++;
        }
    }

    T res = 0;
    for (; str[i] != '\0'; ++i) {
        if (!isdigit(str[i])) { return 0; }
        res = res * 10 + str[i] - '0';
    }

    if constexpr (is_signed_v<T>) {
        return sign * res;
    } else {
        return res;
    }
}

/// \brief Converts an integer value to a null-terminated string using the
/// specified base and stores the result in the array given by str parameter.
///
/// \details If base is 10 and value is negative, the resulting string is
/// preceded with a minus sign (-). With any other base, value is always
/// considered unsigned.
///
/// \todo Negative not implemented.
template <typename T>
constexpr auto integer_to_ascii_base10(T val, char* const buffer) -> char*
{
    auto numberOfDigits = [](T x) -> T {
        T count = 0;
        while (x != 0) {
            x /= 10;
            ++count;
        }
        return count;
    };

    T pos = numberOfDigits(val) - 1;
    while (val >= T { 10 }) {
        auto const q  = val / T { 10 };
        auto const r  = static_cast<char>(val % T { 10 });
        buffer[pos--] = static_cast<char>('0' + r);
        val           = q;
    }

    *buffer = static_cast<char>(val + '0');
    return buffer;
}

/// \brief Interprets a floating point value in a byte string pointed to by str.
/// \tparam FloatT The floating point type to convert to.
/// \param str Pointer to the null-terminated byte string to be interpreted.
/// \param last Pointer to a pointer to character.
/// \returns Floating point value corresponding to the contents of str on
/// success.
template <typename FloatT>
[[nodiscard]] constexpr auto ascii_to_floating_point(const char* str, char const** last = nullptr) noexcept -> FloatT
{
    auto res               = FloatT { 0 };
    auto div               = FloatT { 1 };
    auto afterDecimalPoint = false;
    auto leadingSpaces     = true;

    auto const* ptr = str;
    for (; *ptr != '\0'; ++ptr) {
        if (isspace(*ptr) && leadingSpaces) { continue; }
        leadingSpaces = false;

        if (isdigit(*ptr)) {
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

    if (last != nullptr) { *last = ptr; }

    return res;
}

} // namespace etl::detail

#endif // ETL_DETAIL_STRING_CONVERSION_HPP
