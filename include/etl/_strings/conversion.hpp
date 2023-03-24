#ifndef ETL_STRING_CONVERSION_HPP
#define ETL_STRING_CONVERSION_HPP

#include "etl/_cctype/isdigit.hpp"
#include "etl/_cctype/isspace.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_cstdint/uint_t.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/is_signed.hpp"
#include "etl/_warning/ignore_unused.hpp"

namespace etl::detail {

enum struct ascii_to_int_error : etl::uint8_t {
    none,
    invalid_input,
    overflow,
};

template <typename T, typename CharT>
struct ascii_to_int_result {
    T value;
    ascii_to_int_error error { ascii_to_int_error::none };
    CharT const* end { nullptr };
};

template <typename T, typename CharT>
[[nodiscard]] constexpr auto ascii_to_int_base10(CharT const* str, size_t len = numeric_limits<size_t>::max()) noexcept
    -> ascii_to_int_result<T, CharT>
{
    if (*str == CharT(0)) {
        return ascii_to_int_result<T, CharT> {
            T {},
            ascii_to_int_error::invalid_input,
            str,
        };
    }

    etl::size_t i = 0;

    // skip leading whitespace
    while (etl::isspace(static_cast<int>(str[i])) && (len != 0) && (str[i] != CharT(0))) {
        ++i;
        --len;
    }

    // optional minus for signed types
    [[maybe_unused]] T sign = 1;
    if constexpr (is_signed_v<T>) {
        if (str[i] == CharT('-')) {
            sign = -1;
            ++i;
            --len;
        }
    }

    // loop over digits
    T value = 0;
    for (; (str[i] != CharT(0)) && (len != 0); ++i, --len) {
        if (!etl::isdigit(static_cast<int>(str[i]))) { break; }
        value = value * T(10) + static_cast<T>(str[i] - CharT('0'));
    }

    // one past the last element used for conversion
    auto result = ascii_to_int_result<T, CharT> { value, {}, &str[i] };
    if constexpr (is_signed_v<T>) { result.value *= sign; }
    return result;
}

enum struct int_to_ascii_error : etl::uint8_t {
    none,
    buffer_overflow,
};

struct int_to_ascii_result {
    char* end { nullptr };
    int_to_ascii_error error { int_to_ascii_error::none };
};

template <typename Int, bool TerminateWithNull = true>
[[nodiscard]] constexpr auto int_to_ascii(
    Int num, char* str, int base = 10, size_t length = etl::numeric_limits<size_t>::max()) -> int_to_ascii_result
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
            return { str + length, int_to_ascii_error::buffer_overflow };
        }
        str[i++] = '0';
        if constexpr (TerminateWithNull) { str[i] = '\0'; }
        return { &str[i] };
    }

    bool isNegative = false;
    if constexpr (etl::is_signed_v<Int>) {
        if (num < 0 && base == 10) {
            isNegative = true;
            num        = -num;
        }
    }

    while (num != 0) {
        auto const rem = static_cast<char>(num % static_cast<Int>(base));
        str[i++]       = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num            = num / static_cast<Int>(base);

        if (length <= i) { return { nullptr, int_to_ascii_error::buffer_overflow }; }
    }

    if constexpr (etl::is_signed_v<Int>) {
        if (isNegative) { str[i++] = '-'; }
    }

    if constexpr (TerminateWithNull) { str[i] = '\0'; }

    reverseString(str, i);
    return { &str[i] };
}

/// \brief Interprets a floating point value in a byte string pointed to by str.
/// \tparam FloatT The floating point type to convert to.
/// \param str Pointer to the null-terminated byte string to be interpreted.
/// \param last Pointer to a pointer to character.
/// \returns Floating point value corresponding to the contents of str on
/// success.
template <typename FloatT>
[[nodiscard]] constexpr auto ascii_to_floating_point(char const* str, char const** last = nullptr) noexcept -> FloatT
{
    auto res               = FloatT { 0 };
    auto div               = FloatT { 1 };
    auto afterDecimalPoint = false;
    auto leadingSpaces     = true;

    auto const* ptr = str;
    for (; *ptr != '\0'; ++ptr) {
        if (etl::isspace(*ptr) && leadingSpaces) { continue; }
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

    if (last != nullptr) { *last = ptr; }

    return res;
}

} // namespace etl::detail

#endif // ETL_STRING_CONVERSION_HPP