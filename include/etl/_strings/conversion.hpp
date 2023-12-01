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
#include <etl/_warning/ignore_unused.hpp>

namespace etl::detail {

enum struct ascii_to_integer_error : etl::uint8_t {
    none,
    invalid_input,
    overflow,
};

template <typename IntegerType>
struct ascii_to_integer_result {
    char const* end {nullptr};
    ascii_to_integer_error error {ascii_to_integer_error::none};
    IntegerType value;
};

template <typename IntegerType, bool SkipLeadingWhiteSpace = true>
[[nodiscard]] constexpr auto ascii_to_integer(char const* str, size_t len, IntegerType base = IntegerType(10)) noexcept
    -> ascii_to_integer_result<IntegerType>
{
    if (*str == char(0)) {
        return {
            .end   = str,
            .error = ascii_to_integer_error::invalid_input,
            .value = IntegerType {},
        };
    }

    auto i = size_t {};
    if constexpr (SkipLeadingWhiteSpace) {
        while (isspace(static_cast<int>(str[i])) and (len != 0) and (str[i] != char(0))) {
            ++i;
            --len;
        }
    }

    // optional minus for signed types
    [[maybe_unused]] auto sign = IntegerType(1);
    if constexpr (is_signed_v<IntegerType>) {
        if (((len != 0) and (str[i] != char(0))) and (str[i] == '-')) {
            sign = IntegerType(-1);
            ++i;
            --len;
        }
    }

    auto const firstDigit = i;

    // loop over digits
    auto value = IntegerType {};
    for (; (str[i] != char(0)) and (len != 0); ++i, --len) {

        auto digit = IntegerType {};
        if (isdigit(static_cast<int>(str[i]))) {
            digit = static_cast<IntegerType>(str[i] - '0');
        } else if (isalpha(static_cast<int>(str[i]))) {
            auto const x = static_cast<char>(tolower(static_cast<int>(str[i])));
            digit        = static_cast<IntegerType>(static_cast<IntegerType>(x) - static_cast<IntegerType>('a') + 10);
        } else {
            break;
        }

        if (digit >= base) {
            if (i != firstDigit) { break; }
            return {
                .end   = str,
                .error = ascii_to_integer_error::invalid_input,
                .value = IntegerType {},
            };
        }

        // TODO(tobi): Check overflow
        value = static_cast<IntegerType>(value * base + digit);
    }

    if constexpr (is_signed_v<IntegerType>) { value *= sign; }

    return {
        .end   = &str[i],
        .error = ascii_to_integer_error::none,
        .value = value,
    };
}

enum struct int_to_ascii_error : etl::uint8_t {
    none,
    buffer_overflow,
};

struct int_to_ascii_result {
    char* end {nullptr};
    int_to_ascii_error error {int_to_ascii_error::none};
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
            return {str + length, int_to_ascii_error::buffer_overflow};
        }
        str[i++] = '0';
        if constexpr (TerminateWithNull) { str[i] = '\0'; }
        return {&str[i]};
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

        if (length <= i) { return {nullptr, int_to_ascii_error::buffer_overflow}; }
    }

    if constexpr (etl::is_signed_v<Int>) {
        if (isNegative) { str[i++] = '-'; }
    }

    if constexpr (TerminateWithNull) { str[i] = '\0'; }

    reverseString(str, i);
    return {&str[i]};
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
    auto res               = FloatT {0};
    auto div               = FloatT {1};
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

#endif // TETL_STRINGS_CONVERSION_HPP
