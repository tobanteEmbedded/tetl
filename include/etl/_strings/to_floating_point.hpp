// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRINGS_TO_FLOATING_POINT_HPP
#define TETL_STRINGS_TO_FLOATING_POINT_HPP

#include <etl/_cctype/isdigit.hpp>
#include <etl/_cctype/isspace.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/is_signed.hpp>

namespace etl::strings {

/// \brief Interprets a floating point value in a byte string pointed to by str.
/// \tparam FloatT The floating point type to convert to.
/// \param str Pointer to the null-terminated byte string to be interpreted.
/// \param last Pointer to a pointer to character.
/// \returns Floating point value corresponding to the contents of str on
/// success.
template <typename FloatT>
[[nodiscard]] constexpr auto to_floating_point(char const* str, char const** last = nullptr) noexcept -> FloatT
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

} // namespace etl::strings

#endif // TETL_STRINGS_TO_FLOATING_POINT_HPP
