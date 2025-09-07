// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_STRINGS_TO_FLOATING_POINT_HPP
#define TETL_STRINGS_TO_FLOATING_POINT_HPP

#include <etl/_cctype/isdigit.hpp>
#include <etl/_cctype/isspace.hpp>
#include <etl/_string_view/basic_string_view.hpp>
#include <etl/_type_traits/is_signed.hpp>

namespace etl::strings {

enum struct to_floating_point_error : unsigned char {
    none,
    invalid_input,
    overflow,
};

template <typename Float>
struct to_floating_point_result {
    char const* end{nullptr};
    to_floating_point_error error{to_floating_point_error::none};
    Float value;
};

template <typename Float>
[[nodiscard]] constexpr auto to_floating_point(etl::string_view str) noexcept -> to_floating_point_result<Float>
{
    auto res               = Float{0};
    auto div               = Float{1};
    auto afterDecimalPoint = false;
    auto leadingSpaces     = true;

    auto const* ptr = str.data();
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
                res += static_cast<Float>(*ptr - '0') / div;
            }
        } else if (*ptr == '.') {
            afterDecimalPoint = true;
        } else {
            return {.end = str.data(), .error = to_floating_point_error::invalid_input, .value = {}};
        }
    }

    return {.end = ptr, .error = {}, .value = res};
}

} // namespace etl::strings

#endif // TETL_STRINGS_TO_FLOATING_POINT_HPP
