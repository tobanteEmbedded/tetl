// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_STRING_VIEW_STRING_VIEW_HPP
#define TETL_STRING_VIEW_STRING_VIEW_HPP

#include <etl/_string_view/basic_string_view.hpp>

namespace etl {

/// \brief Typedefs for common character type
using string_view = basic_string_view<char, etl::char_traits<char>>;

inline namespace literals {
inline namespace string_view_literals {

/// \brief Forms a string view of a character literal. Returns
/// etl::string_view{str, len}
[[nodiscard]] constexpr auto operator""_sv(char const* str, etl::size_t len) noexcept -> etl::string_view
{
    return {str, len};
}

} // namespace string_view_literals
} // namespace literals

} // namespace etl

#endif // TETL_STRING_VIEW_STRING_VIEW_HPP
