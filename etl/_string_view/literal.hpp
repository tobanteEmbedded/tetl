
/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_STRING_VIEW_LITERAL_HPP
#define TETL_STRING_VIEW_LITERAL_HPP

#include "etl/_string_view/string_view.hpp"

namespace etl {

inline namespace literals {
inline namespace string_view_literals {

/// \brief Forms a string view of a character literal. Returns
/// etl::string_view{str, len}
constexpr auto operator"" _sv(char const* str, etl::size_t len) noexcept -> etl::string_view { return { str, len }; }

} // namespace string_view_literals

} // namespace literals
} // namespace etl

#endif // TETL_STRING_VIEW_LITERAL_HPP
