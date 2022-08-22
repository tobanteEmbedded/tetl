/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_STRING_STR_REPLACE_HPP
#define TETL_STRING_STR_REPLACE_HPP

namespace etl::detail {

template <typename CharT>
constexpr auto str_replace(CharT* f, CharT* l, CharT ch) -> void
{
    for (; f != l; ++f) { *f = ch; }
}

template <typename CharT>
constexpr auto str_replace(CharT* f, CharT* l, CharT const* sf, CharT const* sl) -> void
{
    for (; (f != l) && (sf != sl); ++f, ++sf) { *f = *sf; }
}
} // namespace etl::detail

#endif // TETL_STRING_STR_REPLACE_HPP
