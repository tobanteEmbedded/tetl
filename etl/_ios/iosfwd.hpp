/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_IOS_IOSFWD_HPP
#define TETL_IOS_IOSFWD_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

template <class CharT>
struct char_traits;
template <>
struct char_traits<char>;
template <>
struct char_traits<wchar_t>;

//   template<> struct char_traits<char8_t>;
//   template<> struct char_traits<char16_t>;
//   template<> struct char_traits<char32_t>;

template <typename CharT, size_t Capacity, typename Traits, typename Child>
struct basic_streambuf;

template <typename CharT, size_t Capacity, typename Traits = char_traits<CharT>>
struct basic_stringbuf;

template <size_t Capacity>
using stringbuf = basic_stringbuf<char, Capacity>;

} // namespace etl
#endif // TETL_IOS_IOSFWD_HPP