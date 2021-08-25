/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_IOS_TYPEDEFS_HPP
#define TETL_IOS_TYPEDEFS_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_ios/iosfwd.hpp"
#include "etl/_type_traits/make_signed.hpp"

namespace etl {

using streamoff  = long;
using streamsize = make_signed_t<size_t>;

// template <typename State>
// struct fpos;

// using streampos  = fpos<typename char_traits<char>::state_type>;
// using wstreampos = fpos<typename char_traits<wchar_t>::state_type>;

} // namespace etl
#endif // TETL_IOS_TYPEDEFS_HPP