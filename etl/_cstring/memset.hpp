/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_MEMSET_HPP
#define TETL_CSTRING_MEMSET_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Copies the value of c (converted to an unsigned char) into each of
/// the ﬁrst n characters of the object pointed to by s.
constexpr auto memset(void* s, int c, etl::size_t n) -> void*
{
    return detail::memset_impl(static_cast<unsigned char*>(s), c, n);
}

} // namespace etl

#endif // TETL_CSTRING_MEMSET_HPP