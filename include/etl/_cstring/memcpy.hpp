/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_MEMCPY_HPP
#define TETL_CSTRING_MEMCPY_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Copy the first n bytes pointed to by src to the buffer pointed to by
/// dest. Source and destination may not overlap. If source and destination
/// might overlap, memmove() must be used instead.
constexpr auto memcpy(void* dest, void const* src, etl::size_t n) -> void*
{
    return detail::memcpy_impl<unsigned char, etl::size_t>(dest, src, n);
}

} // namespace etl

#endif // TETL_CSTRING_MEMCPY_HPP
