/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_MEMMOVE_HPP
#define TETL_CSTRING_MEMMOVE_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Copy the first n bytes pointed to by src to the buffer pointed to by
/// dest. Source and destination may overlap.
constexpr auto memmove(void* dest, void const* src, etl::size_t count) -> void*
{
    return detail::memmove_impl<unsigned char>(dest, src, count);
}

} // namespace etl
#endif // TETL_CSTRING_MEMMOVE_HPP
