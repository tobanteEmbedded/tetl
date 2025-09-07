// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CSTRING_MEMSET_HPP
#define TETL_CSTRING_MEMSET_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// Copies the value of c (converted to an unsigned char) into each of
/// the ﬁrst n characters of the object pointed to by s.
/// \ingroup cstring
inline auto memset(void* s, int c, etl::size_t n) -> void*
{
    return etl::detail::memset(static_cast<unsigned char*>(s), c, n);
}

} // namespace etl

#endif // TETL_CSTRING_MEMSET_HPP
