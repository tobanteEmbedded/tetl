// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CSTRING_MEMMOVE_HPP
#define TETL_CSTRING_MEMMOVE_HPP

#include <etl/_contracts/check.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

/// Copy the first n bytes pointed to by src to the buffer pointed to by
/// dest. Source and destination may overlap.
/// \ingroup cstring
inline auto memmove(void* dest, void const* src, etl::size_t count) -> void*
{
    TETL_PRECONDITION(dest != nullptr);
    TETL_PRECONDITION(src != nullptr);
#if defined(__clang__)
    return __builtin_memmove(dest, src, count);
#else
    return etl::detail::memmove<unsigned char>(dest, src, count);
#endif
}

} // namespace etl
#endif // TETL_CSTRING_MEMMOVE_HPP
