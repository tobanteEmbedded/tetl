/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MEMORY_ALIGN_HPP
#define TETL_MEMORY_ALIGN_HPP

#include "etl/_bit/bit_cast.hpp"
#include "etl/_cstddef/size_t.hpp"

#include "etl/_cstdint/uintptr_t.hpp"

namespace etl {

/// \brief Given a pointer ptr to a buffer of size space, returns a pointer
/// aligned by the specified alignment for size number of bytes and decreases
/// space argument by the number of bytes used for alignment. The first aligned
/// address is returned.
///
/// The function modifies the pointer only if it would be possible to fit the
/// wanted number of bytes aligned by the given alignment into the buffer. If
/// the buffer is too small, the function does nothing and returns nullptr.
///
/// The behavior is undefined if alignment is not a power of two.
[[nodiscard]] inline auto align(etl::size_t alignment, etl::size_t size,
    void*& ptr, etl::size_t& space) noexcept -> void*
{
    auto off = static_cast<etl::size_t>(
        bit_cast<etl::uintptr_t>(ptr) & (alignment - 1));
    if (off != 0) { off = alignment - off; }
    if (space < off || space - off < size) { return nullptr; }

    ptr = static_cast<char*>(ptr) + off;
    space -= off;
    return ptr;
}

} // namespace etl

#endif // TETL_MEMORY_ALIGN_HPP