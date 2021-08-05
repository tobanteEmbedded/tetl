// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_NEW_HPP
#define TETL_NEW_HPP

#include "etl/version.hpp"

// Some parts of the new header are declared in the global namespace. To avoid
// ODR violations, we include the header <new> if it is available.
#if __has_include(<new>)
#include <new>
#else

#include "etl/cstddef.hpp"
#include "etl/warning.hpp"

/// \brief Called by the standard single-object placement new expression. The
/// standard library implementation performs no action and returns ptr
/// unmodified. The behavior is undefined if this function is called through a
/// placement new expression and ptr is a null pointer.
[[nodiscard]] auto operator new(etl::size_t count, void* ptr) noexcept -> void*
{
    etl::ignore_unused(count);
    return ptr;
}

/// \brief Called by the standard array form placement new expression. The
/// standard library implementation performs no action and returns ptr
/// unmodified. The behavior is undefined if this function is called through a
/// placement new expression and ptr is a null pointer.
[[nodiscard]] auto operator new[](etl::size_t count, void* ptr) noexcept
    -> void*
{
    etl::ignore_unused(count);
    return ptr;
}

#endif

namespace etl {
/// \brief etl::nothrow_t is an empty class type used to disambiguate the
/// overloads of throwing and non-throwing allocation functions.
struct nothrow_t {
    explicit nothrow_t() = default;
};

/// \brief etl::nothrow is a constant of type etl::nothrow_t used to
/// disambiguate the overloads of throwing and non-throwing allocation
/// functions.
inline constexpr auto nothrow = etl::nothrow_t {};

/// \brief etl::new_handler is the function pointer type (pointer to function
/// that takes no arguments and returns void), which is used by the functions
/// etl::set_new_handler and etl::get_new_handler
using new_handler = void (*)();

#if defined(__aarch64__)
/// Cache line sizes for ARM values are not strictly correct since cache
/// line sizes depend on implementations, not architectures.  There are even
/// implementations with cache line sizes configurable at boot time.
#define TETL_CACHELINE_SIZE 64
#elif defined(__ARM_ARCH_5T__)
/// Cache line sizes for ARM values are not strictly correct since cache
/// line sizes depend on implementations, not architectures.  There are even
/// implementations with cache line sizes configurable at boot time.
#define TETL_CACHELINE_SIZE 32
#elif defined(__ARM_ARCH_7A__)
/// Cache line sizes for ARM values are not strictly correct since cache
/// line sizes depend on implementations, not architectures.  There are even
/// implementations with cache line sizes configurable at boot time.
#define TETL_CACHELINE_SIZE 64
#elif defined(__PPC64__)
/// Cache line sizes for ARM values are not strictly correct since cache
/// line sizes depend on implementations, not architectures.  There are even
/// implementations with cache line sizes configurable at boot time.
#define TETL_CACHELINE_SIZE 128
#elif defined(__i386__) || defined(__x86_64__)
/// Cache line sizes for ARM values are not strictly correct since cache
/// line sizes depend on implementations, not architectures.  There are even
/// implementations with cache line sizes configurable at boot time.
#define TETL_CACHELINE_SIZE 64
#else
/// Cache line sizes for ARM values are not strictly correct since cache
/// line sizes depend on implementations, not architectures.  There are even
/// implementations with cache line sizes configurable at boot time.
#define TETL_CACHELINE_SIZE alignof(max_align_t)
#endif

/// \brief Minimum offset between two objects to avoid false sharing. Guaranteed
/// to be at least alignof(max_align_t).
constexpr auto hardware_constructive_interference_size = TETL_CACHELINE_SIZE;

/// \brief Maximum size of contiguous memory to promote true sharing. Guaranteed
/// to be at least alignof(max_align_t).
constexpr auto hardware_destructive_interference_size = TETL_CACHELINE_SIZE;

/// \brief Both new-expression and delete-expression, when used with objects
/// whose alignment requirement is greater than the default, pass that alignment
/// requirement as an argument of type align_val_t to the selected
/// allocation/deallocation function.
enum struct align_val_t : size_t {};

/// \brief Tag type used to identify the destroying delete form of operator
/// delete.
struct destroying_delete_t {
    explicit destroying_delete_t() = default;
};

/// \brief Tag type used to identify the destroying delete form of operator
/// delete.
inline constexpr auto destroying_delete = destroying_delete_t {};

} // namespace etl
#endif // TETL_NEW_HPP