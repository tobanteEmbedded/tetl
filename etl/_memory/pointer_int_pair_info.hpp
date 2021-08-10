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

#ifndef TETL_MEMORY_POINTER_INT_PAIR_INFO_HPP
#define TETL_MEMORY_POINTER_INT_PAIR_INFO_HPP

#include "etl/_memory/pointer_traits.hpp"

#include "etl/bit.hpp"
#include "etl/cstdint.hpp"
#include "etl/limits.hpp"

namespace etl {

template <typename PointerT, unsigned IntBits, typename PtrTraits>
struct pointer_int_pair_info {
    // clang-format off
    static_assert(PtrTraits::free_bits < numeric_limits<uintptr_t>::digits, "cannot use a pointer type that has all bits free");
    static_assert(IntBits <= PtrTraits::free_bits, "pointer_int_pair with integer size too large for pointer");
    // clang-format on

    using pointer_type              = PointerT;
    using pointer_traits            = PtrTraits;
    static constexpr auto int_bits  = IntBits;
    static constexpr auto free_bits = pointer_traits::free_bits;

    /// \brief The bits that come from the pointer.
    static constexpr auto ptr_mask
        = ~(uintptr_t)(((intptr_t)1 << free_bits) - 1);

    /// \brief The number of low bits that we reserve for other uses; and keep
    /// zero.
    static constexpr auto int_shift = pointer_traits::free_bits - int_bits;

    /// \brief This is the unshifted mask for valid bits of the int
    /// type.
    static constexpr auto int_mask = (uintptr_t)(((intptr_t)1 << int_bits) - 1);

    /// \brief This is the bits for the integer shifted in place.
    static constexpr auto shifted_int_mask = (uintptr_t)(int_mask << int_shift);

    [[nodiscard]] static auto get_pointer(intptr_t value) -> pointer_type
    {
        return pointer_traits::get_from_void_pointer(
            bit_cast<void*>(value & ptr_mask));
    }

    [[nodiscard]] static auto get_int(intptr_t value) -> intptr_t
    {
        return (value >> int_shift) & int_mask;
    }

    [[nodiscard]] static auto update_ptr(
        intptr_t originalValue, pointer_type ptr) -> intptr_t
    {
        // Preserve all low bits, just update the pointer.
        auto* voidPtr    = pointer_traits::get_as_void_pointer(ptr);
        auto pointerWord = bit_cast<intptr_t>(voidPtr);
        return pointerWord | (originalValue & ~ptr_mask);
    }

    [[nodiscard]] static auto update_int(
        intptr_t originalValue, intptr_t integer) -> intptr_t
    {
        // Preserve all bits other than the ones we are updating.
        auto const integerWord = static_cast<intptr_t>(integer);
        return (originalValue & ~shifted_int_mask) | integerWord << int_shift;
    }
};

} // namespace etl

#endif // TETL_MEMORY_POINTER_INT_PAIR_INFO_HPP