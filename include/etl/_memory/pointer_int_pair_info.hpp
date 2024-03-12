// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_POINTER_INT_PAIR_INFO_HPP
#define TETL_MEMORY_POINTER_INT_PAIR_INFO_HPP

#include <etl/_bit/bit_cast.hpp>
#include <etl/_cstdint/intptr_t.hpp>
#include <etl/_cstdint/uintptr_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_memory/pointer_traits.hpp>

namespace etl {

template <typename PointerT, unsigned IntBits, typename PtrTraits>
struct pointer_int_pair_info {
    // clang-format off
    static_assert(PtrTraits::free_bits < numeric_limits<etl::uintptr_t>::digits, "cannot use a pointer type that has all bits free");
    static_assert(IntBits <= PtrTraits::free_bits, "pointer_int_pair with integer size too large for pointer");
    // clang-format on

    using pointer_type              = PointerT;
    using pointer_traits            = PtrTraits;
    static constexpr auto int_bits  = IntBits;
    static constexpr auto free_bits = pointer_traits::free_bits;

    /// \brief The bits that come from the pointer.
    static constexpr auto ptr_mask = ~static_cast<etl::uintptr_t>((static_cast<etl::intptr_t>(1) << free_bits) - 1);

    /// \brief The number of low bits that we reserve for other uses; and keep
    /// zero.
    static constexpr auto int_shift = static_cast<etl::uintptr_t>(pointer_traits::free_bits - int_bits);

    /// \brief This is the unshifted mask for valid bits of the int
    /// type.
    static constexpr auto int_mask = static_cast<etl::uintptr_t>((static_cast<etl::intptr_t>(1) << int_bits) - 1);

    /// \brief This is the bits for the integer shifted in place.
    static constexpr auto shifted_int_mask = static_cast<etl::uintptr_t>(int_mask << int_shift);

    [[nodiscard]] static auto get_pointer(etl::intptr_t value) -> pointer_type
    {
        return pointer_traits::get_from_void_pointer(etl::bit_cast<void*>(static_cast<etl::uintptr_t>(value) & ptr_mask)
        );
    }

    [[nodiscard]] static auto get_int(etl::intptr_t value) -> etl::intptr_t
    {
        return (static_cast<etl::uintptr_t>(value) >> int_shift) & int_mask;
    }

    [[nodiscard]] static auto update_ptr(etl::intptr_t value, pointer_type ptr) -> etl::intptr_t
    {
        // Preserve all low bits, just update the pointer.
        auto* voidPtr = pointer_traits::get_as_void_pointer(ptr);
        auto ptrWord  = etl::bit_cast<etl::uintptr_t>(voidPtr);
        return static_cast<etl::intptr_t>(ptrWord | (static_cast<etl::uintptr_t>(value) & ~ptr_mask));
    }

    [[nodiscard]] static auto update_int(etl::intptr_t value, etl::intptr_t integer) -> etl::intptr_t
    {
        // Preserve all bits other than the ones we are updating.
        auto const uinteger = static_cast<etl::uintptr_t>(integer);
        return static_cast<etl::intptr_t>(
            (static_cast<etl::uintptr_t>(value) & ~shifted_int_mask) | uinteger << int_shift
        );
    }
};

} // namespace etl

#endif // TETL_MEMORY_POINTER_INT_PAIR_INFO_HPP
