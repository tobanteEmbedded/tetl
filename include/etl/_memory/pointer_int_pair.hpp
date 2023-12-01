// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_POINTER_INT_PAIR_HPP
#define TETL_MEMORY_POINTER_INT_PAIR_HPP

#include "etl/_bit/bit_cast.hpp"
#include "etl/_cstdint/intptr_t.hpp"
#include "etl/_memory/pointer_int_pair_info.hpp"
#include "etl/_memory/pointer_like_traits.hpp"

namespace etl {

/// \brief This struct implements a pair of a pointer and small integer.  It is
/// designed to represent this in the space required by one pointer by
/// bitmangling the integer into the low part of the pointer.  This can only be
/// done for small integers: typically up to 3 bits, but it depends on the
/// number of bits available according to pointer_like_traits for the type.
///
/// \details Note that pointer_int_pair always puts the IntVal part in the
/// highest bits possible.  For example, pointer_int_pair<void*, 1, bool> will
/// put the bit for the bool into bit #2, not bit #0, which allows the low two
/// bits to be used for something else.  For example, this allows:
///  pointer_int_pair<pointer_int_pair<void*, 1, bool>, 1, bool>
/// ... and the two bools will land in different bits.
///
/// \include memory.cpp
template <typename PointerT, unsigned IntBits, typename IntType = unsigned,
    typename PtrTraits = pointer_like_traits<PointerT>,
    typename Info      = pointer_int_pair_info<PointerT, IntBits, PtrTraits>>
struct pointer_int_pair {
    using pointer_type             = PointerT;
    using pointer_traits           = PtrTraits;
    using pointer_info             = Info;
    using int_type                 = IntType;
    static constexpr auto int_bits = IntBits;

    constexpr pointer_int_pair() = default;

    pointer_int_pair(pointer_type pointerValue, int_type intValue) { set_ptr_and_int(pointerValue, intValue); }

    explicit pointer_int_pair(pointer_type pointerValue) { init_with_ptr(pointerValue); }

    void set_pointer(pointer_type pointerValue) { _value = pointer_info::update_ptr(_value, pointerValue); }

    void set_int(int_type intValue) { _value = pointer_info::update_int(_value, static_cast<intptr_t>(intValue)); }

    [[nodiscard]] auto get_pointer() const -> pointer_type { return pointer_info::get_pointer(_value); }

    [[nodiscard]] auto get_int() const -> int_type { return static_cast<int_type>(pointer_info::get_int(_value)); }

    void set_ptr_and_int(pointer_type pointerValue, int_type intValue)
    {
        _value = pointer_info::update_int(pointer_info::update_ptr(0, pointerValue), static_cast<intptr_t>(intValue));
    }

    [[nodiscard]] auto get_addr_of_pointer() const -> pointer_type const*
    {
        return const_cast<pointer_int_pair*>(this)->get_addr_of_pointer();
    }

    auto get_addr_of_pointer() -> pointer_type* { return bit_cast<pointer_type*>(&_value); }

    [[nodiscard]] auto get_opaque_value() const -> void* { return bit_cast<void*>(_value); }

    void set_from_opaque_value(void* val) { _value = bit_cast<intptr_t>(val); }

    static auto get_from_opaque_value(void* v) -> pointer_int_pair
    {
        pointer_int_pair p;
        p.set_from_opaque_value(v);
        return p;
    }

    /// \brief Allow pointer_int_pairs to be created from const void * if and
    /// only if the pointer type could be created from a const void *.
    static auto get_from_opaque_value(void const* v) -> pointer_int_pair
    {
        (void)pointer_traits::get_from_void_pointer(v);
        return get_from_opaque_value(const_cast<void*>(v));
    }

    [[nodiscard]] friend auto operator==(pointer_int_pair const& lhs, pointer_int_pair const& rhs) -> bool
    {
        return lhs._value == rhs._value;
    }

    [[nodiscard]] friend auto operator!=(pointer_int_pair const& lhs, pointer_int_pair const& rhs) -> bool
    {
        return lhs._value != rhs._value;
    }

    [[nodiscard]] friend auto operator<(pointer_int_pair const& lhs, pointer_int_pair const& rhs) -> bool
    {
        return lhs._value < rhs._value;
    }

    [[nodiscard]] friend auto operator>(pointer_int_pair const& lhs, pointer_int_pair const& rhs) -> bool
    {
        return lhs._value > rhs._value;
    }

    [[nodiscard]] friend auto operator<=(pointer_int_pair const& lhs, pointer_int_pair const& rhs) -> bool
    {
        return lhs._value <= rhs._value;
    }

    [[nodiscard]] friend auto operator>=(pointer_int_pair const& lhs, pointer_int_pair const& rhs) -> bool
    {
        return lhs._value >= rhs._value;
    }

private:
    auto init_with_ptr(pointer_type pointerValue) -> void { _value = pointer_info::update_ptr(0, pointerValue); }

    intptr_t _value = 0;
};

template <typename PtrT, unsigned IntBits, typename IntT, typename PtrTraits>
struct pointer_like_traits<pointer_int_pair<PtrT, IntBits, IntT, PtrTraits>> {
    static auto get_as_void_pointer(pointer_int_pair<PtrT, IntBits, IntT> const& p) -> void*
    {
        return p.get_opaque_value();
    }

    static auto get_from_void_pointer(void* p) -> pointer_int_pair<PtrT, IntBits, IntT>
    {
        return pointer_int_pair<PtrT, IntBits, IntT>::get_from_opaque_value(p);
    }

    static auto get_from_void_pointer(void const* p) -> pointer_int_pair<PtrT, IntBits, IntT>
    {
        return pointer_int_pair<PtrT, IntBits, IntT>::get_from_opaque_value(p);
    }

    static constexpr size_t free_bits = PtrTraits::free_bits - IntBits;
};

} // namespace etl

#endif // TETL_MEMORY_POINTER_INT_PAIR_HPP
