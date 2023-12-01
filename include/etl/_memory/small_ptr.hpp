// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_SMALL_PTR_HPP
#define TETL_MEMORY_SMALL_PTR_HPP

#include "etl/_cstddef/nullptr_t.hpp"
#include "etl/_cstddef/ptrdiff_t.hpp"
#include "etl/_cstdint/uint_t.hpp"
#include "etl/_warning/ignore_unused.hpp"

namespace etl {

/// \brief Compressed pointer to specified size. Intended to be used as a drop
/// in replacement for native pointers.
///
/// \details Uses the base address to calculate an offset, which will be stored
/// internally. If used on micro controllers, the base address should be set to
/// the start of RAM. See your linker script.
template <typename Type, intptr_t BaseAddress = 0, typename StorageType = uint16_t>
struct small_ptr {
    /// \brief Default construct empty small_ptr. May contain garbage.
    small_ptr() = default;

    /// \brief Construct from nullptr.
    small_ptr(nullptr_t null) : _value { 0 } { ignore_unused(null); }

    /// \brief Construct from raw pointer.
    small_ptr(Type* ptr) : _value { compress(ptr) } { }

    /// \brief Returns a raw pointer to Type.
    [[nodiscard]] auto get() noexcept -> Type* { return reinterpret_cast<Type*>(BaseAddress + _value); }

    /// \brief Returns a raw pointer to const Type.
    [[nodiscard]] auto get() const noexcept -> Type const*
    {
        return reinterpret_cast<Type const*>(BaseAddress + _value);
    }

    /// \brief Returns the compressed underlying integer address.
    [[nodiscard]] auto compressed_value() const noexcept -> StorageType { return _value; }

    /// \brief Returns a raw pointer to Type.
    [[nodiscard]] auto operator->() const -> Type* { return get(); }

    /// \brief Dereference pointer to Type&.
    [[nodiscard]] auto operator*() -> Type& { return *get(); }

    /// \brief Dereference pointer to Type const&.
    [[nodiscard]] auto operator*() const -> Type const& { return *get(); }

    /// \brief Pre increment of pointer.
    [[nodiscard]] auto operator++(int) noexcept -> small_ptr
    {
        auto temp = *this;
        auto* ptr = get();
        ++ptr;
        _value = compress(ptr);
        return temp;
    }

    /// \brief Post increment of pointer.
    [[nodiscard]] auto operator++() noexcept -> small_ptr&
    {
        auto* ptr = get();
        ptr++;
        _value = compress(ptr);
        return *this;
    }

    /// \brief Pre decrement of pointer.
    [[nodiscard]] auto operator--(int) noexcept -> small_ptr
    {
        auto temp = *this;
        auto* ptr = get();
        --ptr;
        _value = compress(ptr);
        return temp;
    }

    /// \brief Post decrement of pointer.
    [[nodiscard]] auto operator--() noexcept -> small_ptr&
    {
        auto* ptr = get();
        ptr--;
        _value = compress(ptr);
        return *this;
    }

    /// \brief Returns distance from this to other.
    [[nodiscard]] auto operator-(small_ptr other) const noexcept -> ptrdiff_t { return get() - other.get(); }

    /// \brief Implicit conversion to raw pointer to mutable.
    [[nodiscard]] operator Type*() noexcept { return get(); }

    /// \brief Implicit conversion to raw pointer to const.
    [[nodiscard]] operator Type const*() const noexcept { return get(); }

private:
    [[nodiscard]] static auto compress(Type* ptr) -> StorageType
    {
        auto const obj = reinterpret_cast<intptr_t>(ptr);
        return StorageType(obj - BaseAddress);
    }

    StorageType _value;
};

} // namespace etl

#endif // TETL_MEMORY_SMALL_PTR_HPP
