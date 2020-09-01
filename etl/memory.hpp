
/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_MEMORY_HPP
#define TAETL_MEMORY_HPP

#include "etl/definitions.hpp"
#include "etl/limits.hpp"
#include "etl/type_traits.hpp"
#include "etl/warning.hpp"

namespace etl
{
/**
 * @brief Compressed pointer to specified size. Intended to be used as a drop in
 * replacement for native pointers.
 *
 * @details Uses the base address to calculate an offset, which will be stored
 * internally.
 */
template <typename Type, intptr_t BaseAddress = 0,
          typename StorageType = uint16_t>
class small_ptr
{
public:
    /**
     * @brief Default construct empty small_ptr. May contain garbage.
     */
    small_ptr() = default;

    /**
     * @brief Construct from nullptr.
     */
    small_ptr(nullptr_t null) : value_ {0} { ignore_unused(null); }

    /**
     * @brief Construct from raw pointer.
     */
    explicit small_ptr(Type* ptr)
        : value_ {[ptr]() -> StorageType {
            auto const obj    = reinterpret_cast<intptr_t>(ptr);
            auto const offset = obj - BaseAddress;
            if (offset <= mask) { return StorageType(offset & mask); }
            return 0;
        }()}
    {
    }

    /**
     * @brief Returns the underlying integer address.
     */
    [[nodiscard]] auto data() const -> StorageType { return value_; }

    [[nodiscard]] auto operator->() const -> Type* { return get(); }
    [[nodiscard]] auto operator*() -> Type& { return *get(); }
    [[nodiscard]] auto operator*() const -> Type const& { return *get(); }

    [[nodiscard]] auto get() -> Type* { return (Type*)(BaseAddress + value_); }
    [[nodiscard]] auto get() const -> Type const*
    {
        return (Type const*)(BaseAddress + value_);
    }

private:
    StorageType value_;
    constexpr static StorageType mask = etl::numeric_limits<StorageType>::max();
};

/**
 * @brief Compressed pointer to specified size. Intended to be used as a drop in
 * replacement for native pointers.
 *
 * @details Only useful if the memory range starts at 0, since the near_ptr
 * doesn't use a base address offset.
 */
template <class Type, typename StorageType = uint16_t>
class near_ptr
{
    StorageType ptr_;

public:
    near_ptr() = default;
    near_ptr(nullptr_t null) { ignore_unused(null); }

    explicit near_ptr(Type* p) : ptr_((StorageType)(intptr_t)p) { }

    template <class Other>
    explicit near_ptr(const near_ptr<Other>& rhs) : ptr_(rhs.ptr_)
    {
    }

    auto operator*() const -> Type& { return *(Type*)(intptr_t)ptr_; }
};

}  // namespace etl
#endif  // TAETL_MEMORY_HPP