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

#ifndef TAETL_ARRAY_HPP
#define TAETL_ARRAY_HPP

// TAETL
#include "definitions.hpp"

namespace taetl
{
/**
 * @brief Array class with fixed size capacity.
 *
 * @tparam Type Type to hold in container
 * @tparam Size Capacity for Array
 */
template <class Type, taetl::size_t Size>
class Array
{
private:
    taetl::size_t _size {};
    taetl::size_t _capacity {Size};
    Type _data[Size] {};

public:
    using value_type      = Type;
    using pointer         = Type*;
    using const_pointer   = const Type*;
    using reference       = Type&;
    using const_reference = const Type&;
    using iterator        = Type*;
    using const_iterator  = const Type*;

    /**
     * @brief Default constructor.
     */
    constexpr Array() = default;

    /**
     * @brief Returns an iterator to the beginning.
     */
    constexpr auto begin() noexcept -> iterator { return _data; }

    /**
     * @brief Returns an const iterator to the beginning.
     */
    constexpr auto cbegin() const noexcept -> const_iterator { return _data; }

    /**
     * @brief Returns an iterator to the end.
     */
    constexpr auto end() noexcept -> iterator { return _data + size(); }

    /**
     * @brief Returns an const iterator to the end.
     */
    constexpr auto cend() const noexcept -> const_iterator
    {
        return _data + size();
    }

    /**
     * @brief Accesses the first item.
     */
    constexpr auto front() noexcept -> reference { return _data[0]; }

    /**
     * @brief Accesses the last item.
     */
    constexpr auto back() noexcept -> reference { return _data[_size - 1]; }

    /**
     * @brief Adds one element to the back. It fails silently if the Array is
     * full
     */
    constexpr auto push_back(const Type& value) noexcept -> void
    {
        if (_size >= _capacity) { return; }

        _data[_size++] = value;
    }

    /**
     * @brief Decrements the size by 1.
     */
    constexpr auto pop_back() noexcept -> void
    {
        if (_size > 0) { _size--; }
    }

    /**
     * @brief Returns true if the size is 0.
     */
    constexpr auto empty() const noexcept -> bool
    {
        return static_cast<bool>(size() == 0);
    }

    /**
     * @brief Returns the number of items.
     */
    constexpr auto size() const noexcept -> taetl::size_t { return _size; }

    /**
     * @brief Returns the number of items that can be held in allocated
     * storage.
     */
    constexpr auto capacity() const noexcept -> taetl::size_t
    {
        return _capacity;
    }

    /**
     * @brief Accesses the specified item with bounds checking.
     */
    constexpr auto operator[](taetl::size_t index) noexcept -> Type&
    {
        if (_size == 0) { return _data[_size]; }

        if (index < _size) { return _data[index]; }
        return _data[_size - 1];
    }

    /**
     * @brief Resets the size to 0.
     */
    constexpr auto clear() noexcept -> void { _size = 0; }
};

}  // namespace taetl

#endif  // TAETL_ARRAY_HPP