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
 * @brief array class with fixed size capacity.
 *
 * @tparam Type Type to hold in container
 * @tparam Size Capacity for Array
 */
template <class Type, taetl::size_t Size>
class array
{
private:
    Type _data[Size] {};

public:
    using value_type      = Type;
    using size_type       = taetl::size_t;
    using difference_type = taetl::ptrdiff_t;
    using pointer         = Type*;
    using const_pointer   = const Type*;
    using reference       = Type&;
    using const_reference = const Type&;
    using iterator        = Type*;
    using const_iterator  = const Type*;

    /**
     * @brief Default constructor.
     */
    constexpr array() = default;

    /**
     * @brief Accesses the specified item with bounds checking.
     */
    constexpr auto at(size_type pos) noexcept -> reference
    {
        if (Size == 0)
        {
            return _data[Size];
        }

        if (pos < Size)
        {
            return _data[pos];
        }
        return _data[Size - 1];
    }

    /**
     * @brief Accesses the specified const item with bounds checking.
     */
    constexpr auto at(size_type pos) const noexcept -> const_reference
    {
        if (Size == 0)
        {
            return _data[Size];
        }

        if (pos < Size)
        {
            return _data[pos];
        }
        return _data[Size - 1];
    }

    /**
     * @brief Accesses the specified item with bounds checking.
     */
    constexpr auto operator[](size_type pos) noexcept -> reference
    {
        if (Size == 0)
        {
            return _data[Size];
        }

        if (pos < Size)
        {
            return _data[pos];
        }
        return _data[Size - 1];
    }

    /**
     * @brief Accesses the specified item with bounds checking.
     */
    constexpr auto operator[](size_type pos) const noexcept -> const_reference
    {
        if (Size == 0)
        {
            return _data[Size];
        }

        if (pos < Size)
        {
            return _data[pos];
        }
        return _data[Size - 1];
    }

    /**
     * @brief Accesses the first item.
     */
    constexpr auto front() noexcept -> reference { return _data[0]; }

    /**
     * @brief Accesses the first item.
     */
    constexpr auto front() const noexcept -> const_reference
    {
        return _data[0];
    }

    /**
     * @brief Accesses the last item.
     */
    constexpr auto back() noexcept -> reference { return _data[Size - 1]; }

    /**
     * @brief Accesses the last item.
     */
    constexpr auto back() const noexcept -> const_reference
    {
        return _data[Size - 1];
    }

    /**
     * @brief Returns pointer to the underlying array serving as element
     * storage. The pointer is such that range [data(); data() + size()) is
     * always a valid range, even if the container is empty (data() is not
     * dereferenceable in that case).
     */
    constexpr auto data() noexcept -> pointer { return _data; }

    /**
     * @brief Returns pointer to the underlying array serving as element
     * storage. The pointer is such that range [data(); data() + size()) is
     * always a valid range, even if the container is empty (data() is not
     * dereferenceable in that case).
     */
    constexpr auto data() const noexcept -> const_pointer { return _data; }

    /**
     * @brief Returns an iterator to the beginning.
     */
    constexpr auto begin() noexcept -> iterator { return _data; }

    /**
     * @brief Returns an iterator to the beginning.
     */
    constexpr auto begin() const noexcept -> const_iterator { return _data; }

    /**
     * @brief Returns an const iterator to the beginning.
     */
    constexpr auto cbegin() const noexcept -> const_iterator { return _data; }

    /**
     * @brief Returns an iterator to the end.
     */
    constexpr auto end() noexcept -> iterator { return _data + size(); }

    /**
     * @brief Returns an iterator to the end.
     */
    constexpr auto end() const noexcept -> const_iterator { return _data + size(); }

    /**
     * @brief Returns an const iterator to the end.
     */
    constexpr auto cend() const noexcept -> const_iterator
    {
        return _data + size();
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
    constexpr auto size() const noexcept -> size_type { return Size; }

    /**
     * @brief Returns the number of items that can be held in allocated
     * storage.
     */
    constexpr auto max_size() const noexcept -> size_type { return Size; }
};

template <class T, class... U>
array(T, U...) -> array<T, 1 + sizeof...(U)>;

}  // namespace taetl

#endif  // TAETL_ARRAY_HPP