/*
Copyright (c) 2019, Tobias Hienzsch
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

#ifndef TAETL_STRING_H
#define TAETL_STRING_H

// TAETL
#include "definitions.h"

namespace taetl
{
/**
 * @brief String class with fixed size capacity.
 *
 * @tparam CharType Build in type for character size (mostly 'char')
 * @tparam Size Capacity for string
 */
template <class CharType, taetl::size_t Size>
class String
{
private:
    taetl::size_t _size{0};
    const taetl::size_t _capacity{Size};
    CharType _data[Size]{};

public:
    typedef CharType value_type;
    typedef CharType* pointer;
    typedef const CharType* const_pointer;
    typedef CharType& reference;
    typedef const CharType& const_reference;
    typedef CharType* iterator;
    typedef const CharType* const_iterator;

    /**
     * @brief Default constructor.
     */
    constexpr String() = default;

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr reference at(taetl::size_t index) noexcept
    {
        if (index < _size)
        {
            return _data[index];
        }
        return _data[_size];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr const_reference at(taetl::size_t index) const noexcept
    {
        if (index < _size)
        {
            return _data[index];
        }
        return _data[_size];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr reference operator[](taetl::size_t index) noexcept
    {
        if (index < _size)
        {
            return _data[index];
        }
        return _data[_size];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr const_reference operator[](taetl::size_t index) const noexcept
    {
        if (index < _size)
        {
            return _data[index];
        }
        return _data[_size];
    }

    /**
     * @brief Returns an iterator to the beginning.
     */
    constexpr iterator begin() noexcept { return _data; }

    /**
     * @brief Returns an const iterator to the beginning.
     */
    constexpr const_iterator cbegin() const noexcept { return _data; }

    /**
     * @brief Returns an iterator to the end.
     */
    constexpr iterator end() noexcept { return _data + size(); }

    /**
     * @brief Returns an const iterator to the end.
     */
    constexpr const_iterator cend() const noexcept { return _data + size(); }

    /**
     * @brief Accesses the first character.
     */
    constexpr reference front() noexcept { return _data[0]; }

    /**
     * @brief Accesses the last character.
     */
    constexpr reference back() noexcept { return _data[_size - 1]; }

    /**
     * @brief Checks whether the string is empty.
     */
    constexpr bool empty() const noexcept { return _size == 0; }
    /**
     * @brief Returns the number of characters.
     */
    constexpr taetl::size_t size() const noexcept { return _size; }

    /**
     * @brief Returns the number of characters.
     */
    constexpr taetl::size_t length() const noexcept { return _size; }

    /**
     * @brief Returns the number of characters that can be held in allocated
     * storage.
     */
    constexpr taetl::size_t capacity() const noexcept { return _capacity; }

    /**
     * @brief Returns a pointer to a null-terminated character array.
     *
     * The data is equivalent to those stored in the string. The pointer is such
     * that the range [c_str(); c_str() + size()] is valid and the values in it
     * correspond to the values stored in the string with an additional null
     * character after the last position.
     */
    constexpr const CharType* c_str() const noexcept { return &_data[0]; };

    /**
     * @brief Removes all characters from the string.
     */
    constexpr void clear() noexcept
    {
        for (auto c : _data)
        {
            c = 0;
        }
        _size = 0;
    }

    /**
     * @brief Appends count copies of character s.
     */
    constexpr String& append(taetl::size_t count, CharType s) noexcept
    {
        for (taetl::size_t i = 0; i < count; i++)
        {
            _data[_size + i] = s;
        }
        _size += count;
        _data[_size] = 0;

        return *this;
    };

    /**
     * @brief Appends the null-terminated character string pointed to by s. The
     * length of the string is determined by the first null character using
     */
    constexpr String& append(const CharType* s) noexcept { return *this; };

    /**
     * @brief Appends characters in the range [s, s + count). This range can
     * contain null characters.
     */
    constexpr String& append(const CharType* s, taetl::size_t count) noexcept
    {
        for (taetl::size_t i = 0; i < count; i++)
        {
            _data[_size + i] = s[i];
        }
        _size += count;
        _data[_size] = 0;

        return *this;
    };
};
}  // namespace taetl

#endif  // TAETL_STRING_H