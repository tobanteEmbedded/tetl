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

#ifndef TAETL_STRING_HPP
#define TAETL_STRING_HPP

#include "taetl/definitions.hpp"
#include "taetl/warning.hpp"

namespace taetl
{
/**
 * @brief Returns the length of the C string str.
 */
constexpr inline auto strlen(const char* str) -> taetl::size_t
{
    const char* s {};
    for (s = str; *s; ++s)
        ;
    return taetl::size_t(s - str);
}

/**
 * @brief String class with fixed size capacity.
 *
 * @tparam CharType Build in type for character size (mostly 'char')
 * @tparam Size Capacity for string
 */
template <typename CharType = char, taetl::size_t Size = 16>
class String
{
private:
    taetl::size_t _size {0};
    taetl::size_t const _capacity {Size};
    CharType _data[Size] {};

public:
    using value_type      = CharType;
    using pointer         = CharType*;
    using const_pointer   = const CharType*;
    using reference       = CharType&;
    using const_reference = const CharType&;
    using iterator        = CharType*;
    using const_iterator  = const CharType*;

    /**
     * @brief Default constructor.
     */
    constexpr String() = default;

    /**
     * @brief Charater Pointer constant constructor.
     * Fails silently if input len is greater then capacity.
     */
    constexpr String(const char* str, taetl::size_t const len) noexcept
    {
        if (str != nullptr)
        {
            if (len < _capacity)
            {
                ::memset(_data, 0, len + 1);
                _size = len;
                ::memcpy(_data, str, len);
            }
        }
    }

    /**
     * @brief Charater Pointer constant constructor. Calls taetl::strlen.
     * Fails silently if input length is greater then capacity.
     */
    constexpr String(const char* c_string) noexcept
        : String(c_string, taetl::strlen(c_string))
    {
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr auto at(taetl::size_t index) noexcept -> reference
    {
        if (index < _size) { return _data[index]; }
        return _data[_size];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr auto at(taetl::size_t index) const noexcept -> const_reference
    {
        if (index < _size) { return _data[index]; }
        return _data[_size];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr auto operator[](taetl::size_t index) noexcept -> reference
    {
        if (index < _size) { return _data[index]; }
        return _data[_size];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr auto operator[](taetl::size_t index) const noexcept
        -> const_reference
    {
        if (index < _size) { return _data[index]; }
        return _data[_size];
    }

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
     * @brief Accesses the first character.
     */
    constexpr auto front() noexcept -> reference { return _data[0]; }

    /**
     * @brief Accesses the last character.
     */
    constexpr auto back() noexcept -> reference { return _data[_size - 1]; }

    /**
     * @brief Checks whether the string is empty.
     */
    constexpr auto empty() const noexcept -> bool { return _size == 0; }

    /**
     * @brief Returns the number of characters.
     */
    constexpr auto size() const noexcept -> taetl::size_t { return _size; }

    /**
     * @brief Returns the number of characters.
     */
    constexpr auto length() const noexcept -> taetl::size_t { return _size; }

    /**
     * @brief Returns the number of characters that can be held in allocated
     * storage.
     */
    constexpr auto capacity() const noexcept -> taetl::size_t
    {
        return _capacity;
    }

    /**
     * @brief Returns a pointer to a null-terminated character array.
     *
     * The data is equivalent to those stored in the string. The pointer is such
     * that the range [c_str(); c_str() + size()] is valid and the values in it
     * correspond to the values stored in the string with an additional null
     * character after the last position.
     */
    constexpr auto c_str() const noexcept -> const CharType*
    {
        return &_data[0];
    };

    /**
     * @brief Removes all characters from the string.
     */
    constexpr auto clear() noexcept -> void
    {
        for (auto& c : _data) { c = 0; }
        _size = 0;
    }

    /**
     * @brief Appends count copies of character s.
     */
    constexpr auto append(taetl::size_t count, CharType s) noexcept -> String&
    {
        for (taetl::size_t i = 0; i < count; i++) { _data[_size + i] = s; }
        _size += count;
        _data[_size] = 0;

        return *this;
    };

    /**
     * @brief Appends the null-terminated character string pointed to by s. The
     * length of the string is determined by the first null character using
     */
    constexpr auto append(const CharType* s) noexcept -> String&
    {
        taetl::ignoreUnused(s);
        return *this;
    };

    /**
     * @brief Appends characters in the range [s, s + count). This range can
     * contain null characters.
     */
    constexpr auto append(const CharType* s, taetl::size_t count) noexcept
        -> String&
    {
        for (taetl::size_t i = 0; i < count; i++) { _data[_size + i] = s[i]; }
        _size += count;
        _data[_size] = 0;

        return *this;
    };
};
}  // namespace taetl

#endif  // TAETL_STRING_HPP