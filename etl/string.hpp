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

#include "etl/definitions.hpp"
#include "etl/warning.hpp"

namespace etl
{
/**
 * @brief Returns the length of the C string str.
 */
constexpr inline auto strlen(const char* str) -> etl::size_t
{
    const char* s {};
    for (s = str; *s != 0; ++s) { ; }
    return etl::size_t(s - str);
}

/**
 * @brief basic_string class with fixed size capacity.
 *
 * @tparam CharType Build in type for character size (mostly 'char')
 * @tparam Capacity Capacity for basic_string
 */
template <typename CharType, etl::size_t Capacity>
class basic_string
{
public:
    using value_type      = CharType;
    using size_type       = etl::size_t;
    using pointer         = CharType*;
    using const_pointer   = const CharType*;
    using reference       = CharType&;
    using const_reference = const CharType&;
    using iterator        = CharType*;
    using const_iterator  = const CharType*;

    /**
     * @brief Default constructor.
     */
    constexpr basic_string() = default;

    /**
     * @brief Charater Pointer constant constructor.
     * Fails silently if input len is greater then capacity.
     */
    constexpr basic_string(const char* str, etl::size_t const len) noexcept
    {
        if (str != nullptr)
        {
            if (len < Capacity)
            {
                ::memset(data_, 0, len + 1);
                size_ = len;
                ::memcpy(data_, str, len);
            }
        }
    }

    /**
     * @brief Charater Pointer constant constructor. Calls etl::strlen.
     * Fails silently if input length is greater then capacity.
     */
    constexpr basic_string(const char* c_string) noexcept
        : basic_string(c_string, etl::strlen(c_string))
    {
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr auto at(etl::size_t index) noexcept -> reference
    {
        if (index < size_) { return data_[index]; }
        return data_[size_];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    [[nodiscard]] constexpr auto at(etl::size_t index) const noexcept
        -> const_reference
    {
        if (index < size_) { return data_[index]; }
        return data_[size_];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr auto operator[](etl::size_t index) noexcept -> reference
    {
        if (index < size_) { return data_[index]; }
        return data_[size_];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr auto operator[](etl::size_t index) const noexcept
        -> const_reference
    {
        if (index < size_) { return data_[index]; }
        return data_[size_];
    }

    /**
     * @brief Returns an iterator to the beginning.
     */
    constexpr auto begin() noexcept -> iterator { return data_; }

    /**
     * @brief Returns an const iterator to the beginning.
     */
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return data_;
    }

    /**
     * @brief Returns an iterator to the end.
     */
    constexpr auto end() noexcept -> iterator { return data_ + size(); }

    /**
     * @brief Returns an const iterator to the end.
     */
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
    {
        return data_ + size();
    }

    /**
     * @brief Accesses the first character.
     */
    constexpr auto front() noexcept -> reference { return data_[0]; }

    /**
     * @brief Accesses the last character.
     */
    constexpr auto back() noexcept -> reference { return data_[size_ - 1]; }

    /**
     * @brief Checks whether the string is empty.
     */
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return size_ == 0;
    }

    /**
     * @brief Returns the number of characters.
     */
    [[nodiscard]] constexpr auto size() const noexcept -> etl::size_t
    {
        return size_;
    }

    /**
     * @brief Returns the number of characters.
     */
    [[nodiscard]] constexpr auto length() const noexcept -> etl::size_t
    {
        return size_;
    }

    /**
     * @brief Returns the number of characters that can be held in allocated
     * storage.
     */
    [[nodiscard]] constexpr auto capacity() const noexcept -> etl::size_t
    {
        return Capacity;
    }

    /**
     * @brief Returns the number of characters that can be held in allocated
     * storage.
     */
    [[nodiscard]] constexpr auto max_size() const noexcept -> etl::size_t
    {
        return Capacity;
    }

    /**
     * @brief Returns a pointer to a null-terminated character array.
     *
     * The data is equivalent to those stored in the string. The pointer is such
     * that the range [c_str(); c_str() + size()] is valid and the values in it
     * correspond to the values stored in the string with an additional null
     * character after the last position.
     */
    [[nodiscard]] constexpr auto c_str() const noexcept -> const CharType*
    {
        return &data_[0];
    };

    /**
     * @brief Removes all characters from the string.
     */
    constexpr auto clear() noexcept -> void
    {
        for (auto& c : data_) { c = 0; }
        size_ = 0;
    }

    /**
     * @brief Appends count copies of character s.
     */
    constexpr auto append(etl::size_t count, CharType s) noexcept
        -> basic_string&
    {
        for (etl::size_t i = 0; i < count; i++) { data_[size_ + i] = s; }
        size_ += count;
        data_[size_] = 0;

        return *this;
    };

    /**
     * @brief Appends the null-terminated character string pointed to by s. The
     * length of the string is determined by the first null character using
     */
    constexpr auto append(const_pointer s) noexcept -> basic_string&
    {
        auto const len = etl::strlen(s);
        return append(s, len);
    };

    /**
     * @brief Appends characters in the range [s, s + count). This range can
     * contain null characters.
     */
    constexpr auto append(const_pointer s, etl::size_t count) noexcept
        -> basic_string&
    {
        for (etl::size_t i = 0; i < count; i++) { data_[size_ + i] = s[i]; }
        size_ += count;
        data_[size_] = 0;

        return *this;
    };

    /**
     * @brief Inserts count copies of character ch at the position index.
     */
    constexpr auto insert(size_type index, size_type count,
                          CharType ch) noexcept -> basic_string&
    {
        for (size_type i = index; i < count; i++) { data_[size_ + i] = ch; }
        size_ += count;
        data_[size_] = 0;
        return *this;
    }

    /**
     * @brief Inserts null-terminated character string pointed to by s at the
     * position index.
     */
    constexpr auto insert(size_type index, const_pointer s) noexcept
        -> basic_string&
    {
        auto const len = etl::strlen(s);
        for (size_type i = 0; i < len; i++)
        {
            if (auto const pos = index + i; pos < Capacity)
            {
                data_[pos] = s[i];
                size_ += 1;
            }
        }

        data_[size_] = 0;
        return *this;
    }

    /**
     * @brief Inserts the characters in the range [s, s+count) at the position
     * index. The range can contain null characters.
     */
    constexpr auto insert(size_type const index, const_pointer s,
                          size_type const count) noexcept -> basic_string&
    {
        for (size_type i = 0; i < count; i++)
        {
            if (auto const pos = index + i; pos < Capacity)
            {
                data_[pos] = s[i];
                size_ += 1;
            }
        }

        data_[size_] = 0;
        return *this;
    }

private:
    etl::size_t size_        = 0;
    CharType data_[Capacity] = {};
};

template <etl::size_t Capacity>
using string = basic_string<char, Capacity>;

using small_string = basic_string<char, 32>;

}  // namespace etl

#endif  // TAETL_STRING_HPP