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

/**
 * @example string.cpp
 */

#ifndef TAETL_STRING_HPP
#define TAETL_STRING_HPP

#include "etl/string_view.hpp"
#include "etl/warning.hpp"

#include "etl/detail/string_char_traits.hpp"

namespace etl
{
/**
 * @brief basic_static_string class with fixed size capacity.
 *
 * @tparam CharType Build in type for character size (mostly 'char')
 * @tparam Capacity Capacity for basic_static_string
 */
template <typename CharType, etl::size_t Capacity,
          typename Traits = etl::char_traits<CharType>>
class basic_static_string
{
public:
    using traits_type     = Traits;
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
    constexpr basic_static_string() = default;

    /**
     * @brief Charater Pointer constant constructor.
     * Fails silently if input len is greater then capacity.
     */
    constexpr basic_static_string(const char* str, etl::size_t const len) noexcept
    {
        if (str != nullptr)
        {
            if (len < Capacity)
            {
                etl::memset(&data_[0], 0, len + 1);
                size_ = len;
                etl::memcpy(&data_[0], str, len);
            }
        }
    }

    /**
     * @brief Charater Pointer constant constructor. Calls etl::strlen.
     * Fails silently if input length is greater then capacity.
     */
    constexpr basic_static_string(const char* c_string) noexcept
        : basic_static_string(c_string, etl::strlen(c_string))
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
    [[nodiscard]] constexpr auto at(etl::size_t index) const noexcept -> const_reference
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
    constexpr auto operator[](etl::size_t index) const noexcept -> const_reference
    {
        if (index < size_) { return data_[index]; }
        return data_[size_];
    }

    /**
     * @brief Returns an iterator to the beginning.
     */
    constexpr auto begin() noexcept -> iterator { return &data_[0]; }

    /**
     * @brief Returns an const iterator to the beginning.
     */
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return &data_[0];
    }

    /**
     * @brief Returns an iterator to the end.
     */
    constexpr auto end() noexcept -> iterator { return &data_[0] + size(); }

    /**
     * @brief Returns an const iterator to the end.
     */
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
    {
        return &data_[0] + size();
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
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size_ == 0; }

    /**
     * @brief Returns the number of characters.
     */
    [[nodiscard]] constexpr auto size() const noexcept -> etl::size_t { return size_; }

    /**
     * @brief Returns the number of characters.
     */
    [[nodiscard]] constexpr auto length() const noexcept -> etl::size_t { return size_; }

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
     * @brief Returns a pointer to the underlying array serving as character storage. The
     * pointer is such that the range [data(); data() + size()) is valid and the values in
     * it correspond to the values stored in the string.
     *
     * @details Always null-terminated.
     */
    [[nodiscard]] constexpr auto data() noexcept -> CharType* { return &data_[0]; };

    /**
     * @brief Returns a pointer to the underlying array serving as character storage. The
     * pointer is such that the range [data(); data() + size()) is valid and the values in
     * it correspond to the values stored in the string.
     *
     * @details Always null-terminated.
     */
    [[nodiscard]] constexpr auto data() const noexcept -> const CharType*
    {
        return &data_[0];
    };

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
        return data();
    };

    /**
     * @brief Returns a etl::basic_string_view.
     */
    [[nodiscard]] constexpr
    operator basic_string_view<value_type, traits_type>() const noexcept
    {
        return basic_string_view<value_type, traits_type>(data(), size());
    }

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
    constexpr auto append(etl::size_t const count, CharType const s) noexcept
        -> basic_static_string&
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
    constexpr auto append(const_pointer s) noexcept -> basic_static_string&
    {
        auto const len = etl::strlen(s);
        return append(s, len);
    };

    /**
     * @brief Appends characters in the range [s, s + count). This range can
     * contain null characters.
     */
    constexpr auto append(const_pointer s, etl::size_t count) noexcept
        -> basic_static_string&
    {
        for (etl::size_t i = 0; i < count; i++) { data_[size_ + i] = s[i]; }
        size_ += count;
        data_[size_] = 0;

        return *this;
    };

    /**
     * @brief Inserts count copies of character ch at the position index.
     */
    constexpr auto insert(size_type index, size_type count, CharType ch) noexcept
        -> basic_static_string&
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
        -> basic_static_string&
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
                          size_type const count) noexcept -> basic_static_string&
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

    /**
     * @brief Resizes the string to contain count characters.
     *
     * @details If the current size is less than count, additional characters are
     * appended, maximum up to it's capacity. If the current size is greater than count,
     * the string is reduced to its first count elements.
     */
    constexpr auto resize(size_type count, CharType ch) noexcept -> void
    {
        if (size() > count) { size_ = count; }
        if (size() < count) { append(count, ch); }
    }

    /**
     * @brief Resizes the string to contain count characters.
     *
     * @details If the current size is less than count, additional characters are
     * appended, maximum up to it's capacity. If the current size is greater than count,
     * the string is reduced to its first count elements.
     */
    constexpr auto resize(size_type count) noexcept -> void { resize(count, CharType()); }

    /**
     * @brief Checks if the string begins with the given prefix.
     */
    [[nodiscard]] constexpr auto
    starts_with(etl::basic_string_view<CharType, Traits> sv) const noexcept -> bool
    {
        return etl::basic_string_view<CharType, Traits>(data(), size()).starts_with(sv);
    }

    /**
     * @brief Checks if the string begins with the given prefix.
     */
    [[nodiscard]] constexpr auto starts_with(CharType c) const noexcept -> bool
    {
        return etl::basic_string_view<CharType, Traits>(data(), size()).starts_with(c);
    }

    /**
     * @brief Checks if the string begins with the given prefix.
     */
    [[nodiscard]] constexpr auto starts_with(CharType const* str) const -> bool
    {
        return etl::basic_string_view<CharType, Traits>(data(), size()).starts_with(str);
    }

private:
    etl::size_t size_        = 0;
    CharType data_[Capacity] = {};
};

template <etl::size_t Capacity>
using static_string = basic_static_string<char, Capacity>;

}  // namespace etl

#endif  // TAETL_STRING_HPP