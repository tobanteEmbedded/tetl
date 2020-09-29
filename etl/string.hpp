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
    using const_pointer   = CharType const*;
    using reference       = CharType&;
    using const_reference = CharType const&;
    using iterator        = CharType*;
    using const_iterator  = CharType const*;

    /**
     * @brief Default constructor.
     */
    constexpr basic_static_string() = default;

    /**
     * @brief Charater Pointer constant constructor.
     * Fails silently if input len is greater then capacity.
     */
    constexpr basic_static_string(const_pointer str, size_type const len) noexcept
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
    constexpr basic_static_string(const_pointer str) noexcept
        : basic_static_string(str, etl::strlen(str))
    {
    }

    /**
     * @brief Defaulted copy constructor.
     */
    constexpr basic_static_string(basic_static_string const& /*str*/) noexcept = default;

    /**
     * @brief Defaulted copy assignment.
     */
    constexpr auto operator     =(basic_static_string const& /*str*/) noexcept
        -> basic_static_string& = default;

    /**
     * @brief Defaulted move constructor.
     */
    constexpr basic_static_string(basic_static_string&& /*str*/) noexcept = default;

    /**
     * @brief Defaulted move assignment.
     */
    constexpr auto operator     =(basic_static_string&& /*str*/) noexcept
        -> basic_static_string& = default;

    /**
     * @brief Trivial defaulted destructor
     */
    ~basic_static_string() noexcept = default;

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr auto at(size_type index) noexcept -> reference
    {
        if (index < size_) { return data_[index]; }
        return data_[size_];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    [[nodiscard]] constexpr auto at(size_type index) const noexcept -> const_reference
    {
        if (index < size_) { return data_[index]; }
        return data_[size_];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr auto operator[](size_type index) noexcept -> reference
    {
        if (index < size_) { return data_[index]; }
        return data_[size_];
    }

    /**
     * @brief Accesses the specified character with bounds checking.
     */
    constexpr auto operator[](size_type index) const noexcept -> const_reference
    {
        if (index < size_) { return data_[index]; }
        return data_[size_];
    }

    /**
     * @brief Returns an iterator to the beginning.
     */
    constexpr auto begin() noexcept -> iterator { return data(); }

    /**
     * @brief Returns an const iterator to the beginning.
     */
    constexpr auto begin() const noexcept -> const_iterator { return data(); }

    /**
     * @brief Returns an const iterator to the beginning.
     */
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return begin();
    }

    /**
     * @brief Returns an iterator to the end.
     */
    constexpr auto end() noexcept -> iterator { return begin() + size(); }

    /**
     * @brief Returns an const iterator to the end.
     */
    constexpr auto end() const noexcept -> const_iterator { return begin() + size(); }

    /**
     * @brief Returns an const iterator to the end.
     */
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator { return end(); }

    /**
     * @brief Accesses the first character.
     */
    [[nodiscard]] constexpr auto front() noexcept -> reference
    {
        assert(!empty());
        return data_[0];
    }

    /**
     * @brief Accesses the first character.
     */
    [[nodiscard]] constexpr auto front() const noexcept -> const_reference
    {
        assert(!empty());
        return data_[0];
    }

    /**
     * @brief Accesses the last character.
     */
    [[nodiscard]] constexpr auto back() noexcept -> reference
    {
        assert(!empty());
        return data_[size_ - 1];
    }

    /**
     * @brief Accesses the last character.
     */
    [[nodiscard]] constexpr auto back() const noexcept -> const_reference
    {
        assert(!empty());
        return data_[size_ - 1];
    }

    /**
     * @brief Checks whether the string is empty.
     */
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size_ == 0; }

    /**
     * @brief Returns the number of characters.
     */
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return size_; }

    /**
     * @brief Returns the number of characters.
     */
    [[nodiscard]] constexpr auto length() const noexcept -> size_type { return size_; }

    /**
     * @brief Returns the number of characters that can be held in allocated
     * storage.
     */
    [[nodiscard]] constexpr auto capacity() const noexcept -> size_type
    {
        return Capacity;
    }

    /**
     * @brief Returns the number of characters that can be held in allocated
     * storage.
     */
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
    {
        return Capacity;
    }

    /**
     * @brief Reserve is deleted, since the capacity is fixed.
     */
    constexpr auto reserve(size_type new_cap) -> void = delete;

    /**
     * @brief Shrink to fit is deleted, since the capacity is fixed.
     */
    constexpr auto shrink_to_fit() -> void = delete;

    /**
     * @brief Returns a pointer to the underlying array serving as character storage. The
     * pointer is such that the range [data(); data() + size()) is valid and the values in
     * it correspond to the values stored in the string.
     *
     * @details Always null-terminated.
     */
    [[nodiscard]] constexpr auto data() noexcept -> pointer { return &data_[0]; };

    /**
     * @brief Returns a pointer to the underlying array serving as character storage. The
     * pointer is such that the range [data(); data() + size()) is valid and the values in
     * it correspond to the values stored in the string.
     *
     * @details Always null-terminated.
     */
    [[nodiscard]] constexpr auto data() const noexcept -> const_pointer
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
    [[nodiscard]] constexpr auto c_str() const noexcept -> const_pointer
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
     * @brief Appends the given character ch to the end of the string. Does nothing if the
     * string is full.
     */
    constexpr auto push_back(value_type ch) noexcept -> void
    {
        if (size() < capacity()) { append(1, ch); }
    }

    /**
     * @brief Removes the last character from the string. Does nothing if the
     * string is empty.
     */
    constexpr auto pop_back() noexcept -> void
    {
        if (!empty())
        {
            data_[size_ - 1] = '\0';
            size_--;
        }
    }

    /**
     * @brief Appends count copies of character s.
     */
    constexpr auto append(size_type const count, value_type const s) noexcept
        -> basic_static_string&
    {
        for (size_type i = 0; i < count; i++) { data_[size_ + i] = s; }
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
    constexpr auto append(const_pointer s, size_type count) noexcept
        -> basic_static_string&
    {
        for (size_type i = 0; i < count; i++) { data_[size_ + i] = s[i]; }
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
     * @brief Compares this string to str.
     */
    [[nodiscard]] constexpr auto compare(basic_static_string const& str) const noexcept
        -> int
    {
        return compare_impl(data(), size(), str.data(), str.size());
    }

    /**
     * @brief Compares this string to str with other capacity.
     */
    template <size_type OtherCapacity>
    [[nodiscard]] constexpr auto
    compare(basic_static_string<value_type, OtherCapacity, traits_type> const& str)
        const noexcept -> int
    {
        return compare_impl(data(), size(), str.data(), str.size());
    }

    /**
     * @brief Compares a [pos1, pos1+count1) substring of this string to str. If count1 >
     * size() - pos1 the substring is [pos1, size()).
     *
     * @todo Implement.
     */
    [[nodiscard]] constexpr auto compare(size_type pos1, size_type count1,
                                         basic_static_string const& str) const -> int
    {
        etl::ignore_unused(pos1, count1, str);
        return 0;
    }

    /**
     * @brief Compares a [pos1, pos1+count1) substring of this string to a substring
     * [pos2, pos2+count2) of str. If count1 > size() - pos1 the first substring is [pos1,
     * size()). Likewise, count2 > str.size() - pos2 the second substring is [pos2,
     * str.size()).
     *
     * @todo Implement.
     */
    [[nodiscard]] constexpr auto compare(size_type pos1, size_type count1,
                                         basic_static_string const& str, size_type pos2,
                                         size_type count2 = npos) const -> int
    {
        etl::ignore_unused(pos1, count1, str, pos2, count2);
        return 0;
    }

    /**
     * @brief Compares this string to the null-terminated character sequence beginning at
     * the character pointed to by s with length Traits::length(s).
     */
    [[nodiscard]] constexpr auto compare(const_pointer s) const -> int
    {
        return compare_impl(data(), size(), s, Traits::length(s));
    }

    /**
     * @brief Compares a [pos1, pos1+count1) substring of this string to the
     * null-terminated character sequence beginning at the character pointed to by s with
     * length Traits::length(s). If count1 > size() - pos1 the substring is [pos1,
     * size()).
     *
     * @todo Implement.
     */
    [[nodiscard]] constexpr auto compare(size_type pos1, size_type count1,
                                         const_pointer s) const -> int
    {
        etl::ignore_unused(pos1, count1, s);
        return 0;
    }

    /**
     * @brief  Compares a [pos1, pos1+count1) substring of this string to the characters
     * in the range [s, s + count2). If count1 > size() - pos1 the substring is [pos1,
     * size()). (Note: the characters in the range [s, s + count2) may include null
     * characters.)
     *
     * @todo Implement.
     */
    [[nodiscard]] constexpr auto compare(size_type pos1, size_type count1,
                                         const_pointer s, size_type count2) const -> int
    {
        etl::ignore_unused(pos1, count1, s, count2);
        return 0;
    }

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
    [[nodiscard]] constexpr auto starts_with(const_pointer str) const -> bool
    {
        return etl::basic_string_view<CharType, Traits>(data(), size()).starts_with(str);
    }

    /**
     * @brief Checks if the string ends with the given prefix.
     */
    [[nodiscard]] constexpr auto
    ends_with(etl::basic_string_view<CharType, Traits> sv) const noexcept -> bool
    {
        return etl::basic_string_view<CharType, Traits>(data(), size()).ends_with(sv);
    }

    /**
     * @brief Checks if the string ends with the given prefix.
     */
    [[nodiscard]] constexpr auto ends_with(CharType c) const noexcept -> bool
    {
        return etl::basic_string_view<CharType, Traits>(data(), size()).ends_with(c);
    }

    /**
     * @brief Checks if the string ends with the given prefix.
     */
    [[nodiscard]] constexpr auto ends_with(const_pointer str) const -> bool
    {
        return etl::basic_string_view<CharType, Traits>(data(), size()).ends_with(str);
    }

    /**
     * @brief Returns a substring [pos, pos+count). If the requested substring extends
     * past the end of the string, or if count == npos, the returned substring is [pos,
     * size()).
     *
     * If \p pos is greater then size(), an empty string will be returned.
     */
    [[nodiscard]] constexpr auto substr(size_type pos = 0, size_type count = npos) const
        -> basic_static_string
    {
        if (pos > size()) { return {}; }
        return basic_static_string(data() + pos, etl::min(count, size() - pos));
    }

    /**
     * @brief Copies a substring [pos, pos+count) to character string pointed to by dest.
     * If the requested substring lasts past the end of the string, or if count == npos,
     * the copied substring is [pos, size()). The resulting character string is not
     * null-terminated.
     *
     * If \p pos is greater then size(), nothing will be copied.
     *
     * @return Number of characters copied.
     */
    constexpr auto copy(pointer destination, size_type count, size_type pos = 0) const
        -> size_type
    {
        if (pos > size()) { return 0; }
        auto first       = data() + pos;
        auto last        = first + etl::min(count, size() - pos);
        auto const* dest = destination;
        auto const* res  = etl::copy(first, last, destination);
        return static_cast<size_type>(res - dest);
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
     * @brief Exchanges the contents of the string with those of other. All iterators and
     * references may be invalidated.
     */
    constexpr auto swap(basic_static_string& other) noexcept -> void
    {
        auto temp(etl::move(other));
        other = etl::move(*this);
        *this = etl::move(temp);
    }

    /**
     * @brief Finds the first substring equal to the given character sequence. Search
     * begins at pos, i.e. the found substring must not begin in a position preceding pos.
     *
     * https://en.cppreference.com/w/cpp/string/basic_string/find
     *
     * @return Position of the first character of the found substring or npos if no such
     * substring is found.
     */
    [[nodiscard]] constexpr auto find(basic_static_string const& str,
                                      size_type pos = 0) const noexcept -> size_type
    {
        return find(str.c_str(), pos, str.size());
    }

    /**
     * @brief Finds the first substring equal to the given character sequence. Search
     * begins at pos, i.e. the found substring must not begin in a position preceding pos.
     *
     * https://en.cppreference.com/w/cpp/string/basic_string/find
     *
     * @return Position of the first character of the found substring or npos if no such
     * substring is found.
     */
    [[nodiscard]] constexpr auto find(const_pointer s, size_type pos,
                                      size_type count) const noexcept -> size_type
    {
        // an empty substring is found at pos if and only if pos <= size()
        if (count == 0 && pos <= size()) { return pos; }

        // A substring can be found only if pos <= size() - str.size()
        if (pos <= size() - count)
        {
            for (auto i = size_type(pos); i < size(); ++i)
            {
                auto found = i;
                for (auto j = size_type(0); j < count; ++j)
                {
                    if (!(data_[i + j] == s[j]))
                    {
                        found = npos;
                        break;
                    }
                }

                if (found != npos) { return found; }
            }
        }

        // For a non-empty substring, if pos >= size(), the function always returns npos.
        return npos;
    }

    /**
     * @brief Finds the first substring equal to the given character sequence. Search
     * begins at pos, i.e. the found substring must not begin in a position preceding pos.
     *
     * https://en.cppreference.com/w/cpp/string/basic_string/find
     *
     * @return Position of the first character of the found substring or npos if no such
     * substring is found.
     */
    [[nodiscard]] constexpr auto find(const_pointer s, size_type pos = 0) const noexcept
        -> size_type
    {
        return find(s, pos, traits_type::length(s));
    }

    /**
     * @brief Finds the first substring equal to the given character sequence. Search
     * begins at pos, i.e. the found substring must not begin in a position preceding pos.
     *
     * https://en.cppreference.com/w/cpp/string/basic_string/find
     *
     * @return Position of the first character of the found substring or npos if no such
     * substring is found.
     */
    [[nodiscard]] constexpr auto find(value_type ch, size_type pos = 0) const noexcept
        -> size_type
    {
        if (pos < size())
        {
            auto found = etl::find(begin() + pos, end(), ch);
            if (found == end()) { return npos; }
            return static_cast<size_type>(etl::distance(begin(), found));
        }

        return npos;
    }

    /**
     * @brief Finds the first character equal to one of the characters in the given
     * character sequence. The search considers only the interval [pos, size()). If the
     * character is not present in the interval, npos will be returned.
     */
    [[nodiscard]] constexpr auto find_first_of(basic_static_string const& str,
                                               size_type pos = 0) const noexcept
        -> size_type
    {
        return find_first_of(str.c_str(), pos, str.size());
    }

    /**
     * @brief Finds the first character equal to one of the characters in the given
     * character sequence. The search considers only the interval [pos, size()). If the
     * character is not present in the interval, npos will be returned.
     */
    [[nodiscard]] constexpr auto find_first_of(const_pointer s, size_type pos,
                                               size_type count) const -> size_type
    {
        if (pos < size())
        {
            for (auto i = size_type(pos); i < size(); ++i)
            {
                for (auto j = size_type(0); j < count; ++j)
                {
                    if (data_[i] == s[j]) { return i; }
                }
            }
        }

        return npos;
    }

    /**
     * @brief Finds the first character equal to one of the characters in the given
     * character sequence. The search considers only the interval [pos, size()). If the
     * character is not present in the interval, npos will be returned.
     */
    [[nodiscard]] constexpr auto find_first_of(const_pointer s, size_type pos = 0) const
        -> size_type
    {
        return find_first_of(s, pos, traits_type::length(s));
    }

    /**
     * @brief Finds the first character equal to one of the characters in the given
     * character sequence. The search considers only the interval [pos, size()). If the
     * character is not present in the interval, npos will be returned.
     */
    [[nodiscard]] constexpr auto find_first_of(value_type ch,
                                               size_type pos = 0) const noexcept
        -> size_type
    {
        return find_first_of(&ch, pos, 1);
    }

    /**
     * @brief This is a special value equal to the maximum value representable by the type
     * size_type. The exact meaning depends on context, but it is generally used either as
     * end of string indicator by the functions that expect a string index or as the error
     * indicator by the functions that return a string index.
     */
    constexpr static size_type npos = static_cast<size_type>(-1);

private:
    [[nodiscard]] constexpr auto compare_impl(const_pointer lhs, size_type lhs_size,
                                              const_pointer rhs,
                                              size_type rhs_size) const noexcept -> int
    {
        auto const min_size = etl::min(lhs_size, rhs_size);
        auto const result   = traits_type::compare(lhs, rhs, min_size);
        if (result != 0) { return result; }
        if (lhs_size < rhs_size) { return -1; }
        if (lhs_size > rhs_size) { return 1; }
        return 0;
    }

    size_type size_          = 0;
    CharType data_[Capacity] = {};
};  // namespace etl

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details Two strings are equal if both the size of lhs and rhs are equal and each
 * character in lhs has equivalent character in rhs at the same position.
 */
template <typename CharType, typename Traits, etl::size_t Capacity1,
          etl::size_t Capacity2>
[[nodiscard]] constexpr auto
operator==(etl::basic_static_string<CharType, Capacity1, Traits> const& lhs,
           etl::basic_static_string<CharType, Capacity2, Traits> const& rhs) noexcept
    -> bool
{
    return lhs.compare(rhs) == 0;
}

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details Two strings are equal if both the size of lhs and rhs are equal and each
 * character in lhs has equivalent character in rhs at the same position.
 */
template <typename CharType, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator==(etl::basic_static_string<CharType, Capacity1, Traits> const& lhs,
           CharType const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) == 0;
}

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details Two strings are equal if both the size of lhs and rhs are equal and each
 * character in lhs has equivalent character in rhs at the same position.
 */
template <typename CharType, typename Traits, etl::size_t Capacity1,
          etl::size_t Capacity2>
[[nodiscard]] constexpr auto
operator!=(etl::basic_static_string<CharType, Capacity1, Traits> const& lhs,
           etl::basic_static_string<CharType, Capacity2, Traits> const& rhs) noexcept
    -> bool
{
    return lhs.compare(rhs) != 0;
}

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details Two strings are equal if both the size of lhs and rhs are equal and each
 * character in lhs has equivalent character in rhs at the same position.
 */
template <typename CharType, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator!=(etl::basic_static_string<CharType, Capacity1, Traits> const& lhs,
           CharType const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) != 0;
}

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details The ordering comparisons are done lexicographically.
 */
template <typename CharType, typename Traits, etl::size_t Capacity1,
          etl::size_t Capacity2>
[[nodiscard]] constexpr auto
operator<(etl::basic_static_string<CharType, Capacity1, Traits> const& lhs,
          etl::basic_static_string<CharType, Capacity2, Traits> const& rhs) noexcept
{
    return lhs.compare(rhs) < 0;
}

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details The ordering comparisons are done lexicographically.
 */
template <typename CharType, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator<(etl::basic_static_string<CharType, Capacity1, Traits> const& lhs,
          CharType const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) < 0;
}

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details The ordering comparisons are done lexicographically.
 */
template <typename CharType, typename Traits, etl::size_t Capacity1,
          etl::size_t Capacity2>
[[nodiscard]] constexpr auto
operator<=(etl::basic_static_string<CharType, Capacity1, Traits> const& lhs,
           etl::basic_static_string<CharType, Capacity2, Traits> const& rhs) noexcept
{
    return lhs.compare(rhs) <= 0;
}

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details The ordering comparisons are done lexicographically.
 */
template <typename CharType, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator<=(etl::basic_static_string<CharType, Capacity1, Traits> const& lhs,
           CharType const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) <= 0;
}

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details The ordering comparisons are done lexicographically.
 */
template <typename CharType, typename Traits, etl::size_t Capacity1,
          etl::size_t Capacity2>
[[nodiscard]] constexpr auto
operator>(etl::basic_static_string<CharType, Capacity1, Traits> const& lhs,
          etl::basic_static_string<CharType, Capacity2, Traits> const& rhs) noexcept
{
    return lhs.compare(rhs) > 0;
}

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details The ordering comparisons are done lexicographically.
 */
template <typename CharType, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator>(etl::basic_static_string<CharType, Capacity1, Traits> const& lhs,
          CharType const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) > 0;
}

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details The ordering comparisons are done lexicographically.
 */
template <typename CharType, typename Traits, etl::size_t Capacity1,
          etl::size_t Capacity2>
[[nodiscard]] constexpr auto
operator>=(etl::basic_static_string<CharType, Capacity1, Traits> const& lhs,
           etl::basic_static_string<CharType, Capacity2, Traits> const& rhs) noexcept
{
    return lhs.compare(rhs) >= 0;
}

/**
 * @brief Compares the contents of a string with another string or a null-terminated array
 * of CharType.
 *
 * @details The ordering comparisons are done lexicographically.
 */
template <typename CharType, typename Traits, etl::size_t Capacity>
[[nodiscard]] constexpr auto
operator>=(etl::basic_static_string<CharType, Capacity, Traits> const& lhs,
           CharType const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) >= 0;
}

/**
 * @brief Specializes the std::swap algorithm for std::basic_string. Swaps the contents of
 * lhs and rhs. Equivalent to lhs.swap(rhs).
 */
template <typename CharType, typename Traits, etl::size_t Capacity>
constexpr auto swap(etl::basic_static_string<CharType, Capacity, Traits>& lhs,
                    etl::basic_static_string<CharType, Capacity, Traits>&
                        rhs) noexcept(noexcept(lhs.swap(rhs))) -> void
{
    lhs.swap(rhs);
}

template <etl::size_t Capacity>
using static_string = basic_static_string<char, Capacity>;

}  // namespace etl

#endif  // TAETL_STRING_HPP