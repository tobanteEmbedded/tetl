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

#ifndef TAETL_STRING_VIEW_HPP
#define TAETL_STRING_VIEW_HPP

#include "algorithm.hpp"
#include "definitions.hpp"
#include "string.hpp"

namespace etl
{
/**
 * @brief The class template basic_string_view describes an object that can
 * refer to a constant contiguous sequence of char-like objects with the first
 * element of the sequence at position zero. A typical implementation holds only
 * two members: a pointer to constant CharType and a size.
 */
template <class CharType, class Traits = etl::char_traits<CharType>>
class basic_string_view
{
public:
    using traits_type     = Traits;
    using value_type      = CharType;
    using pointer         = CharType*;
    using const_pointer   = CharType const*;
    using reference       = CharType&;
    using const_reference = CharType const&;
    using const_iterator  = CharType const*;
    using iterator        = const_iterator;
    using size_type       = etl::size_t;
    using difference_type = etl::ptrdiff_t;
    // using const_reverse_iterator = etl::reverse_iterator<const_iterator>;
    // using reverse_iterator       = const_reverse_iterator;

    /**
     * @brief Default constructor. Constructs an empty basic_string_view. After
     * construction, data() is equal to nullptr, and size() is equal to 0.
     */
    constexpr basic_string_view() noexcept = default;

    /**
     * @brief Copy constructor. Constructs a view of the same content as other.
     * After construction, data() is equal to other.data(), and size() is equal
     * to other.size().
     */
    constexpr basic_string_view(
        basic_string_view const& other) noexcept = default;

    /**
     * @brief Constructs a view of the first count characters of the character
     * array starting with the element pointed by s. s can contain null
     * characters. The behavior is undefined if [s, s+count) is not a valid
     * range (even though the constructor may not access any of the elements of
     * this range). After construction, data() is equal to s, and size() is
     * equal to count.
     */
    constexpr basic_string_view(CharType const* str, size_type size)
        : begin_ {str}, size_ {size}
    {
    }

    /**
     * @brief Constructs a view of the null-terminated character string pointed
     * to by s, not including the terminating null character. The length of the
     * view is determined as if by Traits::length(s). The behavior is undefined
     * if [s, s+Traits::length(s)) is not a valid range. After construction,
     * data() is equal to s, and size() is equal to Traits::length(s).
     */
    constexpr basic_string_view(CharType const* str)
        : begin_ {str}, size_ {traits_type::length(str)}
    {
    }

    /**
     * @brief Replaces the view with that of view.
     */
    [[nodiscard]] constexpr auto
    operator                  =(const basic_string_view& view) noexcept
        -> basic_string_view& = default;

    /**
     * @brief Returns an iterator to the first character of the view.
     */
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        return begin_;
    }

    /**
     * @brief Returns an iterator to the first character of the view.
     */
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return begin_;
    }

    /**
     * @brief Returns an iterator to the character following the last character
     * of the view. This character acts as a placeholder, attempting to access
     * it results in undefined behavior.
     */
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return begin_ + size_;
    }

    /**
     * @brief Returns an iterator to the character following the last character
     * of the view. This character acts as a placeholder, attempting to access
     * it results in undefined behavior.
     */
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
    {
        return begin_ + size_;
    }

    /**
     * @brief Returns a const reference to the character at specified location
     * pos. No bounds checking is performed: the behavior is undefined if pos >=
     * size().
     */
    [[nodiscard]] constexpr auto at(size_type pos) const -> const_reference
    {
        return begin_[pos];
    }

    /**
     * @brief Returns a const reference to the character at specified location
     * pos. No bounds checking is performed: the behavior is undefined if pos >=
     * size().
     */
    [[nodiscard]] constexpr auto operator[](size_type pos) const
        -> const_reference
    {
        return at(pos);
    }

    /**
     * @brief Returns reference to the first character in the view. The behavior
     * is undefined if empty() == true.
     */
    [[nodiscard]] constexpr auto front() const -> const_reference
    {
        return *begin_;
    }

    /**
     * @brief Returns reference to the last character in the view. The behavior
     * is undefined if empty() == true.
     */
    [[nodiscard]] constexpr auto back() const -> const_reference
    {
        return begin_[size_ - 1];
    }

    /**
     * @brief Returns a pointer to the underlying character array. The pointer
     * is such that the range [data(); data() + size()) is valid and the values
     * in it correspond to the values of the view.
     */
    [[nodiscard]] constexpr auto data() const noexcept -> const_pointer
    {
        return begin_;
    }

    /**
     * @brief Returns the number of CharT elements in the view, i.e.
     * etl::distance(begin(), end()).
     */
    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return size_;
    }

    /**
     * @brief Returns the number of CharT elements in the view, i.e.
     * etl::distance(begin(), end()).
     */
    [[nodiscard]] constexpr auto length() const noexcept -> size_type
    {
        return size_;
    }

    /**
     * @brief The largest possible number of char-like objects that can be
     * referred to by a basic_string_view.
     */
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
    {
        return size_type(-1);
    }

    /**
     * @brief Checks if the view has no characters, i.e. whether size() == 0.
     */
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return size_ == 0;
    }

    /**
     * @brief Moves the start of the view forward by n characters. The behavior
     * is undefined if n > size().
     */
    constexpr auto remove_prefix(size_type n) -> void
    {
        begin_ += n;
        size_ -= n;
    }

    /**
     * @brief Moves the end of the view back by n characters. The behavior is
     * undefined if n > size().
     */
    constexpr auto remove_suffix(size_type n) -> void { size_ = size_ - n; }

    /**
     * @brief Copies the substring [pos, pos + rcount) to the character array
     * pointed to by dest, where rcount is the smaller of count and size() -
     * pos. Equivalent to Traits::copy(dest, data() + pos, rcount).
     */
    [[nodiscard]] constexpr auto copy(CharType* dest, size_type count,
                                      size_type pos = 0) const -> size_type
    {
        auto const rcount = etl::min(count, size() - pos);
        traits_type::copy(dest, data() + pos, rcount);
        return rcount;
    }

    /**
     * @brief Returns a view of the substring [pos, pos + rcount), where rcount
     * is the smaller of count and size() - pos.
     */
    constexpr auto substr(size_type pos = 0, size_type count = npos) const
        -> basic_string_view
    {
        auto const rcount = etl::min(count, size() - pos);
        return basic_string_view {begin_ + pos, rcount};
    }

    /**
     * @brief Checks if the string view begins with the given prefix, where the
     * prefix is a string view.
     *
     * @details Effectively returns substr(0, sv.size()) == sv
     */
    constexpr auto starts_with(basic_string_view sv) const noexcept -> bool
    {
        return substr(0, sv.size()) == sv;
    }

    /**
     * @brief Checks if the string view begins with the given prefix, where the
     * prefix is a single character.
     *
     * @details Effectively returns !empty() && Traits::eq(front(), c)
     */
    constexpr auto starts_with(CharType c) const noexcept -> bool
    {
        return !empty() && traits_type::eq(front(), c);
    }

    /**
     * @brief Checks if the string view begins with the given prefix, where the
     * the prefix is a null-terminated character string.
     *
     * @details Effectively returns starts_with(basic_string_view(s))
     */
    constexpr auto starts_with(const CharType* s) const -> bool
    {
        return starts_with(basic_string_view(s));
    }

    /**
     * @brief This is a special value equal to the maximum value representable
     * by the type size_type.
     *
     * @details The exact meaning depends on context, but it is generally used
     * either as end of view indicator by the functions that expect a view index
     * or as the error indicator by the functions that return a view index.
     */
    static constexpr size_type npos = size_type(-1);

private:
    const_pointer begin_ = nullptr;
    size_type size_      = 0;
};

/**
 * @brief Compares two views. All comparisons are done via the compare() member
 * function (which itself is defined in terms of Traits::compare()):
 *
 * @details Two views are equal if both the size of lhs and rhs are equal and
 * each character in lhs has an equivalent character in rhs at the same
 * position.
 */
template <class CharType, class Traits>
[[nodiscard]] constexpr auto
operator==(etl::basic_string_view<CharType, Traits> lhs,
           etl::basic_string_view<CharType, Traits> rhs) noexcept -> bool
{
    if (lhs.size() != rhs.size()) { return false; }
    return Traits::compare(lhs.data(), rhs.data(), lhs.size()) == 0;
}

/**
 * @brief Compares two views. All comparisons are done via the compare() member
 * function (which itself is defined in terms of Traits::compare()):
 *
 * @details Two views are equal if both the size of lhs and rhs are equal and
 * each character in lhs has an equivalent character in rhs at the same
 * position.
 */
template <class CharType, class Traits>
[[nodiscard]] constexpr auto
operator!=(etl::basic_string_view<CharType, Traits> lhs,
           etl::basic_string_view<CharType, Traits> rhs) noexcept -> bool
{
    return !(lhs == rhs);
}

/**
 * @brief Typedefs for common character type
 */
using string_view = basic_string_view<char, etl::char_traits<char>>;

}  // namespace etl

#endif  // TAETL_STRING_VIEW_HPP