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

#include "etl/detail/container_utils.hpp"
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
    // clang-format off
    template <typename T>
    constexpr static bool string_view_and_not_char_pointer = 
        is_convertible_v<T const&, basic_string_view<CharType, Traits>> 
        && !is_convertible_v<T const&, CharType const*>;
    // clang-format on

public:
    using traits_type            = Traits;
    using value_type             = CharType;
    using size_type              = etl::size_t;
    using pointer                = CharType*;
    using const_pointer          = CharType const*;
    using reference              = CharType&;
    using const_reference        = CharType const&;
    using iterator               = CharType*;
    using const_iterator         = CharType const*;
    using reverse_iterator       = etl::reverse_iterator<iterator>;
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

    /**
     * @brief Default constructor.
     */
    constexpr basic_static_string() = default;

    /**
     * @brief Character pointer constructor.
     *
     * @details Fails silently if input len is greater then capacity.
     */
    constexpr basic_static_string(const_pointer str, size_type const len) noexcept
    {
        assert(len + 1 <= Capacity && "size + null-terminator greater than capacity");

        if (str != nullptr && len + 1 < Capacity)
        {
            clear_storage();
            size_ = len;
            etl::memcpy(&data_[0], str, len);
        }
    }

    /**
     * @brief Character pointer constructor. Calls etl::strlen.
     *
     * @details Fails silently if input length is greater then capacity.
     */
    constexpr basic_static_string(const_pointer str) noexcept
        : basic_static_string(str, etl::strlen(str))
    {
    }

    /**
     * @brief Constructs the string with \p count copies of character \p ch.
     *
     * @details Fails silently if input length is greater then capacity.
     */
    constexpr basic_static_string(size_type count, value_type ch) noexcept
    {
        assert(count + 1 <= Capacity && "size + null-terminator greater than capacity");
        if (count + 1 <= Capacity)
        {
            clear_storage();
            fill(begin(), begin() + count, ch);
            size_ = count;
        }
    }

    /**
     * @brief Constructs the string with the contents of the range [ \p first, \p last).
     * Fails silently if input length is greater then capacity.
     */
    template <typename InputIter, TAETL_REQUIRES_(detail::InputIterator<InputIter>)>
    constexpr basic_static_string(InputIter first, InputIter last) noexcept
        : basic_static_string(first, static_cast<size_type>(distance(first, last)))
    {
    }

    /**
     * @brief Constructs the string with a substring [pos, pos+count) of other.
     */
    constexpr basic_static_string(basic_static_string const& other, size_type pos,
                                  size_type count)
        : basic_static_string {other.substr(pos, count)}
    {
    }

    /**
     * @brief Constructs the string with a substring [pos, other.size()).
     */
    constexpr basic_static_string(basic_static_string const& other, size_type pos)
        : basic_static_string {other.substr(pos, other.size())}
    {
    }

    /**
     * @brief Implicitly converts \p t to a string view sv, then initializes the string
     * with the contents of sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    explicit constexpr basic_static_string(T const& t) noexcept

    {
        basic_string_view<value_type, traits_type> const sv = t;
        assign(sv.begin(), sv.end());
    }

    /**
     * @brief Implicitly converts \p t to a string view sv, then initializes the string
     * with the subrange [ \p pos, \p pos + \p n ) of sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    explicit constexpr basic_static_string(T const& t, size_type pos, size_type n)
        : basic_static_string {
            basic_string_view<value_type, traits_type> {t}.substr(pos, n)}
    {
    }

    /**
     * @brief Defaulted copy constructor.
     */
    constexpr basic_static_string(basic_static_string const& /*str*/) noexcept = default;

    /**
     * @brief Defaulted move constructor.
     */
    constexpr basic_static_string(basic_static_string&& /*str*/) noexcept = default;

    /**
     * @brief Defaulted copy assignment.
     */
    constexpr auto operator     =(basic_static_string const& /*str*/) noexcept
        -> basic_static_string& = default;

    /**
     * @brief Defaulted move assignment.
     */
    constexpr auto operator     =(basic_static_string&& /*str*/) noexcept
        -> basic_static_string& = default;

    /**
     * @brief Replaces the contents with those of null-terminated character string
     pointed to by \p s.
     */
    constexpr auto operator=(const_pointer s) noexcept -> basic_static_string&
    {
        assign(s, traits_type::length(s));
        return *this;
    }

    /**
     * @brief Replaces the contents with character \p ch.
     */
    constexpr auto operator=(value_type ch) noexcept -> basic_static_string&
    {
        assign(etl::addressof(ch), 1);
        return *this;
    }

    /**
     * @brief Implicitly converts \p t to a string view sv, then replaces the contents
     * with those of the sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    constexpr auto operator=(T const& t) noexcept -> basic_static_string&
    {
        assign(t);
        return *this;
    }

    /**
     * @brief Replaces the contents with count copies of character ch.
     */
    constexpr auto assign(size_type count, value_type ch) noexcept -> basic_static_string&
    {
        (*this) = basic_static_string {count, ch};
        return *this;
    }

    /**
     * @brief Replaces the contents with a copy of str.
     */
    constexpr auto assign(basic_static_string const& str) noexcept -> basic_static_string&
    {
        *this = str;
        return *this;
    }

    /**
     * @brief Replaces the contents with a substring [ \p pos, \p pos + \p count )
     * of \p str.
     */
    constexpr auto assign(basic_static_string const& str, size_type pos,
                          size_type count = npos) noexcept -> basic_static_string&
    {
        *this = str.substr(pos, count);
        return *this;
    }

    /**
     * @brief Replaces the contents with those of \p str using move semantics.
     */
    constexpr auto assign(basic_static_string&& str) noexcept -> basic_static_string&
    {
        *this = etl::move(str);
        return *this;
    }

    /**
     * @brief Replaces the contents with copies of the characters in the range
     * [ \p s, \p s + \p count ). This range can contain null characters.
     */
    constexpr auto assign(const_pointer s, size_type count) noexcept
        -> basic_static_string&
    {
        *this = basic_static_string {s, count};
        return *this;
    }

    /**
     * @brief Replaces the contents with those of null-terminated character string pointed
     * to by \p s.
     */
    constexpr auto assign(const_pointer s) noexcept -> basic_static_string&
    {
        *this = basic_static_string {s, etl::strlen(s)};
        return *this;
    }

    /**
     * @brief Replaces the contents with copies of the characters in the
     * range [ \p first , \p last ).
     */
    template <typename InputIt, TAETL_REQUIRES_(detail::InputIterator<InputIt>)>
    constexpr auto assign(InputIt first, InputIt last) noexcept -> basic_static_string&
    {
        *this = basic_static_string {first, last};
        return *this;
    }

    /**
     * @brief Implicitly converts \p t to a string view sv, then replaces the contents
     * with the characters from sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    constexpr auto assign(T const& t) noexcept -> basic_static_string&
    {
        auto tmp = basic_static_string {basic_static_string {t}};
        *this    = tmp;
        return *this;
    }

    /**
     * @brief Implicitly converts \p t to a string view sv, then replaces the contents
     * with the characters from the subview [ \p pos, \p pos + \p count ) of sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    constexpr auto assign(T const& t, size_type pos, size_type count = npos) noexcept
        -> basic_static_string&
    {
        auto tmp = basic_static_string {basic_static_string {t, pos, count}};
        *this    = tmp;
        return *this;
    }

    /**
     * @brief Trivial defaulted destructor
     */
    ~basic_static_string() noexcept = default;

    /**
     * @brief Accesses the specified character without bounds checking.
     */
    constexpr auto operator[](size_type index) noexcept -> reference
    {
        assert(index < size_);
        return data_[index];
    }

    /**
     * @brief Accesses the specified character without bounds checking.
     */
    constexpr auto operator[](size_type index) const noexcept -> const_reference
    {
        assert(index < size_);
        return data_[index];
    }

    /**
     * @brief Returns an iterator to the beginning.
     */
    constexpr auto begin() noexcept -> iterator { return data(); }

    /**
     * @brief Returns an const iterator to the beginning.
     */
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        return data();
    }

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
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return begin() + size();
    }

    /**
     * @brief Returns an const iterator to the end.
     */
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator { return end(); }

    /**
     * @brief Returns a reverse iterator to the first character of the reversed string. It
     * corresponds to the last character of the non-reversed string.
     */
    [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator
    {
        return reverse_iterator(end());
    }

    /**
     * @brief Returns a reverse iterator to the first character of the reversed string. It
     * corresponds to the last character of the non-reversed string.
     */
    [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(end());
    }

    /**
     * @brief Returns a reverse iterator to the first character of the reversed string. It
     * corresponds to the last character of the non-reversed string.
     */
    [[nodiscard]] constexpr auto crbegin() const noexcept -> const_reverse_iterator
    {
        return rbegin();
    }

    /**
     * @brief Returns a reverse iterator to the first character of the reversed string. It
     * corresponds to the last character of the non-reversed string.
     */
    [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator
    {
        return reverse_iterator(begin());
    }

    /**
     * @brief Returns a reverse iterator to the first character of the reversed string. It
     * corresponds to the last character of the non-reversed string.
     */
    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(begin());
    }

    /**
     * @brief Returns a reverse iterator to the first character of the reversed string. It
     * corresponds to the last character of the non-reversed string.
     */
    [[nodiscard]] constexpr auto crend() const noexcept -> const_reverse_iterator
    {
        return rend();
    }

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
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size() == 0; }

    /**
     * @brief Checks whether the string is full. Equals to capacity - 1, for the null
     * termination character.
     */
    [[nodiscard]] constexpr auto full() const noexcept -> bool
    {
        return size() == capacity() - 1;
    }

    /**
     * @brief Returns the number of characters.
     */
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return size_; }

    /**
     * @brief Returns the number of characters.
     */
    [[nodiscard]] constexpr auto length() const noexcept -> size_type { return size(); }

    /**
     * @brief Returns the number of characters that can be held in allocated
     * storage, including the space for the null terminator.
     */
    [[nodiscard]] constexpr auto capacity() const noexcept -> size_type
    {
        return Capacity;
    }

    /**
     * @brief Returns the number of characters that can be held in allocated
     * storage, including the space for the null terminator.
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
     * @brief Removes all characters from the string. Sets size to 0 and overrides the
     * buffer with zeros.
     */
    constexpr auto clear() noexcept -> void
    {
        clear_storage();
        size_ = 0;
    }

    /**
     * @brief Removes min(count, size() - index) characters starting at index.
     *
     * @return *this
     */
    constexpr auto erase(size_type index = 0, size_type count = npos) noexcept
        -> basic_static_string&
    {
        auto safe_count = etl::min(count, size() - index);
        erase(begin() + index, begin() + index + safe_count);
        return *this;
    }

    /**
     * @brief Removes the character at position.
     *
     * @return iterator pointing to the character immediately following the character
     * erased, or end() if no such character exists.
     */
    constexpr auto erase(const_iterator position) noexcept -> iterator
    {
        return erase(position, position + 1);
    }

    /**
     * @brief Removes the characters in the range [first, last).
     *
     * @return iterator pointing to the character last pointed to before the erase, or
     * end() if no such character exists.
     */
    constexpr auto erase(const_iterator first, const_iterator last) noexcept -> iterator
    {
        auto const start    = static_cast<size_type>(etl::distance(cbegin(), first));
        auto const distance = static_cast<size_type>(etl::distance(first, last));
        assert(size() > distance);
        etl::rotate(begin() + start, begin() + start + distance, end());
        // etl::fill(begin() + distance, end(), '\0');
        size_ -= distance;
        data_[size()] = '\0';
        return begin() + start;
    }

    /**
     * @brief Appends the given character ch to the end of the string. Does nothing if the
     * string is full.
     */
    constexpr auto push_back(value_type ch) noexcept -> void
    {
        assert(size() < capacity());
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
        auto const safe_count = etl::min(count, capacity() - size() - 1);
        for (size_type i = 0; i < safe_count; i++) { data_[size_ + i] = s; }
        size_ += safe_count;
        data_[size_] = 0;
        return *this;
    };

    /**
     * @brief Appends the null-terminated character string pointed to by \p s. The
     * length of the string is determined by the first null character using
     */
    constexpr auto append(const_pointer s) noexcept -> basic_static_string&
    {
        auto const len = etl::strlen(s);
        return append(s, len);
    };

    /**
     * @brief Appends characters in the range [ \p s, \p s + \p count ). This range can
     * contain null characters.
     */
    constexpr auto append(const_pointer s, size_type count) noexcept
        -> basic_static_string&
    {
        auto const safe_count = etl::min(count, capacity() - size() - 1);
        for (size_type i = 0; i < safe_count; i++) { data_[size_ + i] = s[i]; }
        size_ += safe_count;
        data_[size_] = 0;
        return *this;
    };

    /**
     * @brief Appends characters in the range [ \p first , \p last ).
     */
    template <typename InputIter, TAETL_REQUIRES_(detail::InputIterator<InputIter>)>
    constexpr auto append(InputIter first, InputIter last) noexcept
        -> basic_static_string&
    {
        assert(capacity() - size() > static_cast<size_type>(etl::distance(first, last)));
        for (; first != last; ++first) { push_back(*first); }
        return *this;
    }

    /**
     * @brief Appends string \p str.
     */
    constexpr auto append(basic_static_string const& str) noexcept -> basic_static_string&
    {
        return append(str.begin(), str.end());
    }

    /**
     * @brief Appends a substring [ \p pos, \p pos + \p count ) of \p str.
     */
    constexpr auto append(basic_static_string const& str, size_type pos,
                          size_type count = npos) noexcept -> basic_static_string&
    {
        return append(str.substr(pos, count));
    }

    /**
     * @brief Implicitly converts \p t to a string_view sv, then appends all characters
     * from sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    constexpr auto append(T const& t) -> basic_static_string&
    {
        etl::basic_string_view<value_type, traits_type> sv = t;
        return append(sv.data(), sv.size());
    }

    /**
     * @brief Implicitly converts \p t to a string_view sv then appends the characters
     * from the subview [ \p pos, \p pos + \p count ) of sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    constexpr auto append(T const& t, size_type pos, size_type count = npos)
        -> basic_static_string&
    {
        etl::basic_string_view<value_type, traits_type> sv = t;
        return append(sv.substr(pos, count));
    }

    /**
     * @brief Appends string \p str.
     */
    constexpr auto operator+=(basic_static_string const& str) noexcept
        -> basic_static_string&
    {
        return append(str);
    }

    /**
     * @brief Appends character ch.
     */
    constexpr auto operator+=(value_type ch) noexcept -> basic_static_string&
    {
        return append(1, ch);
    }

    /**
     * @brief Appends the null-terminated character string pointed to by s.
     */
    constexpr auto operator+=(const_pointer s) noexcept -> basic_static_string&
    {
        return append(s);
    }

    /**
     * @brief Implicitly converts \p t to a string view sv, then appends characters in the
     * string view sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    constexpr auto operator+=(T const& t) noexcept -> basic_static_string&
    {
        return append(t);
    }

    /**
     * @brief Inserts count copies of character ch at the position index.
     */
    constexpr auto insert(size_type const index, size_type const count,
                          value_type const ch) noexcept -> basic_static_string&
    {
        for (size_type i = 0; i < count; ++i)
        { insert_impl(begin() + index, etl::addressof(ch), 1); }
        return *this;
    }

    /**
     * @brief Inserts null-terminated character string pointed to by s at the
     * position index.
     */
    constexpr auto insert(size_type const index, const_pointer s) noexcept
        -> basic_static_string&
    {
        insert_impl(begin() + index, s, etl::strlen(s));
        return *this;
    }

    /**
     * @brief Inserts the characters in the range [s, s+count) at the position
     * index. The range can contain null characters.
     */
    constexpr auto insert(size_type const index, const_pointer s,
                          size_type const count) noexcept -> basic_static_string&
    {
        insert_impl(begin() + index, s, count);
        return *this;
    }

    /**
     * @brief Inserts string \p str at the position \p index.
     */
    constexpr auto insert(size_type const index, basic_static_string const& str) noexcept
        -> basic_static_string&
    {
        insert_impl(begin() + index, str.data(), str.size());
        return *this;
    }

    /**
     * @brief Inserts a string, obtained by str.substr(index_str, count) at the position
     * index.
     */
    constexpr auto insert(size_type const index, basic_static_string const& str,
                          size_type const index_str,
                          size_type const count = npos) noexcept -> basic_static_string&
    {
        using view_type = basic_string_view<value_type, traits_type>;
        auto sv         = view_type(str).substr(index_str, count);
        insert_impl(begin() + index, sv.data(), sv.size());
        return *this;
    }

    // /**
    //  * @brief Inserts character ch before the character pointed by pos.
    //  */
    // constexpr auto insert(const_iterator pos, value_type const ch) noexcept -> iterator
    // {
    // }

    // /**
    //  * @brief Inserts count copies of character ch before the element (if any) pointed
    //  by
    //  * pos.
    //  */
    // constexpr auto insert(const_iterator pos, size_type count,
    //                       value_type const ch) noexcept -> iterator
    // {
    // }

    // /**
    //  * @brief Inserts characters from the range [first, last) before the element (if
    //  any)
    //  * pointed by pos.
    //  */
    // template <typename InputIter, TAETL_REQUIRES_(detail::InputIterator<T>)>
    // constexpr auto insert(const_iterator pos, InputIter first, InputIter last) noexcept
    //     -> iterator
    // {
    // }

    /**
     * @brief Implicitly converts t to a string view sv, then inserts the elements from sv
     * before the element (if any) pointed by pos.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    constexpr auto insert(size_type const pos, T const& t) noexcept
        -> basic_static_string&
    {
        basic_string_view<value_type, traits_type> sv = t;
        insert_impl(begin() + pos, sv.data(), sv.size());
        return *this;
    }

    /**
     * @brief Implicitly converts t to a string view sv, then inserts, before the element
     * (if any) pointed by pos, the characters from the subview [index_str,
     * index_str+count) of sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    constexpr auto insert(size_type const index, T const& t, size_type const index_str,
                          size_type const count = npos) noexcept -> basic_static_string&
    {
        basic_string_view<value_type, traits_type> sv = t;

        auto sub = sv.substr(index_str, count);
        insert_impl(begin() + index, sub.data(), sub.size());
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
     * @brief Compares a [pos, pos+count) substring of this string to str. If count >
     * size() - pos the substring is [pos, size()).
     */
    [[nodiscard]] constexpr auto compare(size_type const pos, size_type const count,
                                         basic_static_string const& str) const -> int
    {
        auto const sz  = count > size() - pos ? size() : count;
        auto const sub = string_view(*this).substr(pos, sz);
        return sub.compare(str);
    }

    /**
     * @brief Compares a [pos1, pos1+count1) substring of this string to a substring
     * [pos2, pos2+count2) of str. If count1 > size() - pos1 the first substring is [pos1,
     * size()). Likewise, count2 > str.size() - pos2 the second substring is [pos2,
     * str.size()).
     */
    [[nodiscard]] constexpr auto compare(size_type const pos1, size_type const count1,
                                         basic_static_string const& str,
                                         size_type const pos2,
                                         size_type const count2 = npos) const -> int
    {
        auto const sz1  = count1 > size() - pos1 ? size() : count1;
        auto const sub1 = string_view(*this).substr(pos1, sz1);

        auto const sz2  = count2 > str.size() - pos2 ? size() : count2;
        auto const sub2 = string_view(str).substr(pos2, sz2);

        return sub1.compare(sub2);
    }

    /**
     * @brief Compares this string to the null-terminated character sequence beginning at
     * the character pointed to by s with length traits_type::length(s).
     */
    [[nodiscard]] constexpr auto compare(const_pointer s) const -> int
    {
        return compare_impl(data(), size(), s, traits_type::length(s));
    }

    /**
     * @brief Compares a [pos1, pos1+count1) substring of this string to the
     * null-terminated character sequence beginning at the character pointed to by s with
     * length traits_type::length(s). If count1 > size() - pos1 the substring is [pos1,
     * size()).
     */
    [[nodiscard]] constexpr auto compare(size_type const pos, size_type const count,
                                         const_pointer s) const -> int
    {
        auto const sz  = count > size() - pos ? size() : count;
        auto const sub = string_view(*this).substr(pos, sz);
        return compare_impl(sub.data(), sub.size(), s, traits_type::length(s));
    }

    /**
     * @brief  Compares a [pos1, pos1+count1) substring of this string to the characters
     * in the range [s, s + count2). If count1 > size() - pos1 the substring is [pos1,
     * size()). (Note: the characters in the range [s, s + count2) may include null
     * characters.)
     */
    [[nodiscard]] constexpr auto compare(size_type const pos1, size_type const count1,
                                         const_pointer s, size_type const count2) const
        -> int
    {
        auto const sz  = count1 > size() - pos1 ? size() : count1;
        auto const sub = string_view(*this).substr(pos1, sz);
        return compare_impl(sub.data(), sub.size(), s, count2);
    }

    /**
     * @brief Implicitly converts \p t to a string view sv, then compares the content of
     * this string to sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    [[nodiscard]] constexpr auto compare(T const& t) const noexcept -> int
    {
        using view_type    = etl::basic_string_view<value_type, traits_type>;
        view_type const sv = t;
        return view_type(*this).compare(sv);
    }

    /**
     * @brief Implicitly converts \p t to a string view sv, then compares a [pos1,
     * pos1+count1) substring of this string to sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    [[nodiscard]] constexpr auto compare(size_type pos1, size_type count1,
                                         T const& t) const noexcept -> int
    {
        using view_type    = etl::basic_string_view<value_type, traits_type>;
        view_type const sv = t;
        return view_type(*this).substr(pos1, count1).compare(sv);
    }

    /**
     * @brief Implicitly converts \p t to a string view sv, then compares a [pos1,
     * pos1+count1) substring of this string to a substring [pos2, pos2+count2) of sv.
     */
    template <typename T, TAETL_REQUIRES_(string_view_and_not_char_pointer<T>)>
    [[nodiscard]] constexpr auto compare(size_type pos1, size_type count1, T const& t,
                                         size_type pos2,
                                         size_type count2 = npos) const noexcept -> int
    {
        using view_type    = etl::basic_string_view<value_type, traits_type>;
        view_type const sv = t;
        return view_type(*this).substr(pos1, count1).compare(sv.substr(pos2, count2));
    }

    /**
     * @brief Checks if the string begins with the given prefix.
     */
    [[nodiscard]] constexpr auto
    starts_with(etl::basic_string_view<value_type, traits_type> sv) const noexcept -> bool
    {
        return etl::basic_string_view<value_type, traits_type>(data(), size())
            .starts_with(sv);
    }

    /**
     * @brief Checks if the string begins with the given prefix.
     */
    [[nodiscard]] constexpr auto starts_with(value_type c) const noexcept -> bool
    {
        return etl::basic_string_view<value_type, traits_type>(data(), size())
            .starts_with(c);
    }

    /**
     * @brief Checks if the string begins with the given prefix.
     */
    [[nodiscard]] constexpr auto starts_with(const_pointer str) const -> bool
    {
        return etl::basic_string_view<value_type, traits_type>(data(), size())
            .starts_with(str);
    }

    /**
     * @brief Checks if the string ends with the given prefix.
     */
    [[nodiscard]] constexpr auto
    ends_with(etl::basic_string_view<value_type, traits_type> sv) const noexcept -> bool
    {
        return etl::basic_string_view<value_type, traits_type>(data(), size())
            .ends_with(sv);
    }

    /**
     * @brief Checks if the string ends with the given prefix.
     */
    [[nodiscard]] constexpr auto ends_with(value_type c) const noexcept -> bool
    {
        return etl::basic_string_view<value_type, traits_type>(data(), size())
            .ends_with(c);
    }

    /**
     * @brief Checks if the string ends with the given prefix.
     */
    [[nodiscard]] constexpr auto ends_with(const_pointer str) const -> bool
    {
        return etl::basic_string_view<value_type, traits_type>(data(), size())
            .ends_with(str);
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
        auto const* first = data() + pos;
        auto const* last  = first + etl::min(count, size() - pos);
        auto const* dest  = destination;
        auto const* res   = etl::copy(first, last, destination);
        return static_cast<size_type>(res - dest);
    }

    /**
     * @brief Resizes the string to contain count characters.
     *
     * @details If the current size is less than count, additional characters are
     * appended, maximum up to it's capacity. If the current size is greater than count,
     * the string is reduced to its first count elements.
     */
    constexpr auto resize(size_type count, value_type ch) noexcept -> void
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
    constexpr auto resize(size_type count) noexcept -> void
    {
        resize(count, value_type());
    }

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

        if (pos <= size() - count)
        {
            auto view = static_cast<basic_string_view<value_type>>(*this);
            return view.find(s, pos, count);
        }

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
        return find(etl::addressof(ch), pos, 1);
    }

    /**
     * @brief Finds the last substring equal to the given character sequence. Search
     * begins at pos, i.e. the found substring must not begin in a position following pos.
     * If npos or any value not smaller than size()-1 is passed as pos, whole string will
     * be searched.
     *
     * https://en.cppreference.com/w/cpp/string/basic_string/rfind
     *
     * @return Position of the first character of the found substring or npos if no such
     * substring is found. Note that this is an offset from the start of the string, not
     * the end.
     */
    [[nodiscard]] constexpr auto rfind(basic_static_string const& str,
                                       size_type pos = 0) const noexcept -> size_type
    {
        return rfind(str.c_str(), pos, str.size());
    }

    /**
     * @brief Finds the last substring equal to the given character sequence. Search
     * begins at pos, i.e. the found substring must not begin in a position following pos.
     * If npos or any value not smaller than size()-1 is passed as pos, whole string will
     * be searched.
     *
     * https://en.cppreference.com/w/cpp/string/basic_string/rfind
     *
     * @return Position of the first character of the found substring or npos if no such
     * substring is found. Note that this is an offset from the start of the string, not
     * the end.
     *
     * @todo Fix. See tests.
     */
    [[nodiscard]] constexpr auto rfind(const_pointer s, size_type pos,
                                       size_type count) const noexcept -> size_type
    {
        if (count == 0)
        {
            if (pos <= size()) { return pos; }
            return size();
        }

        auto view = static_cast<basic_string_view<value_type>>(*this);
        return view.rfind(s, pos, count);
    }

    /**
     * @brief Finds the last substring equal to the given character sequence. Search
     * begins at pos, i.e. the found substring must not begin in a position following pos.
     * If npos or any value not smaller than size()-1 is passed as pos, whole string will
     * be searched.
     *
     * https://en.cppreference.com/w/cpp/string/basic_string/rfind
     *
     * @return Position of the first character of the found substring or npos if no such
     * substring is found. Note that this is an offset from the start of the string, not
     * the end.
     */
    [[nodiscard]] constexpr auto rfind(const_pointer s, size_type pos = 0) const noexcept
        -> size_type
    {
        return rfind(s, pos, traits_type::length(s));
    }

    /**
     * @brief Finds the last substring equal to the given character sequence. Search
     * begins at pos, i.e. the found substring must not begin in a position following pos.
     * If npos or any value not smaller than size()-1 is passed as pos, whole string will
     * be searched.
     *
     * https://en.cppreference.com/w/cpp/string/basic_string/rfind
     *
     * @return Position of the first character of the found substring or npos if no such
     * substring is found. Note that this is an offset from the start of the string, not
     * the end.
     */
    [[nodiscard]] constexpr auto rfind(value_type ch, size_type pos = 0) const noexcept
        -> size_type
    {
        return rfind(etl::addressof(ch), pos, 1);
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
            auto view = static_cast<basic_string_view<value_type>>(*this);
            return view.find_first_of(s, pos, count);
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
        return find_first_of(etl::addressof(ch), pos, 1);
    }

    /**
     * @brief This is a special value equal to the maximum value representable by the type
     * size_type. The exact meaning depends on context, but it is generally used either as
     * end of string indicator by the functions that expect a string index or as the error
     * indicator by the functions that return a string index.
     */
    constexpr static size_type npos = static_cast<size_type>(-1);

private:
    constexpr auto insert_impl(iterator pos, const_pointer text, size_type count) -> void
    {
        // Insert text at end.
        auto current_end = end();
        append(text, count);

        // Rotate to correct position
        etl::rotate(pos, current_end, end());
    }

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

    auto clear_storage() noexcept -> void { etl::memset(begin(), 0, Capacity); }

    size_type size_            = 0;
    value_type data_[Capacity] = {};
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
 * @brief Specializes the etl::swap algorithm for etl::basic_static_string. Swaps the
 * contents of lhs and rhs. Equivalent to lhs.swap(rhs).
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