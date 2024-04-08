// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_STRING_BASIC_STATIC_STRING_HPP
#define TETL_STRING_BASIC_STATIC_STRING_HPP

#include <etl/_algorithm/copy.hpp>
#include <etl/_algorithm/fill.hpp>
#include <etl/_algorithm/max.hpp>
#include <etl/_algorithm/remove.hpp>
#include <etl/_algorithm/rotate.hpp>
#include <etl/_array/array.hpp>
#include <etl/_cstring/memset.hpp>
#include <etl/_iterator/begin.hpp>
#include <etl/_iterator/data.hpp>
#include <etl/_iterator/distance.hpp>
#include <etl/_iterator/end.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_iterator/prev.hpp>
#include <etl/_iterator/rbegin.hpp>
#include <etl/_iterator/rend.hpp>
#include <etl/_iterator/size.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_string/char_traits.hpp>
#include <etl/_string/str_find_first_not_of.hpp>
#include <etl/_string/str_replace.hpp>
#include <etl/_string/str_rfind.hpp>
#include <etl/_string_view/string_view.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/smallest_size_t.hpp>
#include <etl/_utility/ignore_unused.hpp>

namespace etl {

/// \brief basic_inplace_string class with fixed size capacity.
/// \tparam CharT Build in type for character size (mostly 'char')
/// \tparam Capacity Capacity for basic_inplace_string
/// \headerfile etl/string.hpp
///
/// \include string.cpp
template <typename CharT, etl::size_t Capacity, typename Traits = etl::char_traits<CharT>>
struct basic_inplace_string {
    // clang-format off
    template <typename T>
    constexpr static bool view_and_not_char_ptr =
                              is_convertible_v<T const&, basic_string_view<CharT, Traits>>
                          && !is_convertible_v<T const&, CharT const*>;
    // clang-format on

    using internal_size_t = etl::smallest_size_t<Capacity>;

public:
    /// The character type used
    using value_type = CharT;
    /// The size type used
    using size_type = etl::size_t;
    /// The size type used
    using difference_type = etl::ptrdiff_t;
    /// The character traits type used
    using traits_type = Traits;
    /// Pointer to the character type
    using pointer = CharT*;
    /// Const pointer to the character type
    using const_pointer = CharT const*;
    /// Reference to the character type
    using reference = CharT&;
    /// Const reference to the character type
    using const_reference = CharT const&;
    /// Iterator to the character type
    using iterator = CharT*;
    /// Const iterator to the character type
    using const_iterator = CharT const*;
    /// The reverse iterator type used
    using reverse_iterator = etl::reverse_iterator<iterator>;
    /// The const reverse iterator type used
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

    /// Default constructor.
    constexpr basic_inplace_string() = default;

    /// \brief Character pointer constructor.
    ///
    /// \details Fails silently if input len is greater then capacity.
    constexpr basic_inplace_string(const_pointer str, size_type const len) noexcept
    {
        // TETL_ASSERT(len <= Capacity);
        if (str != nullptr && len <= Capacity) {
            unsafe_set_size(len);
            traits_type::copy(_storage.data(), str, len);
        }
    }

    /// \brief Character pointer constructor. Calls traits_type::length.
    ///
    /// \details Fails silently if input length is greater then capacity.
    constexpr basic_inplace_string(const_pointer str) noexcept
        : basic_inplace_string(str, traits_type::length(str))
    {
    }

    constexpr basic_inplace_string(nullptr_t /*null*/) = delete;

    /// Constructs the string with count copies of character ch.
    ///
    /// \details Fails silently if input length is greater then capacity.
    constexpr basic_inplace_string(size_type count, value_type ch) noexcept
    {
        // TETL_ASSERT(count <= Capacity);
        if (count <= Capacity) {
            fill(begin(), begin() + count, ch);
            unsafe_set_size(count);
        }
    }

    /// Constructs the string with the contents of the range [ first,
    /// last). Fails silently if input length is greater then capacity.
    template <typename InputIt>
        requires(detail::InputIterator<InputIt>)
    constexpr basic_inplace_string(InputIt first, InputIt last) noexcept
        : basic_inplace_string(first, static_cast<size_type>(distance(first, last)))
    {
    }

    /// Constructs the string with a substring [pos, pos+count) of other.
    constexpr basic_inplace_string(basic_inplace_string const& other, size_type pos, size_type count)
        : basic_inplace_string{other.substr(pos, count)}
    {
    }

    /// Constructs the string with a substring [pos, other.size()).
    constexpr basic_inplace_string(basic_inplace_string const& other, size_type pos)
        : basic_inplace_string{other.substr(pos, other.size())}
    {
    }

    /// Implicitly converts t to a string view sv, then initializes the
    /// string with the contents of sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    explicit constexpr basic_inplace_string(T const& t) noexcept

    {
        basic_string_view<value_type, traits_type> const sv = t;
        assign(sv.begin(), sv.end());
    }

    /// Implicitly converts t to a string view sv, then initializes the
    /// string with the subrange [ pos, pos + n ) of sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    explicit constexpr basic_inplace_string(T const& t, size_type pos, size_type n)
        : basic_inplace_string{basic_string_view<value_type, traits_type>{t}.substr(pos, n)}
    {
    }

    /// Defaulted copy constructor.
    constexpr basic_inplace_string(basic_inplace_string const& /*str*/) noexcept = default;

    /// Defaulted move constructor.
    constexpr basic_inplace_string(basic_inplace_string&& /*str*/) noexcept = default;

    /// Defaulted copy assignment.
    constexpr auto operator=(basic_inplace_string const& /*str*/) noexcept -> basic_inplace_string& = default;

    /// Defaulted move assignment.
    constexpr auto operator=(basic_inplace_string&& /*str*/) noexcept -> basic_inplace_string& = default;

    /// Replaces the contents with those of null-terminated character
    /// string pointed to by s.
    constexpr auto operator=(const_pointer s) noexcept -> basic_inplace_string&
    {
        assign(s, traits_type::length(s));
        return *this;
    }

    constexpr auto operator=(nullptr_t /*0*/) -> basic_inplace_string& = delete;

    /// Replaces the contents with character ch.
    constexpr auto operator=(value_type ch) noexcept -> basic_inplace_string&
    {
        assign(&ch, 1);
        return *this;
    }

    /// Implicitly converts t to a string view sv, then replaces the
    /// contents with those of the sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    constexpr auto operator=(T const& t) noexcept -> basic_inplace_string&
    {
        assign(t);
        return *this;
    }

    /// Replaces the contents with count copies of character ch.
    constexpr auto assign(size_type count, value_type ch) noexcept -> basic_inplace_string&
    {
        (*this) = basic_inplace_string{count, ch};
        return *this;
    }

    /// Replaces the contents with a copy of str.
    constexpr auto assign(basic_inplace_string const& str) noexcept -> basic_inplace_string&
    {
        *this = str;
        return *this;
    }

    /// Replaces the contents with a substring [ pos, pos + count )
    /// of str.
    constexpr auto
    assign(basic_inplace_string const& str, size_type pos, size_type count = npos) noexcept -> basic_inplace_string&
    {
        *this = str.substr(pos, count);
        return *this;
    }

    /// Replaces the contents with those of str using move semantics.
    constexpr auto assign(basic_inplace_string&& str) noexcept -> basic_inplace_string&
    {
        *this = etl::move(str);
        return *this;
    }

    /// Replaces the contents with copies of the characters in the range
    /// [ s, s + count ). This range can contain null characters.
    constexpr auto assign(const_pointer s, size_type count) noexcept -> basic_inplace_string&
    {
        *this = basic_inplace_string{s, count};
        return *this;
    }

    /// \brief Replaces the contents with those of null-terminated character
    /// string pointed to by s.
    constexpr auto assign(const_pointer s) noexcept -> basic_inplace_string&
    {
        *this = basic_inplace_string{s, traits_type::length(s)};
        return *this;
    }

    /// \brief Replaces the contents with copies of the characters in the
    /// range [ first , last ).
    template <typename InputIt>
        requires(detail::InputIterator<InputIt>)
    constexpr auto assign(InputIt first, InputIt last) noexcept -> basic_inplace_string&
    {
        *this = basic_inplace_string{first, last};
        return *this;
    }

    /// \brief Implicitly converts t to a string view sv, then replaces the
    /// contents with the characters from sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    constexpr auto assign(T const& t) noexcept -> basic_inplace_string&
    {
        auto tmp = basic_inplace_string{basic_inplace_string{t}};
        *this    = tmp;
        return *this;
    }

    /// \brief Implicitly converts t to a string view sv, then replaces the
    /// contents with the characters from the subview [ pos, pos + count ) of
    /// sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    constexpr auto assign(T const& t, size_type pos, size_type count = npos) noexcept -> basic_inplace_string&
    {
        auto tmp = basic_inplace_string{
            basic_inplace_string{t, pos, count}
        };
        *this = tmp;
        return *this;
    }

    /// \brief Accesses the specified character without bounds checking.
    constexpr auto operator[](size_type index) noexcept -> reference { return unsafe_at(index); }

    /// \brief Accesses the specified character without bounds checking.
    constexpr auto operator[](size_type index) const noexcept -> const_reference { return unsafe_at(index); }

    /// \brief Returns an iterator to the beginning.
    constexpr auto begin() noexcept -> iterator { return data(); }

    /// \brief Returns an const iterator to the beginning.
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator { return data(); }

    /// \brief Returns an const iterator to the beginning.
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator { return begin(); }

    /// \brief Returns an iterator to the end.
    constexpr auto end() noexcept -> iterator { return etl::next(begin(), static_cast<ptrdiff_t>(size())); }

    /// \brief Returns an const iterator to the end.
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return etl::next(begin(), static_cast<ptrdiff_t>(size()));
    }

    /// \brief Returns an const iterator to the end.
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator { return end(); }

    /// \brief Returns a reverse iterator to the first character of the reversed
    /// string. It corresponds to the last character of the non-reversed string.
    [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator { return reverse_iterator(end()); }

    /// \brief Returns a reverse iterator to the first character of the reversed
    /// string. It corresponds to the last character of the non-reversed string.
    [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(end());
    }

    /// \brief Returns a reverse iterator to the first character of the reversed
    /// string. It corresponds to the last character of the non-reversed string.
    [[nodiscard]] constexpr auto crbegin() const noexcept -> const_reverse_iterator { return rbegin(); }

    /// \brief Returns a reverse iterator to the first character of the reversed
    /// string. It corresponds to the last character of the non-reversed string.
    [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator { return reverse_iterator(begin()); }

    /// \brief Returns a reverse iterator to the first character of the reversed
    /// string. It corresponds to the last character of the non-reversed string.
    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(begin());
    }

    /// \brief Returns a reverse iterator to the first character of the reversed
    /// string. It corresponds to the last character of the non-reversed string.
    [[nodiscard]] constexpr auto crend() const noexcept -> const_reverse_iterator { return rend(); }

    /// \brief Accesses the first character.
    [[nodiscard]] constexpr auto front() noexcept -> reference { return *begin(); }

    /// \brief Accesses the first character.
    [[nodiscard]] constexpr auto front() const noexcept -> const_reference { return *begin(); }

    /// \brief Accesses the last character.
    [[nodiscard]] constexpr auto back() noexcept -> reference { return *etl::prev(end()); }

    /// \brief Accesses the last character.
    [[nodiscard]] constexpr auto back() const noexcept -> const_reference { return *etl::prev(end()); }

    /// \brief Checks whether the string is empty.
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size() == 0; }

    /// \brief Checks whether the string is full. i.e. size() == capacity()
    [[nodiscard]] constexpr auto full() const noexcept -> bool { return size() == capacity(); }

    /// \brief Returns the number of characters.
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return _storage.get_size(); }

    /// \brief Returns the number of characters.
    [[nodiscard]] constexpr auto length() const noexcept -> size_type { return size(); }

    /// \brief Returns the number of characters that can be held in allocated
    /// storage, NOT including the null terminator.
    [[nodiscard]] constexpr auto capacity() const noexcept -> size_type { return Capacity; }

    /// \brief Returns the number of characters that can be held in allocated
    /// storage, NOT including the null terminator.
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type { return Capacity; }

    /// \brief Reserve is a nop, since the capacity is fixed.
    static constexpr auto reserve(size_type /*newCap*/) -> void { }

    /// \brief Shrink to fit is a nop, since the capacity is fixed.
    static constexpr auto shrink_to_fit() -> void { }

    /// \brief Returns a pointer to the underlying array serving as character
    /// storage. The pointer is such that the range [data(); data() + size()) is
    /// valid and the values in it correspond to the values stored in the
    /// string.
    ///
    /// \details Always null-terminated.
    [[nodiscard]] constexpr auto data() noexcept -> pointer { return _storage.data(); }

    /// \brief Returns a pointer to the underlying array serving as character
    /// storage. The pointer is such that the range [data(); data() + size()) is
    /// valid and the values in it correspond to the values stored in the
    /// string.
    ///
    /// \details Always null-terminated.
    [[nodiscard]] constexpr auto data() const noexcept -> const_pointer { return _storage.data(); }

    /// \brief Returns a pointer to a null-terminated character array.
    ///
    /// The data is equivalent to those stored in the string. The pointer is
    /// such that the range [c_str(); c_str() + size()] is valid and the values
    /// in it correspond to the values stored in the string with an additional
    /// null character after the last position.
    [[nodiscard]] constexpr auto c_str() const noexcept -> const_pointer { return data(); }

    /// \brief Returns a etl::basic_string_view.
    [[nodiscard]] constexpr operator basic_string_view<value_type, traits_type>() const noexcept
    {
        return basic_string_view<value_type, traits_type>(data(), size());
    }

    /// \brief Removes all characters from the string. Sets size to 0 and
    /// overrides the buffer with zeros.
    constexpr auto clear() noexcept -> void
    {
        *begin() = value_type(0);
        unsafe_set_size(0);
    }

    /// \brief Removes min(count, size() - index) characters starting at index.
    ///
    /// \returns *this
    constexpr auto erase(size_type index = 0, size_type count = npos) noexcept -> basic_inplace_string&
    {
        auto safeCount = etl::min(count, size() - index);
        erase(begin() + index, begin() + index + safeCount);
        return *this;
    }

    /// \brief Removes the character at position.
    ///
    /// \returns iterator pointing to the character immediately following the
    /// character erased, or end() if no such character exists.
    constexpr auto erase(const_iterator position) noexcept -> iterator { return erase(position, position + 1); }

    /// \brief Removes the characters in the range [first, last).
    ///
    /// \returns iterator pointing to the character last pointed to before the
    /// erase, or end() if no such character exists.
    constexpr auto erase(const_iterator first, const_iterator last) noexcept -> iterator
    {
        auto const start    = static_cast<size_type>(etl::distance(cbegin(), first));
        auto const distance = static_cast<size_type>(etl::distance(first, last));
        // TETL_ASSERT(size() > distance);
        etl::rotate(begin() + start, begin() + start + distance, end());
        unsafe_set_size(size() - distance);
        return begin() + start;
    }

    /// \brief Appends the given character ch to the end of the string. Does
    /// nothing if the string is full.
    constexpr auto push_back(value_type ch) noexcept -> void
    {
        // TETL_ASSERT(size() < capacity());
        if (size() < capacity()) {
            append(1, ch);
        }
    }

    /// \brief Removes the last character from the string. Does nothing if the
    /// string is empty.
    constexpr auto pop_back() noexcept -> void
    {
        if (!empty()) {
            unsafe_set_size(size() - 1);
        }
    }

    /// \brief Appends count copies of character s.
    constexpr auto append(size_type const count, value_type const s) noexcept -> basic_inplace_string&
    {
        auto const safeCount = etl::min(count, capacity() - size());
        auto const newSize   = size() + safeCount;
        etl::fill(end(), etl::next(begin(), static_cast<ptrdiff_t>(newSize)), s);
        unsafe_set_size(newSize);
        return *this;
    }

    /// \brief Appends the null-terminated character string pointed to by s. The
    /// length of the string is determined by the first null character using
    constexpr auto append(const_pointer s) noexcept -> basic_inplace_string&
    {
        auto const len = traits_type::length(s);
        return append(s, len);
    }

    /// \brief Appends characters in the range [ str, str + count ). This range can
    /// contain null characters.
    constexpr auto append(const_pointer str, size_type count) noexcept -> basic_inplace_string&
    {
        auto const safeCount = etl::min(count, capacity() - size());
        etl::copy(str, etl::next(str, static_cast<ptrdiff_t>(safeCount)), end());
        unsafe_set_size(size() + safeCount);
        return *this;
    }

    /// \brief Appends characters in the range [ first , last ).
    template <typename InputIt>
        requires(detail::InputIterator<InputIt>)
    constexpr auto append(InputIt first, InputIt last) noexcept -> basic_inplace_string&
    {
        for (; first != last; ++first) {
            push_back(*first);
        }
        return *this;
    }

    /// \brief Appends string str.
    constexpr auto append(basic_inplace_string const& str) noexcept -> basic_inplace_string&
    {
        return append(str.begin(), str.end());
    }

    /// \brief Appends a substring [ pos, pos + count ) of str.
    constexpr auto
    append(basic_inplace_string const& str, size_type pos, size_type count = npos) noexcept -> basic_inplace_string&
    {
        return append(str.substr(pos, count));
    }

    /// \brief Implicitly converts t to a string_view sv, then appends all
    /// characters from sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    constexpr auto append(T const& t) -> basic_inplace_string&
    {
        etl::basic_string_view<value_type, traits_type> sv = t;
        return append(sv.data(), sv.size());
    }

    /// \brief Implicitly converts t to a string_view sv then appends the
    /// characters from the subview [ pos, pos + count ) of sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    constexpr auto append(T const& t, size_type pos, size_type count = npos) -> basic_inplace_string&
    {
        etl::basic_string_view<value_type, traits_type> sv = t;
        return append(sv.substr(pos, count));
    }

    /// \brief Appends string str.
    constexpr auto operator+=(basic_inplace_string const& str) noexcept -> basic_inplace_string& { return append(str); }

    /// \brief Appends character ch.
    constexpr auto operator+=(value_type ch) noexcept -> basic_inplace_string& { return append(1, ch); }

    /// \brief Appends the null-terminated character string pointed to by s.
    constexpr auto operator+=(const_pointer s) noexcept -> basic_inplace_string& { return append(s); }

    /// \brief Implicitly converts t to a string view sv, then appends
    /// characters in the string view sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    constexpr auto operator+=(T const& t) noexcept -> basic_inplace_string&
    {
        return append(t);
    }

    /// \brief Inserts count copies of character ch at the position index.
    constexpr auto
    insert(size_type const index, size_type const count, value_type const ch) noexcept -> basic_inplace_string&
    {
        for (size_type i = 0; i < count; ++i) {
            insert_impl(begin() + index, &ch, 1);
        }
        return *this;
    }

    /// \brief Inserts null-terminated character string pointed to by s at the
    /// position index.
    constexpr auto insert(size_type const index, const_pointer s) noexcept -> basic_inplace_string&
    {
        insert_impl(begin() + index, s, traits_type::length(s));
        return *this;
    }

    /// \brief Inserts the characters in the range [s, s+count) at the position
    /// index. The range can contain null characters.
    constexpr auto
    insert(size_type const index, const_pointer s, size_type const count) noexcept -> basic_inplace_string&
    {
        insert_impl(begin() + index, s, count);
        return *this;
    }

    /// \brief Inserts string str at the position index.
    constexpr auto insert(size_type const index, basic_inplace_string const& str) noexcept -> basic_inplace_string&
    {
        insert_impl(begin() + index, str.data(), str.size());
        return *this;
    }

    /// \brief Inserts a string, obtained by str.substr(index_str, count) at the
    /// position index.
    constexpr auto insert(
        size_type const index,
        basic_inplace_string const& str,
        size_type const indexStr,
        size_type const count = npos
    ) noexcept -> basic_inplace_string&
    {
        using view_type = basic_string_view<value_type, traits_type>;
        auto sv         = view_type(str).substr(indexStr, count);
        insert_impl(begin() + index, sv.data(), sv.size());
        return *this;
    }

    //
    //  * \brief Inserts character ch before the character pointed by pos.
    // constexpr auto insert(const_iterator pos, value_type const ch) noexcept
    // -> iterator
    // {
    // }

    //
    //  * \brief Inserts count copies of character ch before the element (if
    //  any) pointed by
    //  * pos.
    // constexpr auto insert(const_iterator pos, size_type count,
    //                       value_type const ch) noexcept -> iterator
    // {
    // }

    //
    //  * \brief Inserts characters from the range [first, last) before the
    //  element (if any)
    //  * pointed by pos.
    // template <typename InputIter>
    // requires(detail::InputIterator<T>)
    // constexpr auto insert(const_iterator pos, InputIter first, InputIter
    // last) noexcept
    //     -> iterator
    // {
    // }

    /// \brief Implicitly converts t to a string view sv, then inserts the
    /// elements from sv before the element (if any) pointed by pos.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    constexpr auto insert(size_type const pos, T const& t) noexcept -> basic_inplace_string&
    {
        basic_string_view<value_type, traits_type> sv = t;
        insert_impl(begin() + pos, sv.data(), sv.size());
        return *this;
    }

    /// \brief Implicitly converts t to a string view sv, then inserts, before
    /// the element (if any) pointed by pos, the characters from the subview
    /// [index_str, index_str+count) of sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    constexpr auto insert(size_type const index, T const& t, size_type const indexStr, size_type const count = npos)
        noexcept -> basic_inplace_string&
    {
        basic_string_view<value_type, traits_type> sv = t;

        auto sub = sv.substr(indexStr, count);
        insert_impl(begin() + index, sub.data(), sub.size());
        return *this;
    }

    /// \brief Compares this string to str.
    [[nodiscard]] constexpr auto compare(basic_inplace_string const& str) const noexcept -> int
    {
        return compare_impl(data(), size(), str.data(), str.size());
    }

    /// \brief Compares this string to str with other capacity.
    template <size_type OtherCapacity>
    [[nodiscard]] constexpr auto compare(basic_inplace_string<value_type, OtherCapacity, traits_type> const& str
    ) const noexcept -> int
    {
        return compare_impl(data(), size(), str.data(), str.size());
    }

    /// \brief Compares a [pos, pos+count) substring of this string to str. If
    /// count > size() - pos the substring is [pos, size()).
    [[nodiscard]] constexpr auto
    compare(size_type const pos, size_type const count, basic_inplace_string const& str) const -> int
    {
        auto const sz  = count > size() - pos ? size() : count;
        auto const sub = string_view(*this).substr(pos, sz);
        return sub.compare(str);
    }

    /// \brief Compares a [pos1, pos1+count1) substring of this string to a
    /// substring [pos2, pos2+count2) of str. If count1 > size() - pos1 the
    /// first substring is [pos1, size()). Likewise, count2 > str.size() - pos2
    /// the second substring is [pos2, str.size()).
    [[nodiscard]] constexpr auto compare(
        size_type const pos1,
        size_type const count1,
        basic_inplace_string const& str,
        size_type const pos2,
        size_type const count2 = npos
    ) const -> int
    {
        auto const sz1  = count1 > size() - pos1 ? size() : count1;
        auto const sub1 = string_view(*this).substr(pos1, sz1);

        auto const sz2  = count2 > str.size() - pos2 ? size() : count2;
        auto const sub2 = string_view(str).substr(pos2, sz2);

        return sub1.compare(sub2);
    }

    /// \brief Compares this string to the null-terminated character sequence
    /// beginning at the character pointed to by s with length
    /// traits_type::length(s).
    [[nodiscard]] constexpr auto compare(const_pointer s) const -> int
    {
        return compare_impl(data(), size(), s, traits_type::length(s));
    }

    /// \brief Compares a [pos1, pos1+count1) substring of this string to the
    /// null-terminated character sequence beginning at the character pointed to
    /// by s with length traits_type::length(s). If count1 > size() - pos1 the
    /// substring is [pos1, size()).
    [[nodiscard]] constexpr auto compare(size_type const pos, size_type const count, const_pointer s) const -> int
    {
        auto const sz  = count > size() - pos ? size() : count;
        auto const sub = string_view(*this).substr(pos, sz);
        return compare_impl(sub.data(), sub.size(), s, traits_type::length(s));
    }

    /// \brief  Compares a [pos1, pos1+count1) substring of this string to the
    /// characters in the range [s, s + count2). If count1 > size() - pos1 the
    /// substring is [pos1, size()). (Note: the characters in the range [s, s +
    /// count2) may include null characters.)
    [[nodiscard]] constexpr auto
    compare(size_type const pos1, size_type const count1, const_pointer s, size_type const count2) const -> int
    {
        auto const sz  = count1 > size() - pos1 ? size() : count1;
        auto const sub = string_view(*this).substr(pos1, sz);
        return compare_impl(sub.data(), sub.size(), s, count2);
    }

    /// \brief Implicitly converts t to a string view sv, then compares the
    /// content of this string to sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    [[nodiscard]] constexpr auto compare(T const& t) const noexcept -> int
    {
        using view_type    = basic_string_view<CharT, Traits>;
        view_type const sv = t;
        return view_type(*this).compare(sv);
    }

    /// \brief Implicitly converts t to a string view sv, then compares a [pos1,
    /// pos1+count1) substring of this string to sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    [[nodiscard]] constexpr auto compare(size_type pos1, size_type count1, T const& t) const noexcept -> int
    {
        using view_type    = basic_string_view<CharT, Traits>;
        view_type const sv = t;
        return view_type(*this).substr(pos1, count1).compare(sv);
    }

    /// \brief Implicitly converts t to a string view sv, then compares a [pos1,
    /// pos1+count1) substring of this string to a substring [pos2, pos2+count2)
    /// of sv.
    template <typename T>
        requires(view_and_not_char_ptr<T>)
    [[nodiscard]] constexpr auto
    compare(size_type pos1, size_type count1, T const& t, size_type pos2, size_type count2 = npos) const noexcept -> int
    {
        using view_type    = basic_string_view<CharT, Traits>;
        view_type const sv = t;
        return view_type(*this).substr(pos1, count1).compare(sv.substr(pos2, count2));
    }

    /// \brief Checks if the string begins with the given prefix.
    [[nodiscard]] constexpr auto starts_with(basic_string_view<CharT, Traits> sv) const noexcept -> bool
    {
        return basic_string_view<CharT, Traits>(data(), size()).starts_with(sv);
    }

    /// \brief Checks if the string begins with the given prefix.
    [[nodiscard]] constexpr auto starts_with(value_type c) const noexcept -> bool
    {
        return basic_string_view<CharT, Traits>(data(), size()).starts_with(c);
    }

    /// \brief Checks if the string begins with the given prefix.
    [[nodiscard]] constexpr auto starts_with(const_pointer s) const -> bool
    {
        return basic_string_view<CharT, Traits>(data(), size()).starts_with(s);
    }

    /// \brief Checks if the string ends with the given prefix.
    [[nodiscard]] constexpr auto ends_with(basic_string_view<CharT, Traits> sv) const noexcept -> bool
    {
        return basic_string_view<CharT, Traits>(data(), size()).ends_with(sv);
    }

    /// \brief Checks if the string ends with the given prefix.
    [[nodiscard]] constexpr auto ends_with(value_type c) const noexcept -> bool
    {
        return basic_string_view<CharT, Traits>(data(), size()).ends_with(c);
    }

    /// \brief Checks if the string ends with the given prefix.
    [[nodiscard]] constexpr auto ends_with(const_pointer str) const -> bool
    {
        return basic_string_view<CharT, Traits>(data(), size()).ends_with(str);
    }

    /// \brief Replaces the part of the string indicated [pos, pos + count) with
    /// a new string.
    constexpr auto replace(size_type pos, size_type count, basic_inplace_string const& str) -> basic_inplace_string&
    {
        // TETL_ASSERT(pos < size());
        // TETL_ASSERT(pos + count < size());

        auto* f = data() + pos;
        auto* l = data() + pos + count;
        detail::str_replace(f, l, str.begin(), str.end());
        return *this;
    }

    /// \brief Replaces the part of the string indicated [first, last) with a
    /// new string.
    constexpr auto
    replace(const_iterator first, const_iterator last, basic_inplace_string const& str) -> basic_inplace_string&
    {
        auto* f = const_cast<iterator>(first);
        auto* l = const_cast<iterator>(last);
        detail::str_replace(f, l, str.begin(), str.end());
        return *this;
    }

    constexpr auto
    replace(size_type pos, size_type count, basic_inplace_string const& str, size_type pos2, size_type count2 = npos)
        -> basic_inplace_string&
    {
        // TETL_ASSERT(pos < size());
        // TETL_ASSERT(pos + count < size());

        // TETL_ASSERT(pos2 < str.size());
        // TETL_ASSERT(pos2 + count2 < str.size());

        auto* f        = data() + min(pos, size());
        auto* l        = data() + min(pos + count, size());
        auto const* sf = next(begin(str), min(pos2, str.size()));
        auto const* sl = next(begin(str), min(pos2 + count2, str.size()));
        detail::str_replace(f, l, sf, sl);
        return *this;
    }

    constexpr auto replace(size_type pos, size_type count, CharT const* str, size_type count2) -> basic_inplace_string&
    {
        // TETL_ASSERT(pos < size());
        // TETL_ASSERT(pos + count < size());

        auto* f = next(data(), min(pos, size()));
        auto* l = next(data(), min(pos + count, size()));
        detail::str_replace(f, l, str, next(str, count2));
        return *this;
    }

    constexpr auto
    replace(const_iterator first, const_iterator last, CharT const* str, size_type count2) -> basic_inplace_string&
    {
        auto* f = const_cast<iterator>(first);
        auto* l = const_cast<iterator>(last);
        detail::str_replace(f, l, str, next(str, count2));
        return *this;
    }

    constexpr auto replace(size_type pos, size_type count, CharT const* str) -> basic_inplace_string&
    {
        // TETL_ASSERT(pos < size());
        // TETL_ASSERT(pos + count < size());

        auto* f = next(data(), min(pos, size()));
        auto* l = next(data(), min(pos + count, size()));
        detail::str_replace(f, l, str, next(str, strlen(str)));
        return *this;
    }

    constexpr auto replace(const_iterator first, const_iterator last, CharT const* str) -> basic_inplace_string&
    {
        auto* f = const_cast<iterator>(first);
        auto* l = const_cast<iterator>(last);
        detail::str_replace(f, l, str, next(str, strlen(str)));
        return *this;
    }

    // constexpr auto replace(size_type pos, size_type count, size_type count2,
    //    CharT ch) -> basic_inplace_string&
    //{
    //    TETL_ASSERT(pos < size());
    //    TETL_ASSERT(pos + count < size());
    //
    //    auto* f = next(data(), min(pos, size()));
    //    auto* l = next(data(), min(pos + count, size()));
    //    detail::str_replace(f, l, ch);
    //    return *this;
    //}

    constexpr auto
    replace(const_iterator first, const_iterator last, size_type count2, CharT ch) -> basic_inplace_string&
    {
        auto* f = const_cast<iterator>(first);
        auto* l = min(const_cast<iterator>(last), f + count2);
        detail::str_replace(f, l, ch);
        return *this;
    }

    /// \brief Returns a substring [pos, pos+count). If the requested substring
    /// extends past the end of the string, or if count == npos, the returned
    /// substring is [pos, size()).
    ///
    /// If pos is greater then size(), an empty string will be returned.
    [[nodiscard]] constexpr auto substr(size_type pos = 0, size_type count = npos) const -> basic_inplace_string
    {
        if (pos > size()) {
            return {};
        }
        return basic_inplace_string(data() + pos, etl::min(count, size() - pos));
    }

    /// \brief Copies a substring [pos, pos+count) to character string pointed
    /// to by dest. If the requested substring lasts past the end of the string,
    /// or if count == npos, the copied substring is [pos, size()). The
    /// resulting character string is not null-terminated.
    ///
    /// If pos is greater then size(), nothing will be copied.
    ///
    /// \returns Number of characters copied.
    constexpr auto copy(pointer destination, size_type count, size_type pos = 0) const -> size_type
    {
        if (pos > size()) {
            return 0;
        }
        auto const* first = data() + pos;
        auto const* last  = first + etl::min(count, size() - pos);
        auto const* dest  = destination;
        auto const* res   = etl::copy(first, last, destination);
        return static_cast<size_type>(res - dest);
    }

    /// \brief Resizes the string to contain count characters.
    ///
    /// \details If the current size is less than count, additional characters
    /// are appended, maximum up to it's capacity. If the current size is
    /// greater than count, the string is reduced to its first count elements.
    constexpr auto resize(size_type count, value_type ch) noexcept -> void
    {
        if (size() > count) {
            unsafe_set_size(count);
        }
        if (size() < count) {
            append(count, ch);
        }
    }

    /// \brief Resizes the string to contain count characters.
    ///
    /// \details If the current size is less than count, additional characters
    /// are appended, maximum up to it's capacity. If the current size is
    /// greater than count, the string is reduced to its first count elements.
    constexpr auto resize(size_type count) noexcept -> void { resize(count, value_type()); }

    /// \brief Exchanges the contents of the string with those of other. All
    /// iterators and references may be invalidated.
    constexpr auto swap(basic_inplace_string& other) noexcept -> void
    {
        auto temp(etl::move(other));
        other = etl::move(*this);
        *this = etl::move(temp);
    }

    /// \brief Finds the first substring equal to the given character sequence.
    /// Search begins at pos, i.e. the found substring must not begin in a
    /// position preceding pos.
    ///
    /// https://en.cppreference.com/w/cpp/string/basic_string/find
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found.
    [[nodiscard]] constexpr auto find(basic_inplace_string const& str, size_type pos = 0) const noexcept -> size_type
    {
        return find(str.c_str(), pos, str.size());
    }

    /// \brief Finds the first substring equal to the given character sequence.
    /// Search begins at pos, i.e. the found substring must not begin in a
    /// position preceding pos.
    ///
    /// https://en.cppreference.com/w/cpp/string/basic_string/find
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found.
    [[nodiscard]] constexpr auto find(const_pointer s, size_type pos, size_type count) const noexcept -> size_type
    {
        // an empty substring is found at pos if and only if pos <= size()
        if (count == 0 && pos <= size()) {
            return pos;
        }

        if (pos <= size() - count) {
            auto view = static_cast<basic_string_view<value_type>>(*this);
            return view.find(s, pos, count);
        }

        return npos;
    }

    /// \brief Finds the first substring equal to the given character sequence.
    /// Search begins at pos, i.e. the found substring must not begin in a
    /// position preceding pos.
    ///
    /// https://en.cppreference.com/w/cpp/string/basic_string/find
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found.
    [[nodiscard]] constexpr auto find(const_pointer s, size_type pos = 0) const noexcept -> size_type
    {
        return find(s, pos, traits_type::length(s));
    }

    /// \brief Finds the first substring equal to the given character sequence.
    /// Search begins at pos, i.e. the found substring must not begin in a
    /// position preceding pos.
    ///
    /// https://en.cppreference.com/w/cpp/string/basic_string/find
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found.
    [[nodiscard]] constexpr auto find(value_type ch, size_type pos = 0) const noexcept -> size_type
    {
        return find(&ch, pos, 1);
    }

    /// \brief Finds the last substring equal to the given character sequence.
    /// Search begins at pos, i.e. the found substring must not begin in a
    /// position following pos. If npos or any value not smaller than size()-1
    /// is passed as pos, whole string will be searched.
    ///
    /// https://en.cppreference.com/w/cpp/string/basic_string/rfind
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found. Note that this is an offset from the
    /// start of the string, not the end.
    [[nodiscard]] constexpr auto rfind(basic_inplace_string const& str, size_type pos = 0) const noexcept -> size_type
    {
        return detail::str_rfind<value_type, size_type, traits_type, npos>(
            begin(),
            size(),
            str.begin(),
            pos,
            str.size()
        );
    }

    /// \brief Finds the last substring equal to the given character sequence.
    /// Search begins at pos, i.e. the found substring must not begin in a
    /// position following pos. If npos or any value not smaller than size()-1
    /// is passed as pos, whole string will be searched.
    ///
    /// https://en.cppreference.com/w/cpp/string/basic_string/rfind
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found. Note that this is an offset from the
    /// start of the string, not the end.
    ///
    /// \bug See tests.
    [[nodiscard]] constexpr auto rfind(const_pointer s, size_type pos, size_type count) const noexcept -> size_type
    {
        return detail::str_rfind<value_type, size_type, traits_type, npos>(begin(), size(), s, pos, count);
    }

    /// \brief Finds the last substring equal to the given character sequence.
    /// Search begins at pos, i.e. the found substring must not begin in a
    /// position following pos. If npos or any value not smaller than size()-1
    /// is passed as pos, whole string will be searched.
    ///
    /// https://en.cppreference.com/w/cpp/string/basic_string/rfind
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found. Note that this is an offset from the
    /// start of the string, not the end.
    [[nodiscard]] constexpr auto rfind(const_pointer s, size_type pos = 0) const noexcept -> size_type
    {
        return detail::str_rfind<value_type, size_type, traits_type, npos>(
            begin(),
            size(),
            s,
            pos,
            traits_type::length(s)
        );
    }

    /// \brief Finds the last substring equal to the given character sequence.
    /// Search begins at pos, i.e. the found substring must not begin in a
    /// position following pos. If npos or any value not smaller than size()-1
    /// is passed as pos, whole string will be searched.
    ///
    /// https://en.cppreference.com/w/cpp/string/basic_string/rfind
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found. Note that this is an offset from the
    /// start of the string, not the end.
    [[nodiscard]] constexpr auto rfind(value_type ch, size_type pos = 0) const noexcept -> size_type
    {
        return detail::str_rfind<value_type, size_type, traits_type, npos>(begin(), size(), ch, pos);
    }

    /// \brief Finds the first character equal to one of the characters in the
    /// given character sequence. The search considers only the interval [pos,
    /// size()). If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto
    find_first_of(basic_inplace_string const& str, size_type pos = 0) const noexcept -> size_type
    {
        return find_first_of(str.c_str(), pos, str.size());
    }

    /// \brief Finds the first character equal to one of the characters in the
    /// given character sequence. The search considers only the interval [pos,
    /// size()). If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto find_first_of(const_pointer s, size_type pos, size_type count) const -> size_type
    {
        if (pos < size()) {
            auto view = static_cast<basic_string_view<value_type>>(*this);
            return view.find_first_of(s, pos, count);
        }

        return npos;
    }

    /// \brief Finds the first character equal to one of the characters in the
    /// given character sequence. The search considers only the interval [pos,
    /// size()). If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto find_first_of(const_pointer s, size_type pos = 0) const -> size_type
    {
        return find_first_of(s, pos, traits_type::length(s));
    }

    /// \brief Finds the first character equal to one of the characters in the
    /// given character sequence. The search considers only the interval [pos,
    /// size()). If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto find_first_of(value_type ch, size_type pos = 0) const noexcept -> size_type
    {
        return find_first_of(&ch, pos, 1);
    }

    /// \brief Finds the first character equal to one of the characters in the
    /// given character sequence. The search considers only the interval [pos,
    /// size()). If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto
    find_first_of(basic_string_view<value_type, traits_type> str, size_type pos = 0) const noexcept -> size_type
    {
        return find_first_of(str.data(), pos, str.size());
    }

    /// \brief Finds the first character not equal to any of the characters in
    /// the given character sequence.
    ///
    /// \return Position of the first character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto
    find_first_not_of(basic_inplace_string const& str, size_type pos = 0) const noexcept -> size_type
    {
        // TETL_ASSERT(pos < size());
        return detail::str_find_first_not_of<value_type, size_type, traits_type, npos>(
            begin(),
            size(),
            str.begin(),
            pos,
            str.size()
        );
    }

    /// \brief Finds the first character not equal to any of the characters in
    /// the given character sequence.
    ///
    /// \return Position of the first character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_first_not_of(value_type ch, size_type pos = 0) const noexcept -> size_type
    {
        // TETL_ASSERT(pos < size());
        return detail::str_find_first_not_of<value_type, size_type, traits_type, npos>(begin(), size(), ch, pos);
    }

    /// \brief Finds the first character not equal to any of the characters in
    /// the given character sequence.
    ///
    /// \return Position of the first character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_first_not_of(value_type const* s, size_type pos) const -> size_type
    {
        // TETL_ASSERT(pos < size());
        return detail::str_find_first_not_of<value_type, size_type, traits_type, npos>(
            begin(),
            size(),
            s,
            pos,
            traits_type::length(s)
        );
    }

    /// \brief Finds the first character not equal to any of the characters in
    /// the given character sequence.
    ///
    /// \return Position of the first character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto
    find_first_not_of(value_type const* s, size_type pos, size_type count) const -> size_type
    {
        // TETL_ASSERT(pos < size());
        return detail::str_find_first_not_of<value_type, size_type, traits_type, npos>(begin(), size(), s, pos, count);
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. The exact search algorithm is not specified. The
    /// search considers only the interval [0, pos]. If the character is not
    /// present in the interval, npos will be returned.
    [[nodiscard]] constexpr auto
    find_last_of(basic_inplace_string const& str, size_type pos = 0) const noexcept -> size_type
    {
        auto view = basic_string_view<value_type>{*this};
        return view.find_last_of(str, pos);
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. The exact search algorithm is not specified. The
    /// search considers only the interval [0, pos]. If the character is not
    /// present in the interval, npos will be returned.
    [[nodiscard]] constexpr auto find_last_of(value_type c, size_type pos = 0) const noexcept -> size_type
    {
        auto view = basic_string_view<value_type>{*this};
        return view.find_last_of(c, pos);
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. The exact search algorithm is not specified. The
    /// search considers only the interval [0, pos]. If the character is not
    /// present in the interval, npos will be returned.
    [[nodiscard]] constexpr auto find_last_of(value_type const* s, size_type pos, size_type count) const -> size_type
    {
        auto view = basic_string_view<value_type>{*this};
        return view.find_last_of(s, pos, count);
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. The exact search algorithm is not specified. The
    /// search considers only the interval [0, pos]. If the character is not
    /// present in the interval, npos will be returned.
    [[nodiscard]] constexpr auto find_last_of(value_type const* s, size_type pos = 0) const -> size_type
    {
        auto view = basic_string_view<value_type>{*this};
        return view.find_last_of(s, pos);
    }

    /// \brief Finds the last character equal to none of the characters in the
    /// given character sequence. The search considers only the interval [0,
    /// pos]. If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto
    find_last_not_of(basic_inplace_string const& str, size_type pos = 0) const noexcept -> size_type
    {
        auto view = basic_string_view<value_type>{*this};
        return view.find_last_not_of(str, pos);
    }

    /// \brief Finds the last character equal to none of the characters in the
    /// given character sequence. The search considers only the interval [0,
    /// pos]. If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto find_last_not_of(value_type c, size_type pos = 0) const noexcept -> size_type
    {
        auto view = basic_string_view<value_type>{*this};
        return view.find_last_not_of(c, pos);
    }

    /// \brief Finds the last character equal to none of the characters in the
    /// given character sequence. The search considers only the interval [0,
    /// pos]. If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto
    find_last_not_of(value_type const* s, size_type pos, size_type count) const -> size_type
    {
        auto view = basic_string_view<value_type>{*this};
        return view.find_last_not_of(s, pos, count);
    }

    /// \brief Finds the last character equal to none of the characters in the
    /// given character sequence. The search considers only the interval [0,
    /// pos]. If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto find_last_not_of(value_type const* s, size_type pos = 0) const -> size_type
    {
        auto view = basic_string_view<value_type>{*this};
        return view.find_last_not_of(s, pos);
    }

    /// \brief Checks if the string contains the given substring.
    [[nodiscard]] constexpr auto contains(etl::basic_string_view<CharT, Traits> sv) const noexcept -> bool
    {
        auto view = basic_string_view<value_type>{*this};
        return view.find_last_not_of(sv);
    }

    /// \brief Checks if the string contains the given substring.
    [[nodiscard]] constexpr auto contains(CharT c) const noexcept -> bool
    {
        auto view = basic_string_view<value_type>{*this};
        return view.find_last_not_of(c);
    }

    /// \brief Checks if the string contains the given substring.
    [[nodiscard]] constexpr auto contains(CharT const* s) const -> bool
    {
        auto view = basic_string_view<value_type>{*this};
        return view.find_last_not_of(s);
    }

    /// \brief This is a special value equal to the maximum value representable
    /// by the type size_type. The exact meaning depends on context, but it is
    /// generally used either as end of string indicator by the functions that
    /// expect a string index or as the error indicator by the functions that
    /// return a string index.
    static constexpr size_type npos = numeric_limits<size_type>::max();

private:
    constexpr auto unsafe_set_size(size_type const newSize) noexcept -> void
    {
        // TETL_ASSERT(newSize <= Capacity);
        _storage.set_size(newSize);
        unsafe_at(newSize) = CharT(0);
    }

    [[nodiscard]] constexpr auto unsafe_at(size_type const index) noexcept -> reference
    {
        // TETL_ASSERT(index < size());
        return *next(_storage.data(), static_cast<ptrdiff_t>(index));
    }

    [[nodiscard]] constexpr auto unsafe_at(size_type const index) const noexcept -> const_reference
    {
        // TETL_ASSERT(index < size());
        return *next(_storage.data(), static_cast<ptrdiff_t>(index));
    }

    constexpr auto insert_impl(iterator pos, const_pointer text, size_type count) -> void
    {
        // Insert text at end.
        auto* currentEnd = end();
        append(text, count);

        // Rotate to correct position
        etl::rotate(pos, currentEnd, end());
    }

    [[nodiscard]] constexpr auto
    compare_impl(const_pointer lhs, size_type lhsSize, const_pointer rhs, size_type rhsSize) const noexcept -> int
    {
        auto const minSize = etl::min(lhsSize, rhsSize);
        auto const result  = traits_type::compare(lhs, rhs, minSize);
        if (result != 0) {
            return result;
        }
        if (lhsSize < rhsSize) {
            return -1;
        }
        if (lhsSize > rhsSize) {
            return 1;
        }
        return 0;
    }

    struct tiny_layout {
        constexpr tiny_layout() noexcept { _buffer[Capacity] = Capacity; }

        [[nodiscard]] constexpr auto data() noexcept { return _buffer.data(); }

        [[nodiscard]] constexpr auto data() const noexcept { return _buffer.data(); }

        [[nodiscard]] constexpr auto get_size() const noexcept { return Capacity - size_type(_buffer[Capacity]); }

        constexpr auto set_size(size_t size) noexcept { return _buffer[Capacity] = value_type(Capacity - size); }

    private:
        etl::array<value_type, Capacity + 1> _buffer{};
    };

    struct normal_layout {
        constexpr normal_layout() noexcept = default;

        [[nodiscard]] constexpr auto data() noexcept { return _buffer.data(); }

        [[nodiscard]] constexpr auto data() const noexcept { return _buffer.data(); }

        [[nodiscard]] constexpr auto get_size() const noexcept { return size_t(_size); }

        constexpr auto set_size(size_t size) noexcept { return _size = internal_size_t(size); }

    private:
        internal_size_t _size{};
        etl::array<value_type, Capacity + 1> _buffer{};
    };

    using layout_type = etl::conditional_t<(Capacity < 16), tiny_layout, normal_layout>;
    layout_type _storage{};
};

/// \brief Returns a string containing characters from lhs followed by the
/// characters from rhs.
template <typename CharT, typename Traits, size_t Capacity1, size_t Capacity2>
[[nodiscard]] constexpr auto operator+(
    basic_inplace_string<CharT, Capacity1, Traits> const& lhs,
    basic_inplace_string<CharT, Capacity2, Traits> const& rhs
) noexcept -> basic_inplace_string<CharT, Capacity1, Traits>
{
    auto str = basic_inplace_string<CharT, Capacity1, Traits>{lhs};
    str.append(rhs);
    return str;
}

/// \brief Returns a string containing characters from lhs followed by the
/// characters from rhs.
template <typename CharT, typename Traits, size_t Capacity>
[[nodiscard]] constexpr auto operator+(basic_inplace_string<CharT, Capacity, Traits> const& lhs, CharT const* rhs)
    noexcept -> basic_inplace_string<CharT, Capacity, Traits>
{
    auto str = basic_inplace_string<CharT, Capacity, Traits>{lhs};
    str.append(rhs);
    return str;
}

/// \brief Returns a string containing characters from lhs followed by the
/// characters from rhs.
template <typename CharT, typename Traits, size_t Capacity>
[[nodiscard]] constexpr auto operator+(basic_inplace_string<CharT, Capacity, Traits> const& lhs, CharT rhs) noexcept
    -> basic_inplace_string<CharT, Capacity, Traits>
{
    auto str = basic_inplace_string<CharT, Capacity, Traits>{lhs};
    str.append(1, rhs);
    return str;
}

/// \brief Returns a string containing characters from lhs followed by the
/// characters from rhs.
template <typename CharT, typename Traits, size_t Capacity>
[[nodiscard]] constexpr auto operator+(CharT const* lhs, basic_inplace_string<CharT, Capacity, Traits> const& rhs)
    noexcept -> basic_inplace_string<CharT, Capacity, Traits>
{
    auto str = basic_inplace_string<CharT, Capacity, Traits>{lhs};
    str.append(rhs);
    return str;
}

/// \brief Returns a string containing characters from lhs followed by the
/// characters from rhs.
template <typename CharT, typename Traits, size_t Capacity>
[[nodiscard]] constexpr auto operator+(CharT lhs, basic_inplace_string<CharT, Capacity, Traits> const& rhs) noexcept
    -> basic_inplace_string<CharT, Capacity, Traits>
{
    auto str = basic_inplace_string<CharT, Capacity, Traits>{1, lhs};
    str.append(rhs);
    return str;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename CharT, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator==(
    etl::basic_inplace_string<CharT, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<CharT, Capacity2, Traits> const& rhs
) noexcept -> bool
{
    return lhs.compare(rhs) == 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename CharT, typename Traits, etl::size_t Capacity>
[[nodiscard]] constexpr auto
operator==(etl::basic_inplace_string<CharT, Capacity, Traits> const& lhs, CharT const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) == 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename CharT, typename Traits, etl::size_t Capacity>
[[nodiscard]] constexpr auto
operator==(CharT const* lhs, etl::basic_inplace_string<CharT, Capacity, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) == 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename CharT, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator!=(
    etl::basic_inplace_string<CharT, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<CharT, Capacity2, Traits> const& rhs
) noexcept -> bool
{
    return lhs.compare(rhs) != 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename CharT, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator!=(etl::basic_inplace_string<CharT, Capacity1, Traits> const& lhs, CharT const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) != 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename CharT, typename Traits, etl::size_t Capacity>
[[nodiscard]] constexpr auto
operator!=(CharT const* lhs, etl::basic_inplace_string<CharT, Capacity, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) != 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator<(
    etl::basic_inplace_string<CharT, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<CharT, Capacity2, Traits> const& rhs
) noexcept
{
    return lhs.compare(rhs) < 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator<(etl::basic_inplace_string<CharT, Capacity1, Traits> const& lhs, CharT const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) < 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator<(CharT const* lhs, etl::basic_inplace_string<CharT, Capacity1, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) > 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator<=(
    etl::basic_inplace_string<CharT, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<CharT, Capacity2, Traits> const& rhs
) noexcept
{
    return lhs.compare(rhs) <= 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator<=(etl::basic_inplace_string<CharT, Capacity1, Traits> const& lhs, CharT const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) <= 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator<=(CharT const* lhs, etl::basic_inplace_string<CharT, Capacity1, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) >= 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator>(
    etl::basic_inplace_string<CharT, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<CharT, Capacity2, Traits> const& rhs
) noexcept
{
    return lhs.compare(rhs) > 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator>(etl::basic_inplace_string<CharT, Capacity1, Traits> const& lhs, CharT const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) > 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator>(CharT const* lhs, etl::basic_inplace_string<CharT, Capacity1, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) < 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator>=(
    etl::basic_inplace_string<CharT, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<CharT, Capacity2, Traits> const& rhs
) noexcept
{
    return lhs.compare(rhs) >= 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity>
[[nodiscard]] constexpr auto
operator>=(etl::basic_inplace_string<CharT, Capacity, Traits> const& lhs, CharT const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) >= 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of CharT.
///
/// \details The ordering comparisons are done lexicographically.
template <typename CharT, typename Traits, etl::size_t Capacity>
[[nodiscard]] constexpr auto
operator>=(CharT const* lhs, etl::basic_inplace_string<CharT, Capacity, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) <= 0;
}

/// \brief Specializes the etl::swap algorithm for etl::basic_inplace_string.
/// Swaps the contents of lhs and rhs. Equivalent to lhs.swap(rhs).
template <typename CharT, typename Traits, etl::size_t Capacity>
constexpr auto
swap(etl::basic_inplace_string<CharT, Capacity, Traits>& lhs, etl::basic_inplace_string<CharT, Capacity, Traits>& rhs)
    noexcept(noexcept(lhs.swap(rhs))) -> void
{
    lhs.swap(rhs);
}

/// \brief Erases all elements that compare equal to value from the container.
template <typename CharT, typename Traits, etl::size_t Capacity, typename U>
constexpr auto erase(basic_inplace_string<CharT, Capacity, Traits>& c, U const& value) noexcept ->
    typename basic_inplace_string<CharT, Capacity, Traits>::size_type
{
    using return_type = typename basic_inplace_string<CharT, Capacity, Traits>::size_type;

    auto it = etl::remove(begin(c), end(c), value);
    auto r  = etl::distance(it, end(c));
    c.erase(it, end(c));
    return static_cast<return_type>(r);
}

/// \brief Erases all elements that satisfy the predicate pred from the
/// container.
template <typename CharT, typename Traits, etl::size_t Capacity, typename Predicate>
constexpr auto erase_if(basic_inplace_string<CharT, Capacity, Traits>& c, Predicate pred) noexcept ->
    typename basic_inplace_string<CharT, Capacity, Traits>::size_type
{
    using return_type = typename basic_inplace_string<CharT, Capacity, Traits>::size_type;

    auto it = etl::remove_if(begin(c), end(c), pred);
    auto r  = etl::distance(it, end(c));
    c.erase(it, end(c));
    return static_cast<return_type>(r);
}

} // namespace etl

#endif // TETL_STRING_BASIC_STATIC_STRING_HPP
