// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_STRING_BASIC_INPLACE_STRING_HPP
#define TETL_STRING_BASIC_INPLACE_STRING_HPP

#include <etl/_algorithm/copy.hpp>
#include <etl/_algorithm/fill.hpp>
#include <etl/_algorithm/max.hpp>
#include <etl/_algorithm/remove.hpp>
#include <etl/_algorithm/rotate.hpp>
#include <etl/_algorithm/swap_ranges.hpp>
#include <etl/_array/array.hpp>
#include <etl/_contracts/check.hpp>
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
#include <etl/_string/str_replace.hpp>
#include <etl/_string_view/basic_string_view.hpp>
#include <etl/_strings/find.hpp>
#include <etl/_strings/rfind.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/smallest_size_t.hpp>
#include <etl/_utility/ignore_unused.hpp>

namespace etl {

/// \brief basic_inplace_string class with fixed size capacity.
/// \tparam Char Build in type for character size (mostly 'char')
/// \tparam Capacity Usable capacity for basic_inplace_string (excluding null terminator)
/// \headerfile etl/string.hpp
/// \include string.cpp
template <typename Char, etl::size_t Capacity, typename Traits = etl::char_traits<Char>>
struct basic_inplace_string {
    template <typename T>
    static constexpr bool string_view_like =                        //
        is_convertible_v<T const&, basic_string_view<Char, Traits>> //
        and not is_convertible_v<T const&, Char const*>;

    using internal_size_t = etl::smallest_size_t<Capacity>;

public:
    using value_type             = Char;
    using size_type              = etl::size_t;
    using difference_type        = etl::ptrdiff_t;
    using traits_type            = Traits;
    using pointer                = Char*;
    using const_pointer          = Char const*;
    using reference              = Char&;
    using const_reference        = Char const&;
    using iterator               = Char*;
    using const_iterator         = Char const*;
    using reverse_iterator       = etl::reverse_iterator<iterator>;
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

    /// Default constructor.
    constexpr basic_inplace_string() = default;

    /// Character pointer constructor.
    /// \pre len <= Capacity
    constexpr basic_inplace_string(const_pointer str, size_type const len) noexcept
    {
        TETL_PRECONDITION(len <= Capacity);
        unsafe_set_size(len);
        traits_type::copy(_storage.data(), str, len);
    }

    /// Character pointer constructor. Calls traits_type::length.
    /// \pre Length of \p str must be <= Capacity
    constexpr basic_inplace_string(const_pointer str) noexcept
        : basic_inplace_string(str, traits_type::length(str))
    {
    }

    constexpr basic_inplace_string(nullptr_t /*null*/) = delete;

    /// Constructs the string with count copies of character ch.
    /// \pre count <= Capacity
    constexpr basic_inplace_string(size_type count, Char ch) noexcept
    {
        TETL_PRECONDITION(count <= Capacity);
        fill(begin(), begin() + count, ch);
        unsafe_set_size(count);
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

    /// Implicitly converts view to a string view sv, then initializes the
    /// string with the contents of sv.
    template <typename StringView>
        requires string_view_like<StringView>
    explicit constexpr basic_inplace_string(StringView const& view) noexcept

    {
        basic_string_view<Char, traits_type> const sv = view;
        assign(sv.begin(), sv.end());
    }

    /// Implicitly converts view to a string view sv, then initializes the
    /// string with the subrange [ pos, pos + n ) of sv.
    template <typename StringView>
        requires string_view_like<StringView>
    explicit constexpr basic_inplace_string(StringView const& view, size_type pos, size_type n)
        : basic_inplace_string{basic_string_view<Char, traits_type>{view}.substr(pos, n)}
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
        auto const len = traits_type::length(s);
        TETL_PRECONDITION(len <= capacity());
        assign(s, len);
        return *this;
    }

    constexpr auto operator=(nullptr_t /*0*/) -> basic_inplace_string& = delete;

    /// Replaces the contents with character ch.
    constexpr auto operator=(Char ch) noexcept -> basic_inplace_string&
    {
        assign(&ch, 1);
        return *this;
    }

    /// Implicitly converts view to a string view sv, then replaces the
    /// contents with those of the sv.
    template <typename StringView>
        requires string_view_like<StringView>
    constexpr auto operator=(StringView const& view) noexcept -> basic_inplace_string&
    {
        assign(view);
        return *this;
    }

    /// Replaces the contents with count copies of character ch.
    constexpr auto assign(size_type count, Char ch) noexcept -> basic_inplace_string&
    {
        TETL_PRECONDITION(count <= capacity());
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

    /// Replaces the contents with copies of the characters in the range
    /// [ s, s + count ). This range can contain null characters.
    constexpr auto assign(const_pointer s, size_type count) noexcept -> basic_inplace_string&
    {
        TETL_PRECONDITION(count <= capacity());
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

    /// \brief Implicitly converts view to a string view sv, then replaces the
    /// contents with the characters from sv.
    template <typename StringView>
        requires string_view_like<StringView>
    constexpr auto assign(StringView const& view) noexcept -> basic_inplace_string&
    {
        auto tmp = basic_inplace_string{view};
        *this    = tmp;
        return *this;
    }

    /// \brief Implicitly converts view to a string view sv, then replaces the
    /// contents with the characters from the subview [ pos, pos + count ) of
    /// sv.
    template <typename StringView>
        requires string_view_like<StringView>
    constexpr auto
    assign(StringView const& view, size_type pos, size_type count = npos) noexcept -> basic_inplace_string&
    {
        auto tmp = basic_inplace_string{view, pos, count};
        *this    = tmp;
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
    [[nodiscard]] constexpr auto front() noexcept -> reference
    {
        TETL_PRECONDITION(not empty());
        return *begin();
    }

    /// \brief Accesses the first character.
    [[nodiscard]] constexpr auto front() const noexcept -> const_reference
    {
        TETL_PRECONDITION(not empty());
        return *begin();
    }

    /// \brief Accesses the last character.
    [[nodiscard]] constexpr auto back() noexcept -> reference
    {
        TETL_PRECONDITION(not empty());
        return *etl::prev(end());
    }

    /// \brief Accesses the last character.
    [[nodiscard]] constexpr auto back() const noexcept -> const_reference
    {
        TETL_PRECONDITION(not empty());
        return *etl::prev(end());
    }

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
    [[nodiscard]] constexpr operator basic_string_view<Char, traits_type>() const noexcept
    {
        return basic_string_view<Char, traits_type>(data(), size());
    }

    /// \brief Removes all characters from the string. Sets size to 0 and
    /// overrides the buffer with zeros.
    constexpr auto clear() noexcept -> void
    {
        *begin() = Char(0);
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
        TETL_PRECONDITION(size() > distance);
        etl::rotate(begin() + start, begin() + start + distance, end());
        unsafe_set_size(size() - distance);
        return begin() + start;
    }

    /// \brief Appends the given character ch to the end of the string.
    /// \pre size() < capacity()
    constexpr auto push_back(Char ch) noexcept -> void
    {
        TETL_PRECONDITION(size() < capacity());
        append(1, ch);
    }

    /// \brief Removes the last character from the string.
    /// \pre size() != 0
    constexpr auto pop_back() noexcept -> void
    {
        TETL_PRECONDITION(not empty());
        unsafe_set_size(size() - 1);
    }

    /// \brief Appends count copies of character s.
    constexpr auto append(size_type const count, Char const s) noexcept -> basic_inplace_string&
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

    /// \brief Implicitly converts view to a string_view sv, then appends all
    /// characters from sv.
    template <typename StringView>
        requires string_view_like<StringView>
    constexpr auto append(StringView const& view) -> basic_inplace_string&
    {
        etl::basic_string_view<Char, traits_type> sv = view;
        return append(sv.data(), sv.size());
    }

    /// \brief Implicitly converts view to a string_view sv then appends the
    /// characters from the subview [ pos, pos + count ) of sv.
    template <typename StringView>
        requires string_view_like<StringView>
    constexpr auto append(StringView const& view, size_type pos, size_type count = npos) -> basic_inplace_string&
    {
        etl::basic_string_view<Char, traits_type> sv = view;
        return append(sv.substr(pos, count));
    }

    /// \brief Appends string str.
    constexpr auto operator+=(basic_inplace_string const& str) noexcept -> basic_inplace_string& { return append(str); }

    /// \brief Appends character ch.
    constexpr auto operator+=(Char ch) noexcept -> basic_inplace_string& { return append(1, ch); }

    /// \brief Appends the null-terminated character string pointed to by s.
    constexpr auto operator+=(const_pointer s) noexcept -> basic_inplace_string& { return append(s); }

    /// \brief Implicitly converts view to a string view sv, then appends
    /// characters in the string view sv.
    template <typename StringView>
        requires string_view_like<StringView>
    constexpr auto operator+=(StringView const& view) noexcept -> basic_inplace_string&
    {
        return append(view);
    }

    /// \brief Inserts count copies of character ch at the position index.
    constexpr auto insert(size_type const index, size_type const count, Char const ch) noexcept -> basic_inplace_string&
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
        using view_type = basic_string_view<Char, traits_type>;
        auto sv         = view_type(str).substr(indexStr, count);
        insert_impl(begin() + index, sv.data(), sv.size());
        return *this;
    }

    //
    //  * \brief Inserts character ch before the character pointed by pos.
    // constexpr auto insert(const_iterator pos, Char const ch) noexcept
    // -> iterator
    // {
    // }

    //
    //  * \brief Inserts count copies of character ch before the element (if
    //  any) pointed by
    //  * pos.
    // constexpr auto insert(const_iterator pos, size_type count,
    //                       Char const ch) noexcept -> iterator
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

    /// \brief Implicitly converts view to a string view sv, then inserts the
    /// elements from sv before the element (if any) pointed by pos.
    template <typename StringView>
        requires string_view_like<StringView>
    constexpr auto insert(size_type const pos, StringView const& view) noexcept -> basic_inplace_string&
    {
        basic_string_view<Char, traits_type> sv = view;
        insert_impl(begin() + pos, sv.data(), sv.size());
        return *this;
    }

    /// \brief Implicitly converts view to a string view sv, then inserts, before
    /// the element (if any) pointed by pos, the characters from the subview
    /// [index_str, index_str+count) of sv.
    template <typename StringView>
        requires string_view_like<StringView>
    constexpr auto
    insert(size_type const index, StringView const& view, size_type const indexStr, size_type const count = npos)
        noexcept -> basic_inplace_string&
    {
        basic_string_view<Char, traits_type> sv = view;

        auto sub = sv.substr(indexStr, count);
        insert_impl(begin() + index, sub.data(), sub.size());
        return *this;
    }

    /// \brief Compares this string to str.
    [[nodiscard]] constexpr auto compare(basic_inplace_string const& str) const noexcept -> int
    {
        return basic_string_view<Char, Traits>{*this}.compare({str.data(), str.size()});
    }

    /// \brief Compares this string to str with other capacity.
    template <size_type OtherCapacity>
    [[nodiscard]] constexpr auto compare(basic_inplace_string<Char, OtherCapacity, traits_type> const& str
    ) const noexcept -> int
    {
        return basic_string_view<Char, Traits>{*this}.compare({str.data(), str.size()});
    }

    /// \brief Compares a [pos, pos+count) substring of this string to str. If
    /// count > size() - pos the substring is [pos, size()).
    [[nodiscard]] constexpr auto
    compare(size_type const pos, size_type const count, basic_inplace_string const& str) const -> int
    {
        auto const sz  = count > size() - pos ? size() : count;
        auto const sub = basic_string_view<Char, Traits>(*this).substr(pos, sz);
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
        auto const sub1 = basic_string_view<Char, Traits>(*this).substr(pos1, sz1);

        auto const sz2  = count2 > str.size() - pos2 ? size() : count2;
        auto const sub2 = basic_string_view<Char, Traits>(str).substr(pos2, sz2);

        return sub1.compare(sub2);
    }

    /// \brief Compares this string to the null-terminated character sequence
    /// beginning at the character pointed to by s with length
    /// traits_type::length(s).
    [[nodiscard]] constexpr auto compare(const_pointer s) const -> int
    {
        return basic_string_view<Char, Traits>{*this}.compare({s, traits_type::length(s)});
    }

    /// \brief Compares a [pos1, pos1+count1) substring of this string to the
    /// null-terminated character sequence beginning at the character pointed to
    /// by s with length traits_type::length(s). If count1 > size() - pos1 the
    /// substring is [pos1, size()).
    [[nodiscard]] constexpr auto compare(size_type const pos, size_type const count, const_pointer s) const -> int
    {
        auto const sz  = count > size() - pos ? size() : count;
        auto const sub = basic_string_view<Char, Traits>(*this).substr(pos, sz);
        return sub.compare({s, traits_type::length(s)});
    }

    /// \brief  Compares a [pos1, pos1+count1) substring of this string to the
    /// characters in the range [s, s + count2). If count1 > size() - pos1 the
    /// substring is [pos1, size()). (Note: the characters in the range [s, s +
    /// count2) may include null characters.)
    [[nodiscard]] constexpr auto
    compare(size_type const pos1, size_type const count1, const_pointer s, size_type const count2) const -> int
    {
        auto const sz  = count1 > size() - pos1 ? size() : count1;
        auto const sub = basic_string_view<Char, Traits>(*this).substr(pos1, sz);
        return sub.compare({s, count2});
    }

    /// \brief Implicitly converts view to a string view sv, then compares the
    /// content of this string to sv.
    template <typename StringView>
        requires string_view_like<StringView>
    [[nodiscard]] constexpr auto compare(StringView const& view) const noexcept -> int
    {
        using view_type    = basic_string_view<Char, Traits>;
        view_type const sv = view;
        return view_type(*this).compare(sv);
    }

    /// \brief Implicitly converts view to a string view sv, then compares a [pos1,
    /// pos1+count1) substring of this string to sv.
    template <typename StringView>
        requires string_view_like<StringView>
    [[nodiscard]] constexpr auto compare(size_type pos1, size_type count1, StringView const& view) const noexcept -> int
    {
        using view_type    = basic_string_view<Char, Traits>;
        view_type const sv = view;
        return view_type(*this).substr(pos1, count1).compare(sv);
    }

    /// \brief Implicitly converts view to a string view sv, then compares a [pos1,
    /// pos1+count1) substring of this string to a substring [pos2, pos2+count2)
    /// of sv.
    template <typename StringView>
        requires string_view_like<StringView>
    [[nodiscard]] constexpr auto
    compare(size_type pos1, size_type count1, StringView const& view, size_type pos2, size_type count2 = npos)
        const noexcept -> int
    {
        using view_type    = basic_string_view<Char, Traits>;
        view_type const sv = view;
        return view_type(*this).substr(pos1, count1).compare(sv.substr(pos2, count2));
    }

    /// \brief Checks if the string begins with the given prefix.
    [[nodiscard]] constexpr auto starts_with(basic_string_view<Char, Traits> sv) const noexcept -> bool
    {
        return basic_string_view<Char, Traits>(data(), size()).starts_with(sv);
    }

    /// \brief Checks if the string begins with the given prefix.
    [[nodiscard]] constexpr auto starts_with(Char c) const noexcept -> bool
    {
        return basic_string_view<Char, Traits>(data(), size()).starts_with(c);
    }

    /// \brief Checks if the string begins with the given prefix.
    [[nodiscard]] constexpr auto starts_with(const_pointer s) const -> bool
    {
        return basic_string_view<Char, Traits>(data(), size()).starts_with(s);
    }

    /// \brief Checks if the string ends with the given prefix.
    [[nodiscard]] constexpr auto ends_with(basic_string_view<Char, Traits> sv) const noexcept -> bool
    {
        return basic_string_view<Char, Traits>(data(), size()).ends_with(sv);
    }

    /// \brief Checks if the string ends with the given prefix.
    [[nodiscard]] constexpr auto ends_with(Char c) const noexcept -> bool
    {
        return basic_string_view<Char, Traits>(data(), size()).ends_with(c);
    }

    /// \brief Checks if the string ends with the given prefix.
    [[nodiscard]] constexpr auto ends_with(const_pointer str) const -> bool
    {
        return basic_string_view<Char, Traits>(data(), size()).ends_with(str);
    }

    /// \brief Replaces the part of the string indicated [pos, pos + count) with
    /// a new string.
    constexpr auto replace(size_type pos, size_type count, basic_inplace_string const& str) -> basic_inplace_string&
    {
        TETL_PRECONDITION(pos < size());
        TETL_PRECONDITION(pos + count < size());

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
        auto* f = to_mutable_iterator(first);
        auto* l = to_mutable_iterator(last);
        detail::str_replace(f, l, str.begin(), str.end());
        return *this;
    }

    constexpr auto
    replace(size_type pos, size_type count, basic_inplace_string const& str, size_type pos2, size_type count2 = npos)
        -> basic_inplace_string&
    {
        TETL_PRECONDITION(pos < size());
        TETL_PRECONDITION(pos2 < str.size());

        auto* f        = data() + etl::min(pos, size());
        auto* l        = data() + etl::min(pos + count, size());
        auto const* sf = etl::next(str.begin(), static_cast<etl::ptrdiff_t>(etl::min(pos2, str.size())));
        auto const* sl = etl::next(str.begin(), static_cast<etl::ptrdiff_t>(etl::min(pos2 + count2, str.size())));
        detail::str_replace(f, l, sf, sl);
        return *this;
    }

    constexpr auto replace(size_type pos, size_type count, Char const* str, size_type count2) -> basic_inplace_string&
    {
        TETL_PRECONDITION(pos < size());
        TETL_PRECONDITION(pos + count < size());

        auto* f = next(data(), min(pos, size()));
        auto* l = next(data(), min(pos + count, size()));
        detail::str_replace(f, l, str, next(str, count2));
        return *this;
    }

    constexpr auto
    replace(const_iterator first, const_iterator last, Char const* str, size_type count2) -> basic_inplace_string&
    {
        auto* f = to_mutable_iterator(first);
        auto* l = to_mutable_iterator(last);
        detail::str_replace(f, l, str, next(str, count2));
        return *this;
    }

    constexpr auto replace(size_type pos, size_type count, Char const* str) -> basic_inplace_string&
    {
        TETL_PRECONDITION(pos < size());
        TETL_PRECONDITION(pos + count < size());

        auto* f = next(data(), min(pos, size()));
        auto* l = next(data(), min(pos + count, size()));
        detail::str_replace(f, l, str, next(str, strlen(str)));
        return *this;
    }

    constexpr auto replace(const_iterator first, const_iterator last, Char const* str) -> basic_inplace_string&
    {
        auto* f = to_mutable_iterator(first);
        auto* l = to_mutable_iterator(last);
        detail::str_replace(f, l, str, next(str, strlen(str)));
        return *this;
    }

    // constexpr auto replace(size_type pos, size_type count, size_type count2,
    //    Char ch) -> basic_inplace_string&
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
    replace(const_iterator first, const_iterator last, size_type count2, Char ch) -> basic_inplace_string&
    {
        auto* f = to_mutable_iterator(first);
        auto* l = etl::min(to_mutable_iterator(last), f + count2);
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
    constexpr auto resize(size_type count, Char ch) noexcept -> void
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
    constexpr auto resize(size_type count) noexcept -> void { resize(count, Char()); }

    /// \brief Exchanges the contents of the string with those of other. All
    /// iterators and references may be invalidated.
    constexpr auto swap(basic_inplace_string& other) noexcept -> void
    {
        auto const thisSize = size();
        auto const maxSize  = static_cast<etl::ptrdiff_t>(etl::max(thisSize, other.size()));

        etl::swap_ranges(begin(), etl::next(begin(), maxSize + 1), other.begin()); // includes null-terminator
        unsafe_set_size(other.size());
        other.unsafe_set_size(thisSize);
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
        return etl::strings::find<Char, Traits>(*this, str, pos);
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
        return etl::strings::find<Char, Traits>(*this, basic_string_view<Char, Traits>{s, count}, pos);
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
        return etl::strings::find<Char, Traits>(*this, s, pos);
    }

    /// \brief Finds the first substring equal to the given character sequence.
    /// Search begins at pos, i.e. the found substring must not begin in a
    /// position preceding pos.
    ///
    /// https://en.cppreference.com/w/cpp/string/basic_string/find
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found.
    [[nodiscard]] constexpr auto find(Char ch, size_type pos = 0) const noexcept -> size_type
    {
        return etl::strings::find<Char, Traits>(*this, basic_string_view<Char, Traits>{&ch, 1}, pos);
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
        return etl::strings::rfind<Char, Traits>(*this, str, pos);
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
        return etl::strings::rfind<Char, Traits>(*this, s, count, pos);
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
        return etl::strings::rfind<Char, Traits>(*this, s, pos);
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
    [[nodiscard]] constexpr auto rfind(Char ch, size_type pos = 0) const noexcept -> size_type
    {
        return etl::strings::rfind<Char, Traits>(*this, ch, pos);
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
            return basic_string_view<Char, Traits>{*this}.find_first_of(s, pos, count);
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
    [[nodiscard]] constexpr auto find_first_of(Char ch, size_type pos = 0) const noexcept -> size_type
    {
        return find_first_of(&ch, pos, 1);
    }

    /// \brief Finds the first character equal to one of the characters in the
    /// given character sequence. The search considers only the interval [pos,
    /// size()). If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto
    find_first_of(basic_string_view<Char, traits_type> str, size_type pos = 0) const noexcept -> size_type
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
        return basic_string_view<Char, Traits>{*this}.find_first_not_of(str, pos);
    }

    /// \brief Finds the first character not equal to any of the characters in
    /// the given character sequence.
    ///
    /// \return Position of the first character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_first_not_of(Char ch, size_type pos = 0) const noexcept -> size_type
    {
        return basic_string_view<Char, Traits>{*this}.find_first_not_of(ch, pos);
    }

    /// \brief Finds the first character not equal to any of the characters in
    /// the given character sequence.
    ///
    /// \return Position of the first character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_first_not_of(Char const* s, size_type pos) const -> size_type
    {
        return basic_string_view<Char, Traits>{*this}.find_first_not_of(s, pos);
    }

    /// \brief Finds the first character not equal to any of the characters in
    /// the given character sequence.
    ///
    /// \return Position of the first character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_first_not_of(Char const* s, size_type pos, size_type count) const -> size_type
    {
        return basic_string_view<Char, Traits>{*this}.find_first_not_of(s, pos, count);
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. The exact search algorithm is not specified. The
    /// search considers only the interval [0, pos]. If the character is not
    /// present in the interval, npos will be returned.
    [[nodiscard]] constexpr auto
    find_last_of(basic_inplace_string const& str, size_type pos = 0) const noexcept -> size_type
    {
        return basic_string_view<Char, Traits>{*this}.find_last_of(str, pos);
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. The exact search algorithm is not specified. The
    /// search considers only the interval [0, pos]. If the character is not
    /// present in the interval, npos will be returned.
    [[nodiscard]] constexpr auto find_last_of(Char c, size_type pos = 0) const noexcept -> size_type
    {
        return basic_string_view<Char, Traits>{*this}.find_last_of(c, pos);
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. The exact search algorithm is not specified. The
    /// search considers only the interval [0, pos]. If the character is not
    /// present in the interval, npos will be returned.
    [[nodiscard]] constexpr auto find_last_of(Char const* s, size_type pos, size_type count) const -> size_type
    {
        return basic_string_view<Char, Traits>{*this}.find_last_of(s, pos, count);
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. The exact search algorithm is not specified. The
    /// search considers only the interval [0, pos]. If the character is not
    /// present in the interval, npos will be returned.
    [[nodiscard]] constexpr auto find_last_of(Char const* s, size_type pos = 0) const -> size_type
    {
        return basic_string_view<Char, Traits>{*this}.find_last_of(s, pos);
    }

    /// \brief Finds the last character equal to none of the characters in the
    /// given character sequence. The search considers only the interval [0,
    /// pos]. If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto
    find_last_not_of(basic_inplace_string const& str, size_type pos = 0) const noexcept -> size_type
    {
        return basic_string_view<Char, Traits>{*this}.find_last_not_of(str, pos);
    }

    /// \brief Finds the last character equal to none of the characters in the
    /// given character sequence. The search considers only the interval [0,
    /// pos]. If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto find_last_not_of(Char c, size_type pos = 0) const noexcept -> size_type
    {
        return basic_string_view<Char, Traits>{*this}.find_last_not_of(c, pos);
    }

    /// \brief Finds the last character equal to none of the characters in the
    /// given character sequence. The search considers only the interval [0,
    /// pos]. If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto find_last_not_of(Char const* s, size_type pos, size_type count) const -> size_type
    {
        return basic_string_view<Char, Traits>{*this}.find_last_not_of(s, pos, count);
    }

    /// \brief Finds the last character equal to none of the characters in the
    /// given character sequence. The search considers only the interval [0,
    /// pos]. If the character is not present in the interval, npos will be
    /// returned.
    [[nodiscard]] constexpr auto find_last_not_of(Char const* s, size_type pos = 0) const -> size_type
    {
        return basic_string_view<Char, Traits>{*this}.find_last_not_of(s, pos);
    }

    /// \brief Checks if the string contains the given substring.
    [[nodiscard]] constexpr auto contains(etl::basic_string_view<Char, Traits> sv) const noexcept -> bool
    {
        return basic_string_view<Char, Traits>{*this}.contains(sv);
    }

    /// \brief Checks if the string contains the given substring.
    [[nodiscard]] constexpr auto contains(Char c) const noexcept -> bool
    {
        return basic_string_view<Char, Traits>{*this}.contains(c);
    }

    /// \brief Checks if the string contains the given substring.
    [[nodiscard]] constexpr auto contains(Char const* s) const -> bool
    {
        return basic_string_view<Char, Traits>{*this}.contains(s);
    }

    /// \brief This is a special value equal to the maximum value representable
    /// by the type size_type. The exact meaning depends on context, but it is
    /// generally used either as end of string indicator by the functions that
    /// expect a string index or as the error indicator by the functions that
    /// return a string index.
    static constexpr size_type npos = numeric_limits<size_type>::max();

private:
    [[nodiscard]] constexpr auto to_mutable_iterator(const_iterator it) -> iterator
    {
        auto const dist = etl::distance(cbegin(), it);
        return etl::next(begin(), static_cast<etl::ptrdiff_t>(dist));
    }

    [[nodiscard]] constexpr auto unsafe_at(size_type index) noexcept -> reference
    {
        TETL_PRECONDITION(index < size() + 1);
        return *etl::next(_storage.data(), static_cast<etl::ptrdiff_t>(index));
    }

    [[nodiscard]] constexpr auto unsafe_at(size_type index) const noexcept -> const_reference
    {
        TETL_PRECONDITION(index < size() + 1);
        return *etl::next(_storage.data(), static_cast<etl::ptrdiff_t>(index));
    }

    constexpr auto unsafe_set_size(size_type const newSize) noexcept -> void
    {
        TETL_PRECONDITION(newSize <= Capacity);
        _storage.set_size(newSize);
        unsafe_at(newSize) = Char(0);
    }

    constexpr auto insert_impl(iterator pos, const_pointer text, size_type count) -> void
    {
        // Insert text at end.
        auto* currentEnd = end();
        append(text, count);

        // Rotate to correct position
        etl::rotate(pos, currentEnd, end());
    }

    struct tiny_layout {
        constexpr tiny_layout() noexcept { _buffer[Capacity] = Capacity; }

        [[nodiscard]] constexpr auto data() noexcept { return _buffer.data(); }

        [[nodiscard]] constexpr auto data() const noexcept { return _buffer.data(); }

        [[nodiscard]] constexpr auto get_size() const noexcept { return Capacity - size_type(_buffer[Capacity]); }

        constexpr auto set_size(size_t size) noexcept { return _buffer[Capacity] = Char(Capacity - size); }

    private:
        etl::array<Char, Capacity + 1> _buffer{};
    };

    struct normal_layout {
        constexpr normal_layout() noexcept = default;

        [[nodiscard]] constexpr auto data() noexcept { return _buffer.data(); }

        [[nodiscard]] constexpr auto data() const noexcept { return _buffer.data(); }

        [[nodiscard]] constexpr auto get_size() const noexcept { return size_t(_size); }

        constexpr auto set_size(size_t size) noexcept { return _size = internal_size_t(size); }

    private:
        internal_size_t _size{};
        etl::array<Char, Capacity + 1> _buffer{};
    };

    using layout_type = etl::conditional_t<(Capacity < 16), tiny_layout, normal_layout>;
    layout_type _storage{};
};

/// Typedef for a basic_inplace_string using 'char'
template <etl::size_t Capacity>
using inplace_string = basic_inplace_string<char, Capacity>;

/// Typedef for a basic_inplace_string using 'wchar_t'
template <etl::size_t Capacity>
using inplace_wstring = basic_inplace_string<wchar_t, Capacity>;

/// Typedef for a basic_inplace_string using 'char8_t'
template <etl::size_t Capacity>
using inplace_u8string = basic_inplace_string<char8_t, Capacity>;

/// Typedef for a basic_inplace_string using 'char16_t'
template <etl::size_t Capacity>
using inplace_u16string = basic_inplace_string<char16_t, Capacity>;

/// Typedef for a basic_inplace_string using 'char32_t'
template <etl::size_t Capacity>
using inplace_u32string = basic_inplace_string<char32_t, Capacity>;

/// \brief Returns a string containing characters from lhs followed by the
/// characters from rhs.
template <typename Char, typename Traits, size_t Capacity1, size_t Capacity2>
[[nodiscard]] constexpr auto operator+(
    basic_inplace_string<Char, Capacity1, Traits> const& lhs,
    basic_inplace_string<Char, Capacity2, Traits> const& rhs
) noexcept -> basic_inplace_string<Char, Capacity1, Traits>
{
    auto str = basic_inplace_string<Char, Capacity1, Traits>{lhs};
    str.append(rhs);
    return str;
}

/// \brief Returns a string containing characters from lhs followed by the
/// characters from rhs.
template <typename Char, typename Traits, size_t Capacity>
[[nodiscard]] constexpr auto operator+(basic_inplace_string<Char, Capacity, Traits> const& lhs, Char const* rhs)
    noexcept -> basic_inplace_string<Char, Capacity, Traits>
{
    auto str = basic_inplace_string<Char, Capacity, Traits>{lhs};
    str.append(rhs);
    return str;
}

/// \brief Returns a string containing characters from lhs followed by the
/// characters from rhs.
template <typename Char, typename Traits, size_t Capacity>
[[nodiscard]] constexpr auto operator+(basic_inplace_string<Char, Capacity, Traits> const& lhs, Char rhs) noexcept
    -> basic_inplace_string<Char, Capacity, Traits>
{
    auto str = basic_inplace_string<Char, Capacity, Traits>{lhs};
    str.append(1, rhs);
    return str;
}

/// \brief Returns a string containing characters from lhs followed by the
/// characters from rhs.
template <typename Char, typename Traits, size_t Capacity>
[[nodiscard]] constexpr auto operator+(Char const* lhs, basic_inplace_string<Char, Capacity, Traits> const& rhs)
    noexcept -> basic_inplace_string<Char, Capacity, Traits>
{
    auto str = basic_inplace_string<Char, Capacity, Traits>{lhs};
    str.append(rhs);
    return str;
}

/// \brief Returns a string containing characters from lhs followed by the
/// characters from rhs.
template <typename Char, typename Traits, size_t Capacity>
[[nodiscard]] constexpr auto operator+(Char lhs, basic_inplace_string<Char, Capacity, Traits> const& rhs) noexcept
    -> basic_inplace_string<Char, Capacity, Traits>
{
    auto str = basic_inplace_string<Char, Capacity, Traits>{1, lhs};
    str.append(rhs);
    return str;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename Char, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator==(
    etl::basic_inplace_string<Char, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<Char, Capacity2, Traits> const& rhs
) noexcept -> bool
{
    return lhs.compare(rhs) == 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename Char, typename Traits, etl::size_t Capacity>
[[nodiscard]] constexpr auto
operator==(etl::basic_inplace_string<Char, Capacity, Traits> const& lhs, Char const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) == 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename Char, typename Traits, etl::size_t Capacity>
[[nodiscard]] constexpr auto
operator==(Char const* lhs, etl::basic_inplace_string<Char, Capacity, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) == 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename Char, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator!=(
    etl::basic_inplace_string<Char, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<Char, Capacity2, Traits> const& rhs
) noexcept -> bool
{
    return lhs.compare(rhs) != 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename Char, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator!=(etl::basic_inplace_string<Char, Capacity1, Traits> const& lhs, Char const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) != 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details Two strings are equal if both the size of lhs and rhs are equal and
/// each character in lhs has equivalent character in rhs at the same position.
template <typename Char, typename Traits, etl::size_t Capacity>
[[nodiscard]] constexpr auto
operator!=(Char const* lhs, etl::basic_inplace_string<Char, Capacity, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) != 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator<(
    etl::basic_inplace_string<Char, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<Char, Capacity2, Traits> const& rhs
) noexcept
{
    return lhs.compare(rhs) < 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator<(etl::basic_inplace_string<Char, Capacity1, Traits> const& lhs, Char const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) < 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator<(Char const* lhs, etl::basic_inplace_string<Char, Capacity1, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) > 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator<=(
    etl::basic_inplace_string<Char, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<Char, Capacity2, Traits> const& rhs
) noexcept
{
    return lhs.compare(rhs) <= 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator<=(etl::basic_inplace_string<Char, Capacity1, Traits> const& lhs, Char const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) <= 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator<=(Char const* lhs, etl::basic_inplace_string<Char, Capacity1, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) >= 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator>(
    etl::basic_inplace_string<Char, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<Char, Capacity2, Traits> const& rhs
) noexcept
{
    return lhs.compare(rhs) > 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator>(etl::basic_inplace_string<Char, Capacity1, Traits> const& lhs, Char const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) > 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity1>
[[nodiscard]] constexpr auto
operator>(Char const* lhs, etl::basic_inplace_string<Char, Capacity1, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) < 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity1, etl::size_t Capacity2>
[[nodiscard]] constexpr auto operator>=(
    etl::basic_inplace_string<Char, Capacity1, Traits> const& lhs,
    etl::basic_inplace_string<Char, Capacity2, Traits> const& rhs
) noexcept
{
    return lhs.compare(rhs) >= 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity>
[[nodiscard]] constexpr auto
operator>=(etl::basic_inplace_string<Char, Capacity, Traits> const& lhs, Char const* rhs) noexcept -> bool
{
    return lhs.compare(rhs) >= 0;
}

/// \brief Compares the contents of a string with another string or a
/// null-terminated array of Char.
///
/// \details The ordering comparisons are done lexicographically.
template <typename Char, typename Traits, etl::size_t Capacity>
[[nodiscard]] constexpr auto
operator>=(Char const* lhs, etl::basic_inplace_string<Char, Capacity, Traits> const& rhs) noexcept -> bool
{
    return rhs.compare(lhs) <= 0;
}

/// \brief Specializes the etl::swap algorithm for etl::basic_inplace_string.
/// Swaps the contents of lhs and rhs. Equivalent to lhs.swap(rhs).
template <typename Char, typename Traits, etl::size_t Capacity>
constexpr auto
swap(etl::basic_inplace_string<Char, Capacity, Traits>& lhs, etl::basic_inplace_string<Char, Capacity, Traits>& rhs)
    noexcept(noexcept(lhs.swap(rhs))) -> void
{
    lhs.swap(rhs);
}

/// \brief Erases all elements that compare equal to value from the container.
template <typename Char, typename Traits, etl::size_t Capacity, typename U>
constexpr auto erase(basic_inplace_string<Char, Capacity, Traits>& c, U const& value) noexcept ->
    typename basic_inplace_string<Char, Capacity, Traits>::size_type
{
    using return_type = typename basic_inplace_string<Char, Capacity, Traits>::size_type;

    auto it = etl::remove(begin(c), end(c), value);
    auto r  = etl::distance(it, end(c));
    c.erase(it, end(c));
    return static_cast<return_type>(r);
}

/// \brief Erases all elements that satisfy the predicate pred from the
/// container.
template <typename Char, typename Traits, etl::size_t Capacity, typename Predicate>
constexpr auto erase_if(basic_inplace_string<Char, Capacity, Traits>& c, Predicate pred) noexcept ->
    typename basic_inplace_string<Char, Capacity, Traits>::size_type
{
    using return_type = typename basic_inplace_string<Char, Capacity, Traits>::size_type;

    auto it = etl::remove_if(begin(c), end(c), pred);
    auto r  = etl::distance(it, end(c));
    c.erase(it, end(c));
    return static_cast<return_type>(r);
}

} // namespace etl

#endif // TETL_STRING_BASIC_INPLACE_STRING_HPP
