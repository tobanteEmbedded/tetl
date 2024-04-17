// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_BASIC_STRING_VIEW_STRING_VIEW_HPP
#define TETL_BASIC_STRING_VIEW_STRING_VIEW_HPP

#include <etl/_algorithm/clamp.hpp>
#include <etl/_algorithm/find_end.hpp>
#include <etl/_algorithm/lexicographical_compare.hpp>
#include <etl/_algorithm/min.hpp>
#include <etl/_algorithm/none_of.hpp>
#include <etl/_concepts/emulation.hpp>
#include <etl/_iterator/begin.hpp>
#include <etl/_iterator/data.hpp>
#include <etl/_iterator/end.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_iterator/rbegin.hpp>
#include <etl/_iterator/rend.hpp>
#include <etl/_iterator/reverse_iterator.hpp>
#include <etl/_iterator/size.hpp>
#include <etl/_ranges/enable_borrowed_range.hpp>
#include <etl/_string/char_traits.hpp>
#include <etl/_type_traits/type_identity.hpp>
#include <etl/_utility/swap.hpp>

namespace etl {

/// \brief The class template basic_string_view describes an object that can
/// refer to a constant contiguous sequence of char-like objects with the first
/// element of the sequence at position zero. A typical implementation holds
/// only two members: a pointer to constant Char and a size.
/// \headerfile etl/string_view.hpp
/// \ingroup string_view
template <typename Char, typename Traits = etl::char_traits<Char>>
struct basic_string_view {
    using traits_type            = Traits;
    using value_type             = Char;
    using pointer                = Char*;
    using const_pointer          = Char const*;
    using reference              = Char&;
    using const_reference        = Char const&;
    using const_iterator         = Char const*;
    using iterator               = const_iterator;
    using size_type              = etl::size_t;
    using difference_type        = etl::ptrdiff_t;
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;
    using reverse_iterator       = const_reverse_iterator;

    /// \brief Default constructor. Constructs an empty basic_string_view. After
    /// construction, data() is equal to nullptr, and size() is equal to 0.
    constexpr basic_string_view() noexcept = default;

    /// \brief Copy constructor. Constructs a view of the same content as other.
    /// After construction, data() is equal to other.data(), and size() is equal
    /// to other.size().
    constexpr basic_string_view(basic_string_view const& other) noexcept = default;

    /// \brief Constructs a view of the first count characters of the character
    /// array starting with the element pointed by s. s can contain null
    /// characters. The behavior is undefined if [s, s+count) is not a valid
    /// range (even though the constructor may not access any of the elements of
    /// this range). After construction, data() is equal to s, and size() is
    /// equal to count.
    constexpr basic_string_view(Char const* str, size_type size)
        : _begin{str}
        , _size{size}
    {
    }

    /// \brief Constructs a view of the null-terminated character string pointed
    /// to by s, not including the terminating null character. The length of the
    /// view is determined as if by Traits::length(s). The behavior is undefined
    /// if [s, s+Traits::length(s)) is not a valid range. After construction,
    /// data() is equal to s, and size() is equal to Traits::length(s).
    constexpr basic_string_view(Char const* str)
        : _begin{str}
        , _size{traits_type::length(str)}
    {
    }

    constexpr basic_string_view(nullptr_t /*null*/) = delete;

    /// \brief Constructs a basic_string_view over the range [first, last). The
    /// behavior is undefined if [first, last) is not a valid range.
    ///
    /// \bug Improve SFINAE protection. See C++20 standard.
    template <typename Iter>
        requires(detail::RandomAccessIterator<Iter>)
    constexpr basic_string_view(Iter first, Iter last)
        : basic_string_view{first, static_cast<size_type>(last - first)}
    {
    }

    ~basic_string_view() noexcept = default;

    /// \brief Replaces the view with that of view.
    constexpr auto operator=(basic_string_view const& view) noexcept -> basic_string_view& = default;

    /// \brief Returns an iterator to the first character of the view.
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator { return cbegin(); }

    /// \brief Returns an iterator to the first character of the view.
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator { return _begin; }

    /// \brief Returns an iterator to the character following the last character
    /// of the view. This character acts as a placeholder, attempting to access
    /// it results in undefined behavior.
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator { return cend(); }

    /// \brief Returns an iterator to the character following the last character
    /// of the view. This character acts as a placeholder, attempting to access
    /// it results in undefined behavior.
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator { return _begin + _size; }

    /// \brief Returns a reverse iterator to the first character of the reversed
    /// view. It corresponds to the last character of the non-reversed view.
    [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator { return crbegin(); }

    /// \brief Returns a reverse iterator to the first character of the reversed
    /// view. It corresponds to the last character of the non-reversed view.
    [[nodiscard]] constexpr auto crbegin() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(end());
    }

    /// \brief Returns a reverse iterator to the character following the last
    /// character of the reversed view.
    ///
    /// It corresponds to the character preceding the first character of the
    /// non-reversed view. This character acts as a placeholder, attempting to
    /// access it results in undefined behavior.
    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator { return crend(); }

    /// \brief Returns a reverse iterator to the character following the last
    /// character of the reversed view.
    ///
    /// It corresponds to the character preceding the first character of the
    /// non-reversed view. This character acts as a placeholder, attempting to
    /// access it results in undefined behavior.
    [[nodiscard]] constexpr auto crend() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(begin());
    }

    /// Returns a const reference to the character at specified location \p pos
    /// \pre `pos < size()`
    [[nodiscard]] constexpr auto operator[](size_type pos) const -> const_reference { return unsafe_at(pos); }

    /// Returns reference to the first character in the view.
    /// \pre `size() > 0`
    [[nodiscard]] constexpr auto front() const -> const_reference { return unsafe_at(0); }

    /// Returns reference to the last character in the view.
    /// \pre `size() > 0`
    [[nodiscard]] constexpr auto back() const -> const_reference { return unsafe_at(_size - 1); }

    /// Returns a pointer to the underlying character array. The pointer
    /// is such that the range [data(); data() + size()) is valid and the values
    /// in it correspond to the values of the view.
    [[nodiscard]] constexpr auto data() const noexcept -> const_pointer { return _begin; }

    /// Returns the number of Char elements in the view, i.e. etl::distance(begin(), end()).
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return length(); }

    /// Returns the number of Char elements in the view, i.e. etl::distance(begin(), end()).
    [[nodiscard]] constexpr auto length() const noexcept -> size_type { return _size; }

    /// The largest possible number of char-like objects that can be
    /// referred to by a basic_string_view.
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type { return size_type(-1); }

    /// Checks if the view has no characters, i.e. whether size() == 0.
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return _size == 0; }

    /// Moves the start of the view forward by n characters.
    /// \pre `n < size()`
    constexpr auto remove_prefix(size_type n) -> void
    {
        _begin += n;
        _size -= n;
    }

    /// Moves the end of the view back by n characters.
    /// \pre `n < size()`
    constexpr auto remove_suffix(size_type n) -> void { _size = _size - n; }

    /// Exchanges the view with that of v.
    constexpr auto swap(basic_string_view& v) noexcept -> void
    {
        etl::swap(_begin, v._begin);
        etl::swap(_size, v._size);
    }

    /// Copies the substring [pos, pos + rcount) to the character array
    /// pointed to by dest, where rcount is the smaller of count and size() -
    /// pos. Equivalent to Traits::copy(dest, data() + pos, rcount).
    [[nodiscard]] constexpr auto copy(Char* dest, size_type count, size_type pos = 0) const -> size_type
    {
        auto const rcount = etl::min(count, size() - pos);
        traits_type::copy(dest, data() + pos, rcount);
        return rcount;
    }

    /// Returns a view of the substring [pos, pos + rcount), where rcount
    /// is the smaller of count and size() - pos.
    [[nodiscard]] constexpr auto substr(size_type pos = 0, size_type count = npos) const -> basic_string_view
    {
        auto const rcount = etl::min(count, size() - pos);
        return basic_string_view{_begin + pos, rcount};
    }

    /// Compares two character sequences.
    ///
    /// https://en.cppreference.com/w/cpp/string/basic_string_view/compare
    [[nodiscard]] constexpr auto compare(basic_string_view v) const noexcept -> int
    {
        auto const rlen = etl::min(size(), v.size());
        auto const res  = traits_type::compare(data(), v.data(), rlen);

        if (res < 0) {
            return -1;
        }
        if (res > 0) {
            return 1;
        }

        if (size() < v.size()) {
            return -1;
        }
        if (size() > v.size()) {
            return 1;
        }

        return 0;
    }

    /// Compares two character sequences. Equivalent to substr(pos1, count1).compare(v).
    [[nodiscard]] constexpr auto compare(size_type pos1, size_type count1, basic_string_view v) const -> int
    {
        return substr(pos1, count1).compare(v);
    }

    /// Compares two character sequences. Equivalent to substr(pos1, count1).compare(v.substr(pos2, count2))
    [[nodiscard]] constexpr auto
    compare(size_type pos1, size_type count1, basic_string_view v, size_type pos2, size_type count2) const -> int
    {
        return substr(pos1, count1).compare(v.substr(pos2, count2));
    }

    /// Compares two character sequences. Equivalent to compare(basic_string_view(s)).
    [[nodiscard]] constexpr auto compare(Char const* s) const -> int { return compare(basic_string_view(s)); }

    /// Compares two character sequences. Equivalent to substr(pos1, count1).compare(basic_string_view(s)).
    [[nodiscard]] constexpr auto compare(size_type pos1, size_type count1, Char const* s) const -> int
    {
        return substr(pos1, count1).compare(basic_string_view(s));
    }

    /// Compares two character sequences. Equivalent to substr(pos1, count1).compare(basic_string_view(s, count2)).
    [[nodiscard]] constexpr auto compare(size_type pos1, size_type count1, Char const* s, size_type count2) const -> int
    {
        return substr(pos1, count1).compare(basic_string_view(s, count2));
    }

    /// Checks if the string view begins with the given prefix, where the prefix is a string view.
    ///
    /// \details Effectively returns substr(0, sv.size()) == sv
    [[nodiscard]] constexpr auto starts_with(basic_string_view sv) const noexcept -> bool
    {
        return substr(0, sv.size()) == sv;
    }

    /// Checks if the string view begins with the given prefix, where the prefix is a single character.
    ///
    /// \details Effectively returns !empty() && Traits::eq(front(), c)
    [[nodiscard]] constexpr auto starts_with(Char c) const noexcept -> bool
    {
        return !empty() && traits_type::eq(front(), c);
    }

    /// \brief Checks if the string view begins with the given prefix, where the
    /// the prefix is a null-terminated character string.
    ///
    /// \details Effectively returns starts_with(basic_string_view(s))
    [[nodiscard]] constexpr auto starts_with(Char const* str) const -> bool
    {
        return starts_with(basic_string_view(str));
    }

    /// \brief Checks if the string view ends with the given suffix, where the
    /// prefix is a string view.
    ///
    /// \details Effectively returns size() >= sv.size() && compare(size() -
    /// sv.size(), npos, sv) == 0
    [[nodiscard]] constexpr auto ends_with(basic_string_view sv) const noexcept -> bool
    {
        return size() >= sv.size() && compare(size() - sv.size(), npos, sv) == 0;
    }

    /// \brief Checks if the string view ends with the given suffix, where the
    /// prefix is a single character.
    ///
    /// \details Effectively returns !empty() && Traits::eq(back(), c)
    [[nodiscard]] constexpr auto ends_with(Char c) const noexcept -> bool { return !empty() && Traits::eq(back(), c); }

    /// \brief Checks if the string view ends with the given suffix, where the
    /// the prefix is a null-terminated character string.
    ///
    /// \details Effectively returns ends_with(basic_string_view(s))
    constexpr auto ends_with(Char const* str) const -> bool { return ends_with(basic_string_view(str)); }

    /// \brief Finds the first substring equal to the given character sequence.
    /// Finds the first occurence of v in this view, starting at position pos.
    ///
    /// \returns Position of the first character of the found substring, or npos
    /// if no such substring is found.
    [[nodiscard]] constexpr auto find(basic_string_view v, size_type pos = 0) const noexcept -> size_type
    {
        if (v.size() > size() - pos) {
            return npos;
        }

        for (size_type outerIdx = pos; outerIdx < size(); ++outerIdx) {
            if (unsafe_at(outerIdx) == v.front()) {
                auto found = [&] {
                    for (size_type innerIdx = 0; innerIdx < v.size(); ++innerIdx) {
                        auto offset = outerIdx + innerIdx;
                        if (unsafe_at(offset) != v[innerIdx]) {
                            return false;
                        }
                    }

                    return true;
                }();

                if (found) {
                    return outerIdx;
                }
            }
        }

        return npos;
    }

    /// \brief Finds the first substring equal to the given character sequence.
    /// Equivalent to find(basic_string_view(etl::addressof(ch), 1), pos)
    ///
    /// \returns Position of the first character of the found substring, or npos
    /// if no such substring is found.
    [[nodiscard]] constexpr auto find(Char ch, size_type pos = 0) const noexcept -> size_type
    {
        return find(basic_string_view(&ch, 1), pos);
    }

    /// \brief Finds the first substring equal to the given character sequence.
    /// Equivalent to find(basic_string_view(s, count), pos)
    ///
    /// \returns Position of the first character of the found substring, or npos
    /// if no such substring is found.
    constexpr auto find(Char const* s, size_type pos, size_type count) const -> size_type
    {
        return find(basic_string_view(s, count), pos);
    }

    /// \brief Finds the first substring equal to the given character sequence.
    /// Equivalent to find(basic_string_view(s), pos)
    ///
    /// \returns Position of the first character of the found substring, or npos
    /// if no such substring is found.
    constexpr auto find(Char const* s, size_type pos = 0) const -> size_type { return find(basic_string_view(s), pos); }

    /// \brief Finds the last substring equal to the given character sequence.
    /// Finds the last occurence of v in this view, starting at position pos.
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found.
    [[nodiscard]] constexpr auto rfind(basic_string_view sv, size_type pos = npos) const noexcept -> size_type
    {
        pos = etl::min(pos, size());
        if (sv.size() < size() - pos) {
            pos += sv.size();
        } else {
            pos = size();
        }

        auto const* r = etl::find_end(data(), data() + pos, sv.begin(), sv.end(), Traits::eq);
        if (sv.size() > 0 && r == data() + pos) {
            return npos;
        }
        return static_cast<size_type>(r - data());
    }

    /// \brief Finds the last substring equal to the given character sequence.
    /// Equivalent to rfind(basic_string_view(&c, 1), pos).
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found.
    [[nodiscard]] constexpr auto rfind(Char c, size_type pos = npos) const noexcept -> size_type
    {
        if (size() < 1) {
            return npos;
        }

        if (pos < size()) {
            ++pos;
        } else {
            pos = size();
        }
        for (auto const* s = data() + pos; s != data();) {
            if (Traits::eq(*--s, c)) {
                return static_cast<size_type>(s - data());
            }
        }
        return npos;
    }

    /// \brief Finds the last substring equal to the given character sequence.
    /// Equivalent to rfind(basic_string_view(s, count), pos).
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found.
    constexpr auto rfind(Char const* s, size_type pos, size_type count) const noexcept -> size_type
    {
        return rfind({s, count}, pos);
    }

    /// \brief Finds the last substring equal to the given character sequence.
    /// Equivalent to rfind(basic_string_view(s), pos).
    ///
    /// \returns Position of the first character of the found substring or npos
    /// if no such substring is found.
    constexpr auto rfind(Char const* s, size_type pos = npos) const noexcept -> size_type
    {
        return rfind({s, traits_type::length(s)}, pos);
    }

    /// \brief Finds the first character equal to any of the characters in the
    /// given character sequence. Finds the first occurence of any of the
    /// characters of v in this view, starting at position pos.
    ///
    /// \returns Position of the first occurrence of any character of the
    /// substring, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_first_of(basic_string_view v, size_type pos = 0) const noexcept -> size_type
    {
        for (size_type idx = pos; idx < size(); ++idx) {
            for (auto const c : v) {
                if (c == unsafe_at(idx)) {
                    return idx;
                }
            }
        }

        return npos;
    }

    /// \brief Finds the first character equal to any of the characters in the
    /// given character sequence. Equivalent to
    /// find_first_of(basic_string_view(&c, 1), pos)
    ///
    /// \returns Position of the first occurrence of any character of the
    /// substring, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_first_of(Char c, size_type pos = 0) const noexcept -> size_type
    {
        return find_first_of(basic_string_view(&c, 1), pos);
    }

    /// \brief Finds the first character equal to any of the characters in the
    /// given character sequence. Equivalent to
    /// find_first_of(basic_string_view(s, count), pos)
    ///
    /// \returns Position of the first occurrence of any character of the
    /// substring, or npos if no such character is found.
    constexpr auto find_first_of(Char const* s, size_type pos, size_type count) const -> size_type
    {
        return find_first_of(basic_string_view(s, count), pos);
    }

    /// \brief Finds the first character equal to any of the characters in the
    /// given character sequence. Equivalent to
    /// find_first_of(basic_string_view(s), pos)
    ///
    /// \returns Position of the first occurrence of any character of the
    /// substring, or npos if no such character is found.
    constexpr auto find_first_of(Char const* s, size_type pos = 0) const -> size_type
    {
        return find_first_of(basic_string_view(s), pos);
    }

    /// \brief Finds the first character not equal to any of the characters in
    /// the given character sequence.
    ///
    /// \return Position of the first character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_first_not_of(basic_string_view sv, size_type pos = 0) const noexcept -> size_type
    {
        auto const* str = data();
        if (pos < size()) {
            auto const* last = str + size();
            for (auto const* s = str + pos; s != last; ++s) {
                if (Traits::find(sv.data(), sv.size(), *s) == nullptr) {
                    return static_cast<size_type>(s - str);
                }
            }
        }
        return npos;
    }

    /// \brief Finds the first character not equal to any of the characters in
    /// the given character sequence.
    ///
    /// \return Position of the first character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_first_not_of(Char c, size_type pos = 0) const noexcept -> size_type
    {
        if (pos < size()) {
            auto const* last = data() + size();
            for (auto const* s = data() + pos; s != last; ++s) {
                if (!Traits::eq(*s, c)) {
                    return static_cast<size_type>(s - data());
                }
            }
        }
        return npos;
    }

    /// \brief Finds the first character not equal to any of the characters in
    /// the given character sequence.
    ///
    /// \return Position of the first character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_first_not_of(Char const* s, size_type pos, size_type count) const -> size_type
    {
        return find_first_not_of({s, count}, pos);
    }

    /// \brief Finds the first character not equal to any of the characters in
    /// the given character sequence.
    ///
    /// \return Position of the first character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_first_not_of(Char const* s, size_type pos = 0) const -> size_type
    {
        return find_first_not_of({s, traits_type::length(s)}, pos);
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. Exact search algorithm is not specified. The search
    /// considers only the interval [0; pos]. If the character is not present in
    /// the interval, npos will be returned. Finds the last occurence of any of
    /// the characters of v in this view, ending at position pos.
    ///
    /// \returns Position of the last occurrence of any character of the
    /// substring, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_last_of(basic_string_view v, size_type pos = npos) const noexcept -> size_type
    {
        auto offset = etl::clamp<size_type>(pos, 0, size() - 1);
        do { // NOLINT(cppcoreguidelines-avoid-do-while)
            auto const current = unsafe_at(offset);
            for (auto const ch : v) {
                if (ch == current) {
                    return offset;
                }
            }
        } while (offset-- != 0);

        return npos;
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. Exact search algorithm is not specified. The search
    /// considers only the interval [0; pos]. If the character is not present in
    /// the interval, npos will be returned. Equivalent to
    /// find_last_of(basic_string_view(&c, 1), pos).
    ///
    /// \returns Position of the last occurrence of any character of the
    /// substring, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_last_of(Char c, size_type pos = npos) const noexcept -> size_type
    {
        return find_last_of(basic_string_view(&c, 1), pos);
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. Exact search algorithm is not specified. The search
    /// considers only the interval [0; pos]. If the character is not present in
    /// the interval, npos will be returned. Equivalent to
    /// find_last_of(basic_string_view(s, count), pos).
    ///
    /// \returns Position of the last occurrence of any character of the
    /// substring, or npos if no such character is found.
    constexpr auto find_last_of(Char const* s, size_type pos, size_type count) const -> size_type
    {
        return find_last_of(basic_string_view(s, count), pos);
    }

    /// \brief Finds the last character equal to one of characters in the given
    /// character sequence. Exact search algorithm is not specified. The search
    /// considers only the interval [0; pos]. If the character is not present in
    /// the interval, npos will be returned. Equivalent to
    /// find_last_of(basic_string_view(s), pos).
    ///
    /// \returns Position of the last occurrence of any character of the
    /// substring, or npos if no such character is found.
    constexpr auto find_last_of(Char const* s, size_type pos = npos) const -> size_type
    {
        return find_last_of(basic_string_view(s), pos);
    }

    /// \brief Finds the last character not equal to any of the characters of v
    /// in this view, starting at position pos.
    ///
    /// \returns Position of the last character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_last_not_of(basic_string_view v, size_type pos = npos) const noexcept -> size_type
    {
        auto offset = etl::clamp<size_type>(pos, 0, size() - 1);
        do { // NOLINT(cppcoreguidelines-avoid-do-while)
            auto equals = [&](auto ch) { return ch == unsafe_at(offset); };
            if (etl::none_of(v.begin(), v.end(), equals)) {
                return offset;
            }
        } while (offset-- != 0);

        return npos;
    }

    /// \brief Finds the last character not equal to any of the characters in
    /// the given character sequence. Equivalent to
    /// find_last_not_of(basic_string_view(&c, 1), pos).
    ///
    /// \returns Position of the last character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_last_not_of(Char c, size_type pos = npos) const noexcept -> size_type
    {
        return find_last_not_of(basic_string_view(&c, 1), pos);
    }

    /// \brief Finds the last character not equal to any of the characters in
    /// the given character sequence. Equivalent to
    /// find_last_not_of(basic_string_view(s, count), pos).
    ///
    /// \returns Position of the last character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_last_not_of(const_pointer s, size_type pos, size_type count) const -> size_type
    {
        return find_last_not_of(basic_string_view(s, count), pos);
    }

    /// \brief Finds the last character not equal to any of the characters in
    /// the given character sequence. Equivalent to
    /// find_last_not_of(basic_string_view(s), pos)
    ///
    /// \returns Position of the last character not equal to any of the
    /// characters in the given string, or npos if no such character is found.
    [[nodiscard]] constexpr auto find_last_not_of(const_pointer s, size_type pos = npos) const -> size_type
    {
        return find_last_not_of(basic_string_view(s), pos);
    }

    /// \brief Checks if the string contains the given substring.
    [[nodiscard]] constexpr auto contains(basic_string_view sv) const noexcept -> bool { return find(sv) != npos; }

    /// \brief Checks if the string contains the given substring.
    [[nodiscard]] constexpr auto contains(Char c) const noexcept -> bool { return find(c) != npos; }

    /// \brief Checks if the string contains the given substring.
    [[nodiscard]] constexpr auto contains(Char const* s) const -> bool { return find(s) != npos; }

    /// \brief This is a special value equal to the maximum value
    /// representable by the type size_type.
    ///
    /// \details The exact meaning depends on context, but it is generally
    /// used either as end of view indicator by the functions that expect a
    /// view index or as the error indicator by the functions that return a
    /// view index.
    static constexpr size_type npos = size_type(-1);

private:
    [[nodiscard]] constexpr auto unsafe_at(size_type pos) const -> const_reference { return _begin[pos]; }

    const_pointer _begin = nullptr;
    size_type _size      = 0;
};

/// Typedef for common character type `char`
/// \ingroup string_view
using string_view = basic_string_view<char, etl::char_traits<char>>;

/// Typedef for common character type `wchar_t`
/// \ingroup string_view
using wstring_view = basic_string_view<wchar_t, etl::char_traits<wchar_t>>;

/// Typedef for common character type `char8_t`
/// \ingroup string_view
using u8string_view = basic_string_view<char8_t, etl::char_traits<char8_t>>;

/// Typedef for common character type `char16_t`
/// \ingroup string_view
using u16string_view = basic_string_view<char16_t, etl::char_traits<char16_t>>;

/// Typedef for common character type `char32_t`
/// \ingroup string_view
using u32string_view = basic_string_view<char32_t, etl::char_traits<char32_t>>;

inline namespace literals {
inline namespace string_view_literals {

/// Forms a string view of a character literal. Returns etl::string_view{str, len}
[[nodiscard]] constexpr auto operator""_sv(char const* str, etl::size_t len) noexcept -> etl::string_view
{
    return {str, len};
}

/// Forms a string view of a character literal. Returns etl::wstring_view{str, len}
[[nodiscard]] constexpr auto operator""_sv(wchar_t const* str, etl::size_t len) noexcept -> etl::wstring_view
{
    return {str, len};
}

/// Forms a string view of a character literal. Returns etl::u8string_view{str, len}
[[nodiscard]] constexpr auto operator""_sv(char8_t const* str, etl::size_t len) noexcept -> etl::u8string_view
{
    return {str, len};
}

/// Forms a string view of a character literal. Returns etl::u16string_view{str, len}
[[nodiscard]] constexpr auto operator""_sv(char16_t const* str, etl::size_t len) noexcept -> etl::u16string_view
{
    return {str, len};
}

/// Forms a string view of a character literal. Returns etl::u32string_view{str, len}
[[nodiscard]] constexpr auto operator""_sv(char32_t const* str, etl::size_t len) noexcept -> etl::u32string_view
{
    return {str, len};
}

} // namespace string_view_literals
} // namespace literals

namespace ranges {

template <typename Char, typename Traits>
inline constexpr bool enable_borrowed_range<etl::basic_string_view<Char, Traits>> = true;

} // namespace ranges

/// \brief Compares two views. All comparisons are done via the compare() member
/// function (which itself is defined in terms of Traits::compare()):
///
/// \details Two views are equal if both the size of lhs and rhs are equal and
/// each character in lhs has an equivalent character in rhs at the same
/// position.
template <typename Char, typename Traits>
[[nodiscard]] constexpr auto
operator==(basic_string_view<Char, Traits> lhs, type_identity_t<basic_string_view<Char, Traits>> rhs) noexcept -> bool
{
    if (lhs.size() != rhs.size()) {
        return false;
    }
    return lhs.compare(rhs) == 0;
}

/// \brief Compares two views. All comparisons are done via the compare() member
/// function (which itself is defined in terms of Traits::compare()):
///
/// \details The ordering comparisons are done lexicographically -- the
/// comparison is performed by a function equivalent to
/// lexicographical_compare.
template <typename Char, typename Traits>
[[nodiscard]] constexpr auto
operator<(basic_string_view<Char, Traits> lhs, basic_string_view<Char, Traits> rhs) noexcept -> bool
{
    return lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
}

template <typename Char, typename Traits, int = 1>
[[nodiscard]] constexpr auto
operator<(type_identity_t<basic_string_view<Char, Traits>> lhs, basic_string_view<Char, Traits> rhs) noexcept -> bool
{
    return lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
}

template <typename Char, typename Traits, int = 2>
[[nodiscard]] constexpr auto
operator<(basic_string_view<Char, Traits> lhs, type_identity_t<basic_string_view<Char, Traits>> rhs) noexcept -> bool
{
    return lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
}

/// \brief Compares two views. All comparisons are done via the compare() member
/// function (which itself is defined in terms of Traits::compare()):
///
/// \details The ordering comparisons are done lexicographically -- the
/// comparison is performed by a function equivalent to
/// lexicographical_compare.
template <typename Char, typename Traits>
[[nodiscard]] constexpr auto
operator<=(basic_string_view<Char, Traits> lhs, basic_string_view<Char, Traits> rhs) noexcept -> bool
{
    return (lhs < rhs) or (lhs == rhs);
}

template <typename Char, typename Traits, int = 1>
[[nodiscard]] constexpr auto
operator<=(type_identity_t<basic_string_view<Char, Traits>> lhs, basic_string_view<Char, Traits> rhs) noexcept -> bool
{
    return (lhs < rhs) or (lhs == rhs);
}

template <typename Char, typename Traits, int = 2>
[[nodiscard]] constexpr auto
operator<=(basic_string_view<Char, Traits> lhs, type_identity_t<basic_string_view<Char, Traits>> rhs) noexcept -> bool
{
    return (lhs < rhs) or (lhs == rhs);
}

/// \brief Compares two views. All comparisons are done via the compare() member
/// function (which itself is defined in terms of Traits::compare()):
///
/// \details The ordering comparisons are done lexicographically -- the
/// comparison is performed by a function equivalent to
/// lexicographical_compare.
template <typename Char, typename Traits>
[[nodiscard]] constexpr auto
operator>(basic_string_view<Char, Traits> lhs, basic_string_view<Char, Traits> rhs) noexcept -> bool
{
    return !(lhs < rhs) and !(lhs == rhs);
}

template <typename Char, typename Traits, int = 1>
[[nodiscard]] constexpr auto
operator>(type_identity_t<basic_string_view<Char, Traits>> lhs, basic_string_view<Char, Traits> rhs) noexcept -> bool
{
    return !(lhs < rhs) and !(lhs == rhs);
}

template <typename Char, typename Traits, int = 2>
[[nodiscard]] constexpr auto
operator>(basic_string_view<Char, Traits> lhs, type_identity_t<basic_string_view<Char, Traits>> rhs) noexcept -> bool
{
    return !(lhs < rhs) and !(lhs == rhs);
}

/// \brief Compares two views. All comparisons are done via the compare() member
/// function (which itself is defined in terms of Traits::compare()):
///
/// \details The ordering comparisons are done lexicographically -- the
/// comparison is performed by a function equivalent to
/// lexicographical_compare.
template <typename Char, typename Traits>
[[nodiscard]] constexpr auto
operator>=(basic_string_view<Char, Traits> lhs, basic_string_view<Char, Traits> rhs) noexcept -> bool
{
    return lhs > rhs or lhs == rhs;
}

template <typename Char, typename Traits, int = 1>
[[nodiscard]] constexpr auto
operator>=(type_identity_t<basic_string_view<Char, Traits>> lhs, basic_string_view<Char, Traits> rhs) noexcept -> bool
{
    return lhs > rhs or lhs == rhs;
}

template <typename Char, typename Traits, int = 2>
[[nodiscard]] constexpr auto
operator>=(basic_string_view<Char, Traits> lhs, type_identity_t<basic_string_view<Char, Traits>> rhs) noexcept -> bool
{
    return lhs > rhs or lhs == rhs;
}

} // namespace etl

#endif // TETL_BASIC_STRING_VIEW_STRING_VIEW_HPP
