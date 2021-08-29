/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_STRING_CHAR_TRAITS_HPP
#define TETL_STRING_CHAR_TRAITS_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_cwchar/wcslen.hpp"
#include "etl/_cwchar/wint_t.hpp"
#include "etl/_cwchar/wmemchr.hpp"
#include "etl/_cwchar/wmemcmp.hpp"
#include "etl/_cwchar/wmemcpy.hpp"
#include "etl/_cwchar/wmemmove.hpp"
#include "etl/_cwchar/wmemset.hpp"
#include "etl/_ios/iosfwd.hpp"
#include "etl/_ios/typedefs.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {
/// \brief The char_traits class is a traits class template that abstracts basic
/// character and string operations for a given character type. The defined
/// operation set is such that generic algorithms almost always can be
/// implemented in terms of it. It is thus possible to use such algorithms with
/// almost any possible character or string type, just by supplying a customized
/// char_traits class. The char_traits class template serves as a basis for
/// explicit instantiations. The user can provide a specialization for any
/// custom character types. Several specializations are defined for the standard
/// character types. If an operation on traits emits an exception, the behavior
/// is undefined.
template <typename CharT>
struct char_traits;

/// \brief Specializations of char_traits for type char.
template <>
struct char_traits<char> {
    using char_type = char;
    using int_type  = int;
    using off_type  = streamoff;
    // using pos_type  = streampos;
    // using state_type          = mbstate_t;
    // using comparison_category = strong_ordering;

    /// \brief Assigns character a to character r.
    static constexpr auto assign(char_type& a, char_type const& b) noexcept
        -> void
    {
        a = b;
    }

    /// \brief Returns true if a and b are equal, false otherwise.
    static constexpr auto eq(char_type a, char_type b) noexcept -> bool
    {
        return a == b;
    }

    /// \brief Returns true if a is less than b, false otherwise.
    static constexpr auto lt(char_type a, char_type b) noexcept -> bool
    {
        return a < b;
    }

    /// \brief Compares the first count characters of the character strings s1
    /// and s2. The comparison is done lexicographically. If count is zero,
    /// strings are considered equal.
    static constexpr auto compare(
        char_type const* lhs, char_type const* rhs, size_t count) -> int
    {
        if (count == 0) { return 0; }

        for (size_t i = 0; i < count; ++i) {
            if (lhs[i] < rhs[i]) { return -1; }
            if (lhs[i] > rhs[i]) { return 1; }
        }

        return 0;
    }

    /// \brief Returns the length of the character sequence pointed to by s,
    /// that is, the position of the terminating null character (CharT()).
    static constexpr auto length(char_type const* str) -> size_t
    {
        return detail::strlen_impl<char_type, size_t>(str);
    }

    /// \brief Searches for character ch within the first count characters of
    /// the sequence pointed to by p.
    ///
    /// \returns A pointer to the first character in the range specified by [p,
    /// p
    /// + count) that compares equal to ch, or a null pointer if not found.
    static constexpr auto find(char_type const* str, size_t count,
        char_type const& token) -> char_type const*
    {
        for (size_t i = 0; i < count; ++i) {
            if (str[i] == token) { return &str[i]; }
        }

        return nullptr;
    }

    /// \brief Copies count characters from the character string pointed to by
    /// src to the character string pointed to by dest. Performs correctly even
    /// if the copied character ranges overlap, i.e. src is in [dest, dest +
    /// count).
    static constexpr auto move(
        char_type* dest, char_type const* source, size_t count) -> char_type*
    {
        for (size_t i = 0; i < count; ++i) { dest[i] = source[i]; }
        return dest;
    }

    /// \brief Copies count characters from the character string pointed to by
    /// src to the character string pointed to by dest. Formally, for each i in
    /// [0, count), performs assign(src[i], dest[i]). The behavior is undefined
    /// if copied character ranges overlap, i.e. src is in [dest, dest + count).
    static constexpr auto copy(
        char_type* dest, char_type const* source, size_t count) -> char_type*
    {
        for (size_t i = 0; i < count; ++i) { assign(dest[i], source[i]); }
        return dest;
    }

    /// \brief Assigns character a to each character in count characters in the
    /// character sequence pointed to by p.
    static constexpr auto assign(char_type* str, size_t count, char_type token)
        -> char_type*
    {
        for (size_t i = 0; i < count; ++i) { assign(str[i], token); }
        return str;
    }

    /// \brief Converts a value of int_type to char_type. If there are no
    /// equivalent value (such as when c is a copy of the eof() value), the
    /// result is unspecified. Formally, returns the value x such that
    /// char_type<char>::eq_int_type(c, char_type<char>::to_int_type(x)) is
    /// true, and an unspecified value if no such x exists.
    static constexpr auto to_char_type(int_type c) noexcept -> char_type;

    /// \brief Converts a value of char_type to int_type.
    static constexpr auto to_int_type(char_type c) noexcept -> int_type
    {
        return int_type { static_cast<unsigned char>(c) };
    }

    /// \brief Checks whether two values of type int_type are equal.
    ///
    /// https://en.cppreference.com/w/cpp/string/char_traits/eq_int_type
    static constexpr auto eq_int_type(int_type lhs, int_type rhs) noexcept
        -> bool
    {
        if (lhs == rhs) { return true; }
        if ((lhs == eof()) && (rhs == eof())) { return true; }
        if ((lhs == eof()) || (rhs == eof())) { return false; }
        return false;
    }

    /// \brief Returns a value not equivalent to any valid value of type
    /// char_type. Formally, returns a value e such that
    /// char_type<char>::eq_int_type(e, char_type<char>::to_int_type(c)) is
    /// false for all values c
    static constexpr auto eof() noexcept -> int_type { return -1; }

    /// \brief Checks whether e is not equivalent to eof value.
    ///
    /// \details Formally if char_type<char>::eq_int_type(e,
    /// char_type<char>::eof()) is false, returns e otherwise, returns a value f
    /// such that char_type<char>::eq_int_type(f, char_type<char>::eof()) is
    /// false
    static constexpr auto not_eof(int_type c) noexcept -> int_type
    {
        if (!eq_int_type(c, eof())) { return c; }
        return 0;
    }
};

template <>
struct char_traits<wchar_t> {
    using char_type = wchar_t;
    using int_type  = wint_t;
    using off_type  = streamoff;
    // using pos_type   = wstreampos;
    // using state_type = mbstate_t;

    static constexpr auto assign(wchar_t& lhs, wchar_t const& rhs) noexcept
        -> void
    {
        lhs = rhs;
    }

    static constexpr auto eq(wchar_t const& lhs, wchar_t const& rhs) noexcept
        -> bool
    {
        return lhs == rhs;
    }

    static constexpr auto lt(wchar_t const& lhs, wchar_t const& rhs) noexcept
        -> bool
    {
        return lhs < rhs;
    }

    static constexpr auto compare(
        wchar_t const* lhs, wchar_t const* rhs, size_t count) -> int
    {
        if (count == 0) { return 0; }
        return etl::wmemcmp(lhs, rhs, count);
    }

    static constexpr auto length(wchar_t const* str) -> size_t
    {
        return etl::wcslen(str);
    }

    static constexpr auto find(wchar_t const* str, size_t count,
        wchar_t const& token) -> wchar_t const*
    {
        if (count == 0) { return nullptr; }
        return etl::wmemchr(str, token, count);
    }

    static constexpr auto move(wchar_t* dest, wchar_t const* src, size_t count)
        -> wchar_t*
    {
        if (count == 0) { return dest; }
        return etl::wmemmove(dest, src, count);
    }

    static constexpr auto copy(wchar_t* dest, wchar_t const* src, size_t count)
        -> wchar_t*
    {
        if (count == 0) { return dest; }
        return etl::wmemcpy(dest, src, count);
    }

    static constexpr auto assign(wchar_t* str, size_t count, wchar_t token)
        -> wchar_t*
    {
        if (count == 0) { return str; }
        return etl::wmemset(str, token, count);
    }

    static constexpr auto to_char_type(int_type const& ch) noexcept -> wchar_t
    {
        return static_cast<wchar_t>(ch);
    }

    static constexpr auto to_int_type(wchar_t const& ch) noexcept -> int_type
    {
        return static_cast<int_type>(ch);
    }

    static constexpr auto eq_int_type(
        int_type const& lhs, int_type const& rhs) noexcept -> bool
    {
        return lhs == rhs;
    }

    static constexpr auto eof() noexcept -> int_type
    {
        return static_cast<int_type>(WEOF);
    }

    static constexpr auto not_eof(int_type const& ch) noexcept -> int_type
    {
        return eq_int_type(ch, eof()) ? 0 : ch;
    }
};

} // namespace etl

#endif // TETL_STRING_CHAR_TRAITS_HPP