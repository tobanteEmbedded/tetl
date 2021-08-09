// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_DETAIL_STRINGS_CHAR_TRAITS_HPP
#define TETL_DETAIL_STRINGS_CHAR_TRAITS_HPP

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

    // using off_type            = streamoff;
    // using pos_type            = streampos;
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
        return etl::strlen(str);
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
        return int_type { static_cast<uint8_t>(c) };
    }

    /// \brief Checks whether two values of type int_type are equal.
    ///
    /// \notes
    /// [cppreference.com/w/cpp/string/char_traits/eq_int_type](https://en.cppreference.com/w/cpp/string/char_traits/eq_int_type)
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

} // namespace etl

#endif // TETL_DETAIL_STRINGS_CHAR_TRAITS_HPP