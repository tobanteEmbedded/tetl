// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRING_CHAR_TRAITS_HPP
#define TETL_STRING_CHAR_TRAITS_HPP

#include <etl/_compare/strong_ordering.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_cstdint/uint_least_t.hpp>
#include <etl/_cwchar/wint_t.hpp>
#include <etl/_ios/typedefs.hpp>
#include <etl/_strings/cstr.hpp>

namespace etl {

namespace detail {

template <typename CharType, typename IntType, IntType Eof>
struct char_traits_base {
    using char_type           = CharType;
    using int_type            = IntType;
    using off_type            = etl::streamoff;
    using comparison_category = etl::strong_ordering;

    static constexpr auto assign(char_type& a, char_type const& b) noexcept -> void
    {
        a = b;
    }

    static constexpr auto eq(char_type a, char_type b) noexcept -> bool
    {
        return a == b;
    }

    static constexpr auto lt(char_type a, char_type b) noexcept -> bool
    {
        return a < b;
    }

    static constexpr auto compare(char_type const* lhs, char_type const* rhs, size_t count) -> int
    {
        if (count == 0) {
            return 0;
        }

        for (size_t i = 0; i < count; ++i) {
            if (lhs[i] < rhs[i]) {
                return -1;
            }
            if (lhs[i] > rhs[i]) {
                return 1;
            }
        }

        return 0;
    }

    static constexpr auto length(char_type const* str) -> size_t
    {
        return etl::detail::strlen<char_type, size_t>(str);
    }

    static constexpr auto find(char_type const* str, size_t count, char_type const& token) -> char_type const*
    {
        for (size_t i = 0; i < count; ++i) {
            if (str[i] == token) {
                return &str[i];
            }
        }

        return nullptr;
    }

    static constexpr auto move(char_type* dest, char_type const* source, size_t count) -> char_type*
    {
        for (size_t i = 0; i < count; ++i) {
            dest[i] = source[i];
        }
        return dest;
    }

    static constexpr auto copy(char_type* dest, char_type const* source, size_t count) -> char_type*
    {
        for (size_t i = 0; i < count; ++i) {
            assign(dest[i], source[i]);
        }
        return dest;
    }

    static constexpr auto assign(char_type* str, size_t count, char_type token) -> char_type*
    {
        for (size_t i = 0; i < count; ++i) {
            assign(str[i], token);
        }
        return str;
    }

    static constexpr auto to_char_type(int_type c) noexcept -> char_type
    {
        return static_cast<char_type>(c);
    }

    static constexpr auto to_int_type(char_type c) noexcept -> int_type
    {
        return static_cast<int_type>(c);
    }

    static constexpr auto eq_int_type(int_type lhs, int_type rhs) noexcept -> bool
    {
        if (lhs == rhs) {
            return true;
        }
        if (lhs == eof() and rhs == eof()) {
            return true;
        }
        if (lhs == eof() or rhs == eof()) {
            return false;
        }
        return false;
    }

    static constexpr auto eof() noexcept -> int_type
    {
        return Eof;
    }

    static constexpr auto not_eof(int_type c) noexcept -> int_type
    {
        return !eq_int_type(c, eof()) ? c : 0;
    }
};

} // namespace detail

/// The char_traits class is a traits class template that abstracts basic
/// character and string operations for a given character type.
///
/// The defined operation set is such that generic algorithms almost always can be
/// implemented in terms of it. It is thus possible to use such algorithms with
/// almost any possible character or string type, just by supplying a customized
/// char_traits class. The char_traits class template serves as a basis for
/// explicit instantiations. The user can provide a specialization for any
/// custom character types. Several specializations are defined for the standard
/// character types. If an operation on traits emits an exception, the behavior
/// is undefined.
///
/// \headerfile etl/string.hpp
/// \ingroup string
template <typename CharT>
struct char_traits;

/// Specializations of char_traits for type char.
/// \ingroup string
template <>
struct char_traits<char> : detail::char_traits_base<char, int, -1> { };

/// Specializations of char_traits for type wchar_t.
/// \ingroup string
template <>
struct char_traits<wchar_t> : detail::char_traits_base<wchar_t, wint_t, static_cast<wint_t>(WEOF)> { };

/// Specializations of char_traits for type char8_t.
/// \ingroup string
template <>
struct char_traits<char8_t> : detail::char_traits_base<char8_t, unsigned, static_cast<unsigned>(-1)> { };

/// Specializations of char_traits for type char16_t.
/// \ingroup string
template <>
struct char_traits<char16_t> : detail::char_traits_base<char16_t, uint_least16_t, uint_least16_t(0xFFFF)> { };

/// Specializations of char_traits for type char32_t.
/// \ingroup string
template <>
struct char_traits<char32_t> : detail::char_traits_base<char32_t, uint_least32_t, uint_least32_t(0xFFFFFFFF)> { };

} // namespace etl

#endif // TETL_STRING_CHAR_TRAITS_HPP
