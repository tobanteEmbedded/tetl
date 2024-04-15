// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTRING_ALGORITHM_HPP
#define TETL_CSTRING_ALGORITHM_HPP

namespace etl::detail {

template <typename CharT>
[[nodiscard]] constexpr auto strcpy(CharT* dest, CharT const* src) -> CharT*
{
    auto* temp = dest;
    while ((*dest++ = *src++) != CharT(0)) { }
    return temp;
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strncpy(CharT* dest, CharT const* src, SizeT count) -> CharT*
{
    auto* temp = dest;
    for (SizeT counter = 0; *src != CharT(0) && counter != count;) {
        *dest = *src;
        ++src;
        ++dest;
        ++counter;
    }

    return temp;
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strlen(CharT const* str) -> SizeT
{
    CharT const* s = nullptr;
    for (s = str; *s != CharT(0); ++s) { }
    return static_cast<SizeT>(s - str);
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strcat(CharT* dest, CharT const* src) -> CharT*
{
    auto* ptr = dest + strlen<CharT, SizeT>(dest);
    while (*src != CharT(0)) {
        *ptr++ = *src++;
    }
    *ptr = CharT(0);
    return dest;
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strncat(CharT* dest, CharT const* src, SizeT const count) -> CharT*
{
    auto* ptr          = dest + strlen<CharT, SizeT>(dest);
    SizeT localCounter = 0;
    while (*src != CharT(0) && localCounter != count) {
        *ptr++ = *src++;
        ++localCounter;
    }

    *ptr = CharT(0);
    return dest;
}

template <typename CharT>
[[nodiscard]] constexpr auto strcmp(CharT const* lhs, CharT const* rhs) -> int
{
    for (; *lhs != CharT(0); ++lhs, ++rhs) {
        if (*lhs != *rhs) {
            break;
        }
    }
    return static_cast<int>(*lhs) - static_cast<int>(*rhs);
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strncmp(CharT const* lhs, CharT const* rhs, SizeT const count) -> int
{
    CharT u1{};
    CharT u2{};

    auto localCount = count;
    while (localCount-- > 0) {
        u1 = static_cast<CharT>(*lhs++);
        u2 = static_cast<CharT>(*rhs++);
        if (u1 != u2) {
            return static_cast<int>(u1 - u2);
        }
        if (u1 == CharT(0)) {
            return 0;
        }
    }

    return 0;
}

template <typename CharT>
[[nodiscard]] constexpr auto strchr(CharT* str, int ch) -> CharT*
{
    while (*str != CharT(0)) {
        if (*str == static_cast<CharT>(ch)) {
            return str;
        }
        ++str;
    }

    if (static_cast<CharT>(ch) == CharT(0)) {
        return str;
    }
    return nullptr;
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strrchr(CharT* str, int ch) -> CharT*
{
    if (str == nullptr) {
        return nullptr;
    }
    auto len = strlen<CharT, SizeT>(str);
    if (static_cast<CharT>(ch) == CharT(0)) {
        return str + len;
    }

    while (len-- != 0) {
        if (str[len] == static_cast<CharT>(ch)) {
            return str + len;
        }
    }

    return nullptr;
}

template <typename CharT, typename SizeT, bool InclusiveSearch>
[[nodiscard]] constexpr auto is_legal_char(CharT const* options, SizeT len, CharT ch) noexcept -> bool
{
    for (SizeT i = 0; i < len; ++i) {
        if (options[i] == ch) {
            return InclusiveSearch;
        }
    }
    return !InclusiveSearch;
}

template <typename CharT, typename SizeT, bool InclusiveSearch>
[[nodiscard]] constexpr auto strspn(CharT const* dest, CharT const* src) noexcept -> SizeT
{
    auto result       = SizeT{0};
    auto const length = strlen<CharT, SizeT>(dest);
    auto const srcLen = strlen<CharT, SizeT>(src);
    for (SizeT i = 0; i < length; ++i) {
        if (!is_legal_char<CharT, SizeT, InclusiveSearch>(src, srcLen, dest[i])) {
            break;
        }
        ++result;
    }

    return result;
}

template <typename CharT, typename SizeT>
[[nodiscard]] constexpr auto strpbrk_impl(CharT* s, CharT* del) noexcept -> CharT*
{
    auto const i = strspn<CharT, SizeT, false>(s, del);
    if (i != 0) {
        return s + i;
    }
    if (is_legal_char<CharT, SizeT, true>(del, strlen<CharT, SizeT>(del), s[0])) {
        return s;
    }
    return nullptr;
}

template <typename CharT>
[[nodiscard]] constexpr auto strstr_impl(CharT* haystack, CharT* needle) noexcept -> CharT*
{
    while (*haystack != CharT(0)) {
        if ((*haystack == *needle) && (strcmp(haystack, needle) == 0)) {
            return haystack;
        }
        haystack++;
    }
    return nullptr;
}

template <typename CharT, typename SizeT>
constexpr auto memcpy(void* dest, void const* src, SizeT n) -> void*
{
    auto* dp       = static_cast<CharT*>(dest);
    auto const* sp = static_cast<CharT const*>(src);
    while (n-- != CharT(0)) {
        *dp++ = *sp++;
    }
    return dest;
}

template <typename CharT, typename ValT, typename SizeT>
constexpr auto memset(CharT* const s, ValT const c, SizeT n) -> CharT*
{
    auto* p = s;
    while (n-- != CharT(0)) {
        *p++ = static_cast<CharT>(c);
    }
    return s;
}

// Check original implementation. They use `__np_anyptrlt` which is not
// portable. https://clc-wiki.net/wiki/C_standard_library:string.h:memmove
template <typename CharT, typename SizeT>
constexpr auto memmove(void* dest, void const* src, SizeT n) -> CharT*
{
    auto const* ps = static_cast<CharT const*>(src);
    auto* pd       = static_cast<CharT*>(dest);

    if (ps < pd) {
        for (pd += n, ps += n; n-- != CharT(0);) {
            *--pd = *--ps;
        }
    } else {
        while (n-- != CharT(0)) {
            *pd++ = *ps++;
        }
    }

    return static_cast<CharT*>(dest);
}

template <typename CharT, typename SizeT>
constexpr auto memchr(CharT* ptr, CharT ch, SizeT n) -> CharT*
{
    for (SizeT i{0}; i != n; ++i) {
        if (ptr[i] == ch) {
            return ptr + i;
        }
    }
    return nullptr;
}

} // namespace etl::detail

#endif // TETL_CSTRING_ALGORITHM_HPP
