// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_HASH_HPP
#define TETL_FUNCTIONAL_HASH_HPP

#include "etl/_bit/bit_cast.hpp"
#include "etl/_cstddef/nullptr_t.hpp"
#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief hash
template <typename T>
struct hash;

template <>
struct hash<bool> {
    [[nodiscard]] constexpr auto operator()(bool val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<char> {
    [[nodiscard]] constexpr auto operator()(char val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<signed char> {
    [[nodiscard]] constexpr auto operator()(signed char val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<unsigned char> {
    [[nodiscard]] constexpr auto operator()(unsigned char val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};

#if defined(__cpp_char8_t)
template <>
struct hash<char8_t> {
    [[nodiscard]] constexpr auto operator()(char8_t val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
#endif

template <>
struct hash<char16_t> {
    [[nodiscard]] constexpr auto operator()(char16_t val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<char32_t> {
    [[nodiscard]] constexpr auto operator()(char32_t val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<wchar_t> {
    [[nodiscard]] constexpr auto operator()(wchar_t val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<short> {
    [[nodiscard]] constexpr auto operator()(short val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<unsigned short> {
    [[nodiscard]] constexpr auto operator()(unsigned short val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<int> {
    [[nodiscard]] constexpr auto operator()(int val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<unsigned int> {
    [[nodiscard]] constexpr auto operator()(unsigned int val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<long> {
    [[nodiscard]] constexpr auto operator()(long val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<long long> {
    [[nodiscard]] constexpr auto operator()(long long val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<unsigned long> {
    [[nodiscard]] constexpr auto operator()(unsigned long val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<unsigned long long> {
    [[nodiscard]] constexpr auto operator()(unsigned long long val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<float> {
    [[nodiscard]] constexpr auto operator()(float val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<double> {
    [[nodiscard]] constexpr auto operator()(double val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
template <>
struct hash<long double> {
    [[nodiscard]] constexpr auto operator()(long double val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};

template <>
struct hash<etl::nullptr_t> {
    [[nodiscard]] constexpr auto operator()(nullptr_t /*unused*/) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(0);
    }
};

template <typename T>
struct hash<T*> {
    [[nodiscard]] auto operator()(T* val) const noexcept -> etl::size_t { return etl::bit_cast<etl::size_t>(val); }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_HASH_HPP
