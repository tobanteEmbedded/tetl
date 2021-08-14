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

#ifndef TETL_FUNCTIONAL_HASH_HPP
#define TETL_FUNCTIONAL_HASH_HPP

#include "etl/_bit/bit_cast.hpp"
#include "etl/_cstddef/nullptr_t.hpp"
#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief hash
/// \group hash
/// \module Utility
template <typename T>
struct hash;

/// \group hash
/// \module Utility
template <>
struct hash<bool> {
    [[nodiscard]] constexpr auto operator()(bool val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<char> {
    [[nodiscard]] constexpr auto operator()(char val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<signed char> {
    [[nodiscard]] constexpr auto operator()(signed char val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<unsigned char> {
    [[nodiscard]] constexpr auto operator()(unsigned char val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<char16_t> {
    [[nodiscard]] constexpr auto operator()(char16_t val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<char32_t> {
    [[nodiscard]] constexpr auto operator()(char32_t val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<wchar_t> {
    [[nodiscard]] constexpr auto operator()(wchar_t val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<short> {
    [[nodiscard]] constexpr auto operator()(short val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<unsigned short> {
    [[nodiscard]] constexpr auto operator()(unsigned short val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<int> {
    [[nodiscard]] constexpr auto operator()(int val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<unsigned int> {
    [[nodiscard]] constexpr auto operator()(unsigned int val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<long> {
    [[nodiscard]] constexpr auto operator()(long val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<long long> {
    [[nodiscard]] constexpr auto operator()(long long val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<unsigned long> {
    [[nodiscard]] constexpr auto operator()(unsigned long val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<unsigned long long> {
    [[nodiscard]] constexpr auto operator()(
        unsigned long long val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<float> {
    [[nodiscard]] constexpr auto operator()(float val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<double> {
    [[nodiscard]] constexpr auto operator()(double val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<long double> {
    [[nodiscard]] constexpr auto operator()(long double val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};

/// \group hash
/// \module Utility
template <>
struct hash<etl::nullptr_t> {
    [[nodiscard]] auto operator()(nullptr_t /*unused*/) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(0);
    }
};

/// \group hash
/// \module Utility
template <typename T>
struct hash<T*> {
    [[nodiscard]] auto operator()(T* val) const noexcept -> etl::size_t
    {
        return etl::bit_cast<etl::size_t>(val);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_HASH_HPP