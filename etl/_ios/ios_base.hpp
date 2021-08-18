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

#ifndef TETL_IOS_IOS_BASE_HPP
#define TETL_IOS_IOS_BASE_HPP

#include "etl/_bit/is_bitmask_type.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_cstdint/uint_t.hpp"
#include "etl/_ios/iosfwd.hpp"
#include "etl/_ios/typedefs.hpp"
#include "etl/_strings/char_traits.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/make_signed.hpp"
#include "etl/_utility/exchange.hpp"

namespace etl {

namespace detail {

enum struct seekdir_type : etl::uint16_t {
    beg = 1,
    end = 2,
    cur = 4,
};

enum struct openmode_type : etl::uint16_t {
    app    = 1,
    binary = 2,
    in     = 4,
    out    = 8,
    trunc  = 16,
    ate    = 32,
};

enum struct fmtflags_type : etl::uint16_t {
    dec       = 1,
    oct       = 2,
    hex       = 4,
    basefield = dec | oct | hex,

    left        = 8,
    right       = 16,
    internal    = 32,
    adjustfield = left | right | internal,

    scientific = 64,
    fixed      = 128,
    floatfield = scientific | fixed,

    boolalpha = 256,
    showbase  = 512,
    showpoint = 1024,
    showpos   = 2048,
    skipws    = 4096,
    unitbuf   = 8192,
    uppercase = 16384,

};

enum struct iostate_type : etl::uint16_t {
    goodbit = 0,
    badbit  = 1,
    failbit = 2,
    eofbit  = 4,
};

} // namespace detail

template <>
struct is_bitmask_type<detail::openmode_type> : true_type {
};
template <>
struct is_bitmask_type<detail::fmtflags_type> : true_type {
};
template <>
struct is_bitmask_type<detail::iostate_type> : true_type {
};

struct ios_base {
    using seekdir             = detail::seekdir_type;
    static constexpr auto beg = seekdir::beg;
    static constexpr auto end = seekdir::end;
    static constexpr auto cur = seekdir::cur;

    using openmode               = detail::openmode_type;
    static constexpr auto app    = openmode::app;
    static constexpr auto binary = openmode::binary;
    static constexpr auto in     = openmode::in;
    static constexpr auto out    = openmode::out;
    static constexpr auto trunc  = openmode::trunc;
    static constexpr auto ate    = openmode::ate;

    using fmtflags                    = detail::fmtflags_type;
    static constexpr auto dec         = fmtflags::dec;
    static constexpr auto oct         = fmtflags::oct;
    static constexpr auto hex         = fmtflags::hex;
    static constexpr auto basefield   = dec | oct | hex;
    static constexpr auto left        = fmtflags::left;
    static constexpr auto right       = fmtflags::right;
    static constexpr auto internal    = fmtflags::internal;
    static constexpr auto adjustfield = left | right | internal;
    static constexpr auto scientific  = fmtflags::scientific;
    static constexpr auto fixed       = fmtflags::fixed;
    static constexpr auto floatfield  = scientific | fixed;
    static constexpr auto boolalpha   = fmtflags::boolalpha;
    static constexpr auto showbase    = fmtflags::showbase;
    static constexpr auto showpoint   = fmtflags::showpoint;
    static constexpr auto showpos     = fmtflags::showpos;
    static constexpr auto skipws      = fmtflags::skipws;
    static constexpr auto unitbuf     = fmtflags::unitbuf;
    static constexpr auto uppercase   = fmtflags::uppercase;

    using iostate                 = detail::iostate_type;
    static constexpr auto goodbit = iostate::goodbit;
    static constexpr auto badbit  = iostate::badbit;
    static constexpr auto failbit = iostate::failbit;
    static constexpr auto eofbit  = iostate::eofbit;

    ios_base(ios_base const&) = delete;

    /// \brief Manages format flags. Returns current formatting setting.
    constexpr auto flags() const noexcept -> fmtflags { return fmtFlags_; }

    /// \brief Manages format flags. Replaces current settings with given ones.
    constexpr auto flags(fmtflags flags) noexcept -> fmtflags
    {
        return exchange(fmtFlags_, flags);
    }

    /// \brief Sets the formatting flags identified by flags.
    constexpr auto setf(fmtflags flags) noexcept -> fmtflags
    {
        return exchange(fmtFlags_, fmtFlags_ | flags);
    }

    /// \brief Clears the formatting flags under mask, and sets the cleared
    /// flags to those specified by flags.
    constexpr auto setf(fmtflags flags, fmtflags mask) noexcept -> fmtflags
    {
        return exchange(fmtFlags_, (fmtFlags_ & ~mask) | (flags & mask));
    }

    /// \brief Unsets the formatting flags identified by flags.
    constexpr auto unsetf(fmtflags flags) noexcept -> void
    {
        fmtFlags_ &= (~flags);
    }

    /// \brief Manages the precision (i.e. how many digits are generated) of
    /// floating point output performed by num_put::do_put. Returns the current
    /// precision.
    [[nodiscard]] constexpr auto precision() const noexcept -> streamsize
    {
        return precision_;
    }

    /// \brief Manages the precision (i.e. how many digits are generated) of
    /// floating point output performed by num_put::do_put. Sets the precision
    /// to the given one. Returns the previous precision.
    constexpr auto precision(streamsize newPrecision) noexcept -> streamsize
    {
        return exchange(precision_, newPrecision);
    }

    /// \brief Manages the minimum number of characters to generate on certain
    /// output operations and the maximum number of characters to generate on
    /// certain input operations. Returns the current width.
    [[nodiscard]] constexpr auto width() const noexcept -> streamsize
    {
        return width_;
    }

    /// \brief Manages the minimum number of characters to generate on certain
    /// output operations and the maximum number of characters to generate on
    /// certain input operations. Sets the width to the given one. Returns the
    /// previous width.
    constexpr auto width(streamsize newWidth) noexcept -> streamsize
    {
        return exchange(width_, newWidth);
    }

protected:
    ios_base() = default;

private:
    fmtflags fmtFlags_ {};
    streamsize precision_ { 6 };
    streamsize width_ { 0 };
};

} // namespace etl

#endif // TETL_IOS_IOS_BASE_HPP