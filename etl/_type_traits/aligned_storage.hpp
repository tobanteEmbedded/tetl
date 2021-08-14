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

#ifndef TETL_TYPE_TRAITS_ALIGNED_STORAGE_HPP
#define TETL_TYPE_TRAITS_ALIGNED_STORAGE_HPP

#include "etl/_cstddef/max_align_t.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/conditional.hpp"

namespace etl {

namespace detail {
// With this change, types smaller then 16 bytes are aligned to their size. This
// equals the behavoir from libc++ and MSVC-STL. Copied from
// https://github.com/WG21-SG14/SG14/commit/98baf1aeab
// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=61458#c10
template <size_t Cap>
union aligned_storage_impl {
    template <typename T>
    using maybe = conditional_t<(Cap >= sizeof(T)), T, char>;

    struct double1 {
        double a;
    };
    struct double4 {
        double a[4];
    };

    char real_data[Cap];
    maybe<int> a;
    maybe<long> b;
    maybe<long long> c;
    maybe<void*> d;
    maybe<void (*)()> e;
    maybe<double1> f;
    maybe<double4> g;
    maybe<long double> h;
};
} // namespace detail

/// \brief Provides the nested type type, which is a trivial standard-layout
/// type suitable for use as uninitialized storage for any object whose size is
/// at most Len and whose alignment requirement is a divisor of Align.
/// The default value of Align is the most stringent (the largest)
/// alignment requirement for any object whose size is at most Len. If the
/// default value is not used, Align must be the value of alignof(T) for some
/// type T, or the behavior is undefined.
/// \group aligned_storage
template <size_t Len, size_t Align = alignof(detail::aligned_storage_impl<Len>)>
struct aligned_storage {
    struct type {
        alignas(Align) unsigned char data[Len];
    };
};

/// \group aligned_storage
template <size_t Len, size_t Align = alignof(detail::aligned_storage_impl<Len>)>
using aligned_storage_t = typename aligned_storage<Len, Align>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ALIGNED_STORAGE_HPP