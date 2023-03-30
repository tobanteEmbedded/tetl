// SPDX-License-Identifier: BSL-1.0

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
template <etl::size_t Cap>
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
template <etl::size_t Len, etl::size_t Align = alignof(detail::aligned_storage_impl<Len>)>
struct aligned_storage {
    struct type {
        alignas(Align) unsigned char data[Len];
    };
};

template <etl::size_t Len, etl::size_t Align = alignof(detail::aligned_storage_impl<Len>)>
using aligned_storage_t = typename etl::aligned_storage<Len, Align>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ALIGNED_STORAGE_HPP
