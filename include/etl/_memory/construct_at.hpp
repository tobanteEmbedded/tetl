// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_CONSTRUCT_AT_HPP
#define TETL_MEMORY_CONSTRUCT_AT_HPP

#include <etl/_config/all.hpp>

#include <etl/_new/operator.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_utility/forward.hpp>

#if __has_include(<memory>)
    // TODO: Only include private header that defines construct_at from each STL
    // STL = https://github.com/microsoft/STL/blob/main/stl/inc/xutility
    // libc++ = https://github.com/llvm/llvm-project/blob/main/libcxx/include/__memory/construct_at.h
    // libstdc++ = https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/include/bits/stl_construct.h
    #include <memory>
#else
// NOLINTBEGIN

namespace std {

template <typename T, typename... Args, typename = decltype(::new (etl::declval<void*>()) T(etl::declval<Args>()...))>
constexpr auto construct_at(T* p, Args&&... args) -> T*
{
    return ::new (static_cast<void*>(p)) T(etl::forward<Args>(args)...);
}

} // namespace std

// NOLINTEND
#endif

namespace etl {

/// \brief Creates a T object initialized with arguments args... at given address p.
template <typename T, typename... Args, typename = decltype(::new (etl::declval<void*>()) T(etl::declval<Args>()...))>
constexpr auto construct_at(T* p, Args&&... args) -> T*
{
    return ::std::construct_at(p, etl::forward<Args>(args)...);
}

} // namespace etl

#endif // TETL_MEMORY_CONSTRUCT_AT_HPP
