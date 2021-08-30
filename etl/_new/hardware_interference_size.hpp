/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_NEW_HARDWARE_INTERFERENCE_SIZE_HPP
#define TETL_NEW_HARDWARE_INTERFERENCE_SIZE_HPP

#include "etl/_cstddef/max_align_t.hpp"

/// Cache line sizes for ARM values are not strictly correct since cache
/// line sizes depend on implementations, not architectures.  There are even
/// implementations with cache line sizes configurable at boot time.
#if defined(__aarch64__)
    #define TETL_CACHELINE_SIZE 64
#elif defined(__ARM_ARCH_5T__)
    #define TETL_CACHELINE_SIZE 32
#elif defined(__ARM_ARCH_7A__)
    #define TETL_CACHELINE_SIZE 64
#elif defined(__PPC64__)
    #define TETL_CACHELINE_SIZE 128
#elif defined(__i386__) || defined(__x86_64__)
    #define TETL_CACHELINE_SIZE 64
#else
    #define TETL_CACHELINE_SIZE alignof(max_align_t)
#endif

namespace etl {

/// \brief Minimum offset between two objects to avoid false sharing. Guaranteed
/// to be at least alignof(max_align_t).
constexpr auto hardware_constructive_interference_size = TETL_CACHELINE_SIZE;

/// \brief Maximum size of contiguous memory to promote true sharing. Guaranteed
/// to be at least alignof(max_align_t).
constexpr auto hardware_destructive_interference_size = TETL_CACHELINE_SIZE;

} // namespace etl

#endif // TETL_NEW_HARDWARE_INTERFERENCE_SIZE_HPP