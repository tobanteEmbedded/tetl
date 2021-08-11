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

#ifndef TETL_NEW_HARDWARE_INTERFERENCE_SIZE_HPP
#define TETL_NEW_HARDWARE_INTERFERENCE_SIZE_HPP

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