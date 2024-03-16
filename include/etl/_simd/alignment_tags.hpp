// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_SIMD_ALIGNMENT_TAGS_HPP
#define TETL_SIMD_ALIGNMENT_TAGS_HPP

#include <etl/_cstddef/size_t.hpp>

namespace etl {

struct element_aligned_tag { };

inline constexpr element_aligned_tag element_aligned{};

struct vector_aligned_tag { };

inline constexpr vector_aligned_tag vector_aligned{};

template <size_t>
struct overaligned_tag { };

template <size_t N>
inline constexpr overaligned_tag<N> overaligned{};

} // namespace etl

#endif // TETL_SIMD_ALIGNMENT_TAGS_HPP
