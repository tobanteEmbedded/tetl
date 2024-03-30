// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_HPP
#define TETL_MEMORY_HPP

/// \defgroup memory memory
/// High-level memory management utilities
/// \ingroup dynamic-memory-library
/// \example memory.cpp

#include <etl/_config/all.hpp>

#include <etl/_memory/addressof.hpp>
#include <etl/_memory/align.hpp>
#include <etl/_memory/allocator_arg_t.hpp>
#include <etl/_memory/allocator_traits.hpp>
#include <etl/_memory/assume_aligned.hpp>
#include <etl/_memory/construct_at.hpp>
#include <etl/_memory/default_delete.hpp>
#include <etl/_memory/destroy.hpp>
#include <etl/_memory/destroy_at.hpp>
#include <etl/_memory/destroy_n.hpp>
#include <etl/_memory/pointer_like_traits.hpp>
#include <etl/_memory/pointer_traits.hpp>
#include <etl/_memory/ranges_construct_at.hpp>
#include <etl/_memory/ranges_destroy.hpp>
#include <etl/_memory/ranges_destroy_at.hpp>
#include <etl/_memory/to_address.hpp>
#include <etl/_memory/uninitialized_fill.hpp>
#include <etl/_memory/uses_allocator.hpp>

// Non-standard extensions
#include <etl/_memory/monotonic_allocator.hpp>
#include <etl/_memory/pointer_int_pair.hpp>
#include <etl/_memory/pointer_int_pair_info.hpp>
#include <etl/_memory/small_ptr.hpp>

#endif // TETL_MEMORY_HPP
