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

#ifndef TETL_TYPETRAITS_HPP
#define TETL_TYPETRAITS_HPP

#include "etl/_config/all.hpp"

#include "etl/_type_traits/add_const.hpp"
#include "etl/_type_traits/add_cv.hpp"
#include "etl/_type_traits/add_lvalue_reference.hpp"
#include "etl/_type_traits/add_pointer.hpp"
#include "etl/_type_traits/add_rvalue_reference.hpp"
#include "etl/_type_traits/add_volatile.hpp"
#include "etl/_type_traits/aligned_storage.hpp"
#include "etl/_type_traits/aligned_union.hpp"
#include "etl/_type_traits/alignment_of.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/common_type.hpp"
#include "etl/_type_traits/conditional.hpp"
#include "etl/_type_traits/conjunction.hpp"
#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/disjunction.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/extent.hpp"
#include "etl/_type_traits/has_unique_object_representations.hpp"
#include "etl/_type_traits/has_virtual_destructor.hpp"
#include "etl/_type_traits/index_sequence.hpp"
#include "etl/_type_traits/integer_sequence.hpp"
#include "etl/_type_traits/invoke_result.hpp"
#include "etl/_type_traits/is_abstract.hpp"
#include "etl/_type_traits/is_aggregate.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"
#include "etl/_type_traits/is_array.hpp"
#include "etl/_type_traits/is_assignable.hpp"
#include "etl/_type_traits/is_base_of.hpp"
#include "etl/_type_traits/is_bounded_array.hpp"
#include "etl/_type_traits/is_class.hpp"
#include "etl/_type_traits/is_compound.hpp"
#include "etl/_type_traits/is_const.hpp"
#include "etl/_type_traits/is_constant_evaluated.hpp"
#include "etl/_type_traits/is_constructible.hpp"
#include "etl/_type_traits/is_convertible.hpp"
#include "etl/_type_traits/is_copy_assignable.hpp"
#include "etl/_type_traits/is_copy_constructible.hpp"
#include "etl/_type_traits/is_default_constructible.hpp"
#include "etl/_type_traits/is_destructible.hpp"
#include "etl/_type_traits/is_empty.hpp"
#include "etl/_type_traits/is_enum.hpp"
#include "etl/_type_traits/is_final.hpp"
#include "etl/_type_traits/is_floating_point.hpp"
#include "etl/_type_traits/is_function.hpp"
#include "etl/_type_traits/is_fundamental.hpp"
#include "etl/_type_traits/is_integral.hpp"
#include "etl/_type_traits/is_lvalue_reference.hpp"
#include "etl/_type_traits/is_member_function_pointer.hpp"
#include "etl/_type_traits/is_member_object_pointer.hpp"
#include "etl/_type_traits/is_member_pointer.hpp"
#include "etl/_type_traits/is_move_assignable.hpp"
#include "etl/_type_traits/is_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_assignable.hpp"
#include "etl/_type_traits/is_nothrow_constructible.hpp"
#include "etl/_type_traits/is_nothrow_copy_assignable.hpp"
#include "etl/_type_traits/is_nothrow_copy_constructible.hpp"
#include "etl/_type_traits/is_nothrow_default_constructible.hpp"
#include "etl/_type_traits/is_nothrow_destructible.hpp"
#include "etl/_type_traits/is_nothrow_move_assignable.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_swappable.hpp"
#include "etl/_type_traits/is_nothrow_swappable_with.hpp"
#include "etl/_type_traits/is_null_pointer.hpp"
#include "etl/_type_traits/is_object.hpp"
#include "etl/_type_traits/is_pointer.hpp"
#include "etl/_type_traits/is_polymorphic.hpp"
#include "etl/_type_traits/is_reference.hpp"
#include "etl/_type_traits/is_reference_wrapper.hpp"
#include "etl/_type_traits/is_rvalue_reference.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/is_scalar.hpp"
#include "etl/_type_traits/is_scoped_enum.hpp"
#include "etl/_type_traits/is_signed.hpp"
#include "etl/_type_traits/is_standard_layout.hpp"
#include "etl/_type_traits/is_swappable.hpp"
#include "etl/_type_traits/is_swappable_with.hpp"
#include "etl/_type_traits/is_trivial.hpp"
#include "etl/_type_traits/is_trivially_assignable.hpp"
#include "etl/_type_traits/is_trivially_constructible.hpp"
#include "etl/_type_traits/is_trivially_copy_assignable.hpp"
#include "etl/_type_traits/is_trivially_copy_constructible.hpp"
#include "etl/_type_traits/is_trivially_copyable.hpp"
#include "etl/_type_traits/is_trivially_default_constructible.hpp"
#include "etl/_type_traits/is_trivially_destructible.hpp"
#include "etl/_type_traits/is_trivially_move_assignable.hpp"
#include "etl/_type_traits/is_trivially_move_constructible.hpp"
#include "etl/_type_traits/is_unbounded_array.hpp"
#include "etl/_type_traits/is_union.hpp"
#include "etl/_type_traits/is_unsigned.hpp"
#include "etl/_type_traits/is_void.hpp"
#include "etl/_type_traits/is_volatile.hpp"
#include "etl/_type_traits/make_signed.hpp"
#include "etl/_type_traits/make_unsigned.hpp"
#include "etl/_type_traits/meta.hpp"
#include "etl/_type_traits/negation.hpp"
#include "etl/_type_traits/rank.hpp"
#include "etl/_type_traits/remove_all_extents.hpp"
#include "etl/_type_traits/remove_const.hpp"
#include "etl/_type_traits/remove_cv.hpp"
#include "etl/_type_traits/remove_cvref.hpp"
#include "etl/_type_traits/remove_extent.hpp"
#include "etl/_type_traits/remove_pointer.hpp"
#include "etl/_type_traits/remove_reference.hpp"
#include "etl/_type_traits/remove_volatile.hpp"
#include "etl/_type_traits/type_identity.hpp"
#include "etl/_type_traits/underlying_type.hpp"
#include "etl/_type_traits/void_t.hpp"

// Also include swap, because it's declaration is visible anyway (needed by
// is_swappable and friends) and auto-complete will detect it, but the
// definition would be missing and it would not compile. Leading to a bad user
// experience.
#include "etl/_utility/swap.hpp"

#endif // TETL_TYPETRAITS_HPP