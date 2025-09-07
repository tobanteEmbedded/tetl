// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ITERATOR_HPP
#define TETL_ITERATOR_HPP

/// \defgroup iterator iterator
/// Range iterators
/// \ingroup iterators-library

#include <etl/_config/all.hpp>

#include <etl/_iterator/advance.hpp>
#include <etl/_iterator/back_insert_iterator.hpp>
#include <etl/_iterator/begin.hpp>
#include <etl/_iterator/data.hpp>
#include <etl/_iterator/distance.hpp>
#include <etl/_iterator/empty.hpp>
#include <etl/_iterator/end.hpp>
#include <etl/_iterator/front_insert_iterator.hpp>
#include <etl/_iterator/incrementable.hpp>
#include <etl/_iterator/incrementable_traits.hpp>
#include <etl/_iterator/indirect_result_t.hpp>
#include <etl/_iterator/indirectly_readable.hpp>
#include <etl/_iterator/indirectly_readable_traits.hpp>
#include <etl/_iterator/indirectly_regular_unary_invocable.hpp>
#include <etl/_iterator/indirectly_unary_invocable.hpp>
#include <etl/_iterator/input_or_output_iterator.hpp>
#include <etl/_iterator/iter_common_reference_t.hpp>
#include <etl/_iterator/iter_difference_t.hpp>
#include <etl/_iterator/iter_reference_t.hpp>
#include <etl/_iterator/iter_rvalue_reference_t.hpp>
#include <etl/_iterator/iter_value_t.hpp>
#include <etl/_iterator/iterator_traits.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_iterator/prev.hpp>
#include <etl/_iterator/projected.hpp>
#include <etl/_iterator/ranges_iter_move.hpp>
#include <etl/_iterator/rbegin.hpp>
#include <etl/_iterator/rend.hpp>
#include <etl/_iterator/reverse_iterator.hpp>
#include <etl/_iterator/sentinel_for.hpp>
#include <etl/_iterator/size.hpp>
#include <etl/_iterator/tags.hpp>
#include <etl/_iterator/weakly_incrementable.hpp>

// Non-standard extensions
#include <etl/_iterator/full.hpp>
#include <etl/_iterator/legacy_bidirectional_iterator.hpp>
#include <etl/_iterator/legacy_forward_iterator.hpp>
#include <etl/_iterator/legacy_input_iterator.hpp>
#include <etl/_iterator/legacy_iterator.hpp>

#endif // TETL_ITERATOR_HPP
