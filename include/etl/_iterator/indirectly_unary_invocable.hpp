// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_ITERATOR_INDIRECTLY_UNARY_INVOCABLE_HPP
#define TETL_ITERATOR_INDIRECTLY_UNARY_INVOCABLE_HPP

#include <etl/_concepts/common_reference_with.hpp>
#include <etl/_concepts/copy_constructible.hpp>
#include <etl/_concepts/invocable.hpp>
#include <etl/_iterator/indirectly_readable.hpp>
#include <etl/_iterator/iter_common_reference_t.hpp>
#include <etl/_iterator/iter_reference_t.hpp>
#include <etl/_iterator/iter_value_t.hpp>
#include <etl/_type_traits/invoke_result.hpp>

namespace etl {

template <typename F, typename Iter>
concept indirectly_unary_invocable = etl::indirectly_readable<Iter>
                                 and etl::copy_constructible<F>
                                 and etl::invocable<F&, etl::iter_value_t<Iter>&>
                                 and etl::invocable<F&, etl::iter_reference_t<Iter>>
                                 and etl::invocable<F&, etl::iter_common_reference_t<Iter>>
                                 and etl::common_reference_with<
                                         etl::invoke_result_t<F&, etl::iter_value_t<Iter>&>,
                                         etl::invoke_result_t<F&, etl::iter_reference_t<Iter>>
                                 >;

} // namespace etl

#endif // TETL_ITERATOR_INDIRECTLY_UNARY_INVOCABLE_HPP
