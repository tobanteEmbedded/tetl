// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_ITERATOR_INDIRECT_RESULT_T_HPP
#define TETL_ITERATOR_INDIRECT_RESULT_T_HPP

#include <etl/_concepts/invocable.hpp>
#include <etl/_iterator/indirectly_readable.hpp>
#include <etl/_iterator/iter_reference_t.hpp>
#include <etl/_type_traits/invoke_result.hpp>

namespace etl {

/// \ingroup iterator
template <typename F, typename... Iters>
    requires(etl::indirectly_readable<Iters> and ...) and etl::invocable<F, etl::iter_reference_t<Iters>...>
using indirect_result_t = etl::invoke_result_t<F, etl::iter_reference_t<Iters>...>;

} // namespace etl

#endif // TETL_ITERATOR_INDIRECT_RESULT_T_HPP
