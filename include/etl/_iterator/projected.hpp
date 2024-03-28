// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_PROJECTED_HPP
#define TETL_ITERATOR_PROJECTED_HPP

#include <etl/_iterator/indirect_result_t.hpp>
#include <etl/_iterator/indirectly_readable.hpp>
#include <etl/_iterator/indirectly_regular_unary_invocable.hpp>
#include <etl/_iterator/iter_difference_t.hpp>
#include <etl/_iterator/weakly_incrementable.hpp>
#include <etl/_type_traits/remove_cvref.hpp>

namespace etl {

namespace detail {

template <typename I, typename Proj>
struct projected_impl {
    struct type {
        using value_type = etl::remove_cvref_t<etl::indirect_result_t<Proj&, I>>;
        auto operator*() const -> etl::indirect_result_t<Proj&, I>; // not defined
    };
};

template <typename I, typename Proj>
    requires weakly_incrementable<I>
struct projected_impl<I, Proj> {
    struct type {
        using value_type      = etl::remove_cvref_t<etl::indirect_result_t<Proj&, I>>;
        using difference_type = etl::iter_difference_t<I>; // conditionally present

        auto operator*() const -> etl::indirect_result_t<Proj&, I>; // not defined
    };
};

} // namespace detail

template <etl::indirectly_readable I, etl::indirectly_regular_unary_invocable<I> Proj>
using projected = etl::detail::projected_impl<I, Proj>::type;

} // namespace etl

#endif // TETL_ITERATOR_PROJECTED_HPP
