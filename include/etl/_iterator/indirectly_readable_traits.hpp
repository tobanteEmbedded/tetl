// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_INDIRECT_READABLE_TRAITS_HPP
#define TETL_ITERATOR_INDIRECT_READABLE_TRAITS_HPP

#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/is_array.hpp>
#include <etl/_type_traits/is_object.hpp>
#include <etl/_type_traits/remove_cv.hpp>
#include <etl/_type_traits/remove_extent.hpp>

namespace etl {

namespace detail {

template <typename>
struct maybe_value_type { };

template <typename T>
    requires etl::is_object_v<T>
struct maybe_value_type<T> {
    using value_type = etl::remove_cv_t<T>;
};

template <typename T>
concept has_member_value_type = requires { typename T::value_type; };

template <typename T>
concept has_member_element_type = requires { typename T::element_type; };

} // namespace detail

template <typename I>
struct indirectly_readable_traits { };

template <typename T>
struct indirectly_readable_traits<T const> : indirectly_readable_traits<T> { };

template <typename T>
struct indirectly_readable_traits<T*> : detail::maybe_value_type<T> { };

template <typename I>
    requires etl::is_array_v<I>
struct indirectly_readable_traits<I> {
    using value_type = etl::remove_cv_t<etl::remove_extent_t<I>>;
};

template <detail::has_member_value_type T>
struct indirectly_readable_traits<T> : detail::maybe_value_type<typename T::value_type> { };

template <detail::has_member_element_type T>
struct indirectly_readable_traits<T> : detail::maybe_value_type<typename T::element_type> { };

template <detail::has_member_value_type T>
    requires detail::has_member_element_type<T>
struct indirectly_readable_traits<T> { };

template <detail::has_member_value_type T>
    requires(detail::has_member_element_type<T>
             and etl::same_as<etl::remove_cv_t<typename T::element_type>, etl::remove_cv_t<typename T::value_type>>)
struct indirectly_readable_traits<T> : detail::maybe_value_type<typename T::value_type> { };

} // namespace etl

#endif // TETL_ITERATOR_INDIRECT_READABLE_TRAITS_HPP
