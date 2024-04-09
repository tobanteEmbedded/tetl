// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_REMOVE_CV_HPP
#define TETL_TYPE_TRAITS_REMOVE_CV_HPP

#include <etl/_type_traits/remove_const.hpp>
#include <etl/_type_traits/remove_volatile.hpp>

namespace etl {

/// \brief Provides the member typedef type which is the same as T, except that
/// its topmost cv-qualifiers are removed. Removes the topmost const, or the
/// topmost volatile, or both, if present.
/// \details The behavior of a program that adds specializations for any of the
/// templates described on this page is undefined.
template <typename T>
struct remove_cv {
    using type = remove_const_t<remove_volatile_t<T>>;
};

template <typename T>
using remove_cv_t = remove_const_t<remove_volatile_t<T>>;

} // namespace etl

#endif // TETL_TYPE_TRAITS_REMOVE_CV_HPP
