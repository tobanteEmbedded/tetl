// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_ADD_CV_HPP
#define TETL_TYPE_TRAITS_ADD_CV_HPP

namespace etl {

/// \brief Provides the member typedef type which is the same as T, except it
/// has a cv-qualifier added (unless T is a function, a reference, or already
/// has this cv-qualifier). Adds both const and volatile.
///
/// \headerfile etl/type_traits.hpp
template <typename T>
struct add_cv {
    using type = T const volatile;
};

/// \relates add_cv
template <typename T>
using add_cv_t = typename add_cv<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_CV_HPP
