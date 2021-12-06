/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_ADD_CV_HPP
#define TETL_TYPE_TRAITS_ADD_CV_HPP

namespace etl {

/// \group add_cv
template <typename T>
using add_cv_t = T const volatile;

/// \brief Provides the member typedef type which is the same as T, except it
/// has a cv-qualifier added (unless T is a function, a reference, or already
/// has this cv-qualifier). Adds both const and volatile.
/// \group add_cv
template <typename T>
struct add_cv {
    using type = add_cv_t<T>;
};

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_CV_HPP