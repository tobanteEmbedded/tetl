// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_CONCEPTS_HPP
#define TETL_LINALG_CONCEPTS_HPP

#include <etl/_complex/abs.hpp>
#include <etl/_complex/complex.hpp>
#include <etl/_complex/conj.hpp>
#include <etl/_complex/imag.hpp>
#include <etl/_complex/real.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_concepts/unsigned_integral.hpp>
#include <etl/_math/abs.hpp>
#include <etl/_mdspan/layout.hpp>
#include <etl/_mdspan/layout_left.hpp>
#include <etl/_mdspan/layout_right.hpp>
#include <etl/_mdspan/mdspan.hpp>
#include <etl/_numeric/abs.hpp>
#include <etl/_type_traits/always_false.hpp>
#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/common_type.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/is_arithmetic.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_type_traits/remove_const.hpp>

namespace etl::linalg::detail {

template <typename T>
struct is_mdspan : false_type { };

template <typename T, typename Extents, typename Layout, typename Accessor>
struct is_mdspan<mdspan<T, Extents, Layout, Accessor>> : true_type { };

template <typename... Ts>
using common_size_type_t = common_type_t<typename Ts::size_type...>;

namespace linalg_adl_checks {

using etl::abs;
using etl::conj;
using etl::imag;
using etl::real;

template <typename T>
auto abs(T const&) -> T = delete;
template <typename T>
auto conj(T const&) -> T = delete;
template <typename T>
auto real(T const&) -> T = delete;
template <typename T>
auto imag(T const&) -> T = delete;

template <typename T>
concept has_abs = requires { abs(declval<T>()); };

template <typename T>
concept has_conj = requires { conj(declval<T>()); };

template <typename T>
concept has_real = requires { real(declval<T>()); };

template <typename T>
concept has_imag = requires { imag(declval<T>()); };

} // namespace linalg_adl_checks

template <typename T>
concept has_adl_abs = linalg_adl_checks::has_abs<T>;

template <typename T>
concept has_adl_conj = linalg_adl_checks::has_conj<T>;

template <typename T>
concept has_adl_real = linalg_adl_checks::has_real<T>;

template <typename T>
concept has_adl_imag = linalg_adl_checks::has_imag<T>;

inline constexpr auto abs_if_needed = []<typename T>(T const& val) {
    if constexpr (has_adl_abs<T>) {
        using etl::abs;
        return abs(val);
    } else {
        return val;
    }
};

inline constexpr auto conj_if_needed = []<typename T>(T const& val) {
    if constexpr (has_adl_conj<T>) {
        using etl::conj;
        return conj(val);
    } else {
        return val;
    }
};

inline constexpr auto real_if_needed = []<typename T>(T const& val) {
    if constexpr (has_adl_real<T>) {
        using etl::real;
        return real(val);
    } else {
        return val;
    }
};

inline constexpr auto imag_if_needed = []<typename T>(T const& val) {
    if constexpr (is_arithmetic_v<T>) {
        return val;
    } else if constexpr (has_adl_imag<T>) {
        using etl::imag;
        return imag(val);
    } else {
        return T {};
    }
};

} // namespace etl::linalg::detail

namespace etl::linalg {

template <typename T>
concept in_vector = detail::is_mdspan<T>::value && T::rank() == 1;

template <typename T>
concept out_vector
    = detail::is_mdspan<T>::value && T::rank() == 1
      && same_as<remove_const_t<typename T::element_type>, typename T::element_type> && T::is_always_unique();

template <typename T>
concept inout_vector
    = detail::is_mdspan<T>::value && T::rank() == 1
      && same_as<remove_const_t<typename T::element_type>, typename T::element_type> && T::is_always_unique();

template <typename T>
concept in_matrix = detail::is_mdspan<T>::value && T::rank() == 2;

template <typename T>
concept out_matrix
    = detail::is_mdspan<T>::value && T::rank() == 2
      && is_same_v<remove_const_t<typename T::element_type>, typename T::element_type> && T::is_always_unique();

template <typename T>
concept inout_matrix
    = detail::is_mdspan<T>::value && T::rank() == 2
      && is_same_v<remove_const_t<typename T::element_type>, typename T::element_type> && T::is_always_unique();

// template <typename T>
// concept possibly_packed_inout_matrix =
//     detail::is_mdspan<T>::value && T::rank() == 2 &&
//     is_same_v<remove_const_t<typename T::element_type>,
//                    typename T::element_type> &&
//     (T::is_always_unique() ||
//      is_same_v<typename T::layout_type, layout_blas_packed>);

template <typename T>
concept in_object = detail::is_mdspan<T>::value && (T::rank() == 1 || T::rank() == 2);

template <typename T>
concept out_object
    = detail::is_mdspan<T>::value && (T::rank() == 1 || T::rank() == 2)
      && is_same_v<remove_const_t<typename T::element_type>, typename T::element_type> && T::is_always_unique();

template <typename T>
concept inout_object
    = detail::is_mdspan<T>::value && (T::rank() == 1 || T::rank() == 2)
      && is_same_v<remove_const_t<typename T::element_type>, typename T::element_type> && T::is_always_unique();

} // namespace etl::linalg

#endif // TETL_LINALG_CONCEPTS_HPP
