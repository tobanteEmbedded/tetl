// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_LINALG_EXPOSITION_HPP
#define TETL_LINALG_EXPOSITION_HPP

#include <etl/_complex/complex.hpp>
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

template <typename... Ts>
using common_index_type_t = common_type_t<typename Ts::index_type...>;

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
    if constexpr (unsigned_integral<T>) {
        return val;
    } else if constexpr (is_arithmetic_v<T>) {
        return etl::abs(val);
    } else if constexpr (has_adl_abs<T>) {
        return abs(val);
    } else {
        static_assert(always_false<T>);
    }
};

inline constexpr auto conj_if_needed = []<typename T>(T const& val) {
    if constexpr (not is_arithmetic_v<T> and has_adl_conj<T>) {
        return conj(val);
    } else {
        return val;
    }
};

inline constexpr auto real_if_needed = []<typename T>(T const& val) {
    if constexpr (not is_arithmetic_v<T> and has_adl_real<T>) {
        return real(val);
    } else {
        return val;
    }
};

inline constexpr auto imag_if_needed = []<typename T>(T const& val) {
    if constexpr (not is_arithmetic_v<T> and has_adl_imag<T>) {
        return imag(val);
    } else {
        return T{};
    }
};

} // namespace etl::linalg::detail

namespace etl::linalg {

/// \ingroup linalg
template <typename T>
concept in_vector = is_mdspan_v<T> and T::rank() == 1;

/// \ingroup linalg
template <typename T>
concept out_vector = is_mdspan_v<T>
                 and T::rank() == 1
                 and same_as<remove_const_t<typename T::element_type>, typename T::element_type>
                 and T::is_always_unique();

/// \ingroup linalg
template <typename T>
concept inout_vector = is_mdspan_v<T>
                   and T::rank() == 1
                   and same_as<remove_const_t<typename T::element_type>, typename T::element_type>
                   and T::is_always_unique();

/// \ingroup linalg
template <typename T>
concept in_matrix = is_mdspan_v<T> and T::rank() == 2;

/// \ingroup linalg
template <typename T>
concept out_matrix = is_mdspan_v<T>
                 and T::rank() == 2
                 and is_same_v<remove_const_t<typename T::element_type>, typename T::element_type>
                 and T::is_always_unique();

/// \ingroup linalg
template <typename T>
concept inout_matrix = is_mdspan_v<T>
                   and T::rank() == 2
                   and is_same_v<remove_const_t<typename T::element_type>, typename T::element_type>
                   and T::is_always_unique();

/// \ingroup linalg
template <typename T>
concept in_object = is_mdspan_v<T> and (T::rank() == 1 || T::rank() == 2);

/// \ingroup linalg
template <typename T>
concept out_object = is_mdspan_v<T>
                 and (T::rank() == 1 || T::rank() == 2)
                 and is_same_v<remove_const_t<typename T::element_type>, typename T::element_type>
                 and T::is_always_unique();

/// \ingroup linalg
template <typename T>
concept inout_object = is_mdspan_v<T>
                   and (T::rank() == 1 || T::rank() == 2)
                   and is_same_v<remove_const_t<typename T::element_type>, typename T::element_type>
                   and T::is_always_unique();

namespace detail {

template <typename MDS1, typename MDS2>
    requires(is_mdspan_v<MDS1> and is_mdspan_v<MDS2>)
[[nodiscard]] constexpr auto compatible_static_extents(etl::size_t r1, etl::size_t r2) -> bool
{
    return MDS1::static_extent(r1) == dynamic_extent
        or MDS2::static_extent(r2) == dynamic_extent
        or MDS1::static_extent(r1) == MDS2::static_extent(r2);
}

template <in_vector In1, in_vector In2, in_vector Out>
[[nodiscard]] constexpr auto possibly_addable() -> bool
{
    return compatible_static_extents<Out, In1>(0, 0)
       and compatible_static_extents<Out, In2>(0, 0)
       and compatible_static_extents<In1, In2>(0, 0);
}

template <in_matrix In1, in_matrix In2, in_matrix Out>
[[nodiscard]] constexpr auto possibly_addable() -> bool
{
    return compatible_static_extents<Out, In1>(0, 0)
       and compatible_static_extents<Out, In1>(1, 1)
       and compatible_static_extents<Out, In2>(0, 0)
       and compatible_static_extents<Out, In2>(1, 1)
       and compatible_static_extents<In1, In2>(0, 0)
       and compatible_static_extents<In1, In2>(1, 1);
}

template <in_matrix InMat, in_vector InVec, in_vector OutVec>
[[nodiscard]] constexpr auto possibly_multipliable() -> bool
{
    return compatible_static_extents<OutVec, InMat>(0, 0) and compatible_static_extents<InMat, InVec>(1, 0);
}

template <in_vector InVec, in_matrix InMat, in_vector OutVec>
[[nodiscard]] constexpr auto possibly_multipliable() -> bool
{
    return compatible_static_extents<OutVec, InMat>(0, 1) and compatible_static_extents<InMat, InVec>(0, 0);
}

template <in_matrix InMat1, in_matrix InMat2, in_matrix OutMat>
[[nodiscard]] constexpr auto possibly_multipliable() -> bool
{
    return compatible_static_extents<OutMat, InMat1>(0, 0)
       and compatible_static_extents<OutMat, InMat2>(1, 1)
       and compatible_static_extents<InMat1, InMat2>(1, 0);
}

[[nodiscard]] constexpr auto addable(in_vector auto const& in1, in_vector auto const& in2, in_vector auto const& out)
    -> bool
{
    return out.extent(0) == in1.extent(0) and out.extent(0) == in2.extent(0);
}

[[nodiscard]] constexpr auto addable(in_matrix auto const& in1, in_matrix auto const& in2, in_matrix auto const& out)
    -> bool
{
    return out.extent(0) == in1.extent(0)
       and out.extent(1) == in1.extent(1)
       and out.extent(0) == in2.extent(0)
       and out.extent(1) == in2.extent(1);
}

[[nodiscard]] constexpr auto
multipliable(in_matrix auto const& inMat, in_vector auto const& inVec, in_vector auto const& outVec) -> bool
{
    return outVec.extent(0) == inMat.extent(0) and inMat.extent(1) == inVec.extent(0);
}

[[nodiscard]] constexpr auto
multipliable(in_vector auto const& inVec, in_matrix auto const& inMat, in_vector auto const& outVec) -> bool
{
    return outVec.extent(0) == inMat.extent(1) and inMat.extent(0) == inVec.extent(0);
}

[[nodiscard]] constexpr auto
multipliable(in_matrix auto const& inMat1, in_matrix auto const& inMat2, in_matrix auto const& outMat) -> bool
{
    return outMat.extent(0) == inMat1.extent(0)
       and outMat.extent(1) == inMat2.extent(1)
       and inMat1.extent(1) == inMat2.extent(0);
}

} // namespace detail

} // namespace etl::linalg

#endif // TETL_LINALG_EXPOSITION_HPP
