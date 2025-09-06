// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_ALGORITHM_RANGES_IN_FUN_RESULT_HPP
#define TETL_ALGORITHM_RANGES_IN_FUN_RESULT_HPP

#include <etl/_config/all.hpp>

#include <etl/_concepts/convertible_to.hpp>
#include <etl/_utility/move.hpp>

namespace etl::ranges {

/// \ingroup algorithm
template <typename I, typename F>
struct in_fun_result {
    template <typename I2, typename F2>
        requires etl::convertible_to<I const&, I2> and etl::convertible_to<F const&, F2>
    constexpr operator in_fun_result<I2, F2>() const&
    {
        return {in, fun};
    }

    template <typename I2, typename F2>
        requires etl::convertible_to<I, I2> and etl::convertible_to<F, F2>
    constexpr operator in_fun_result<I2, F2>() &&
    {
        return {etl::move(in), etl::move(fun)};
    }

    TETL_NO_UNIQUE_ADDRESS I in;
    TETL_NO_UNIQUE_ADDRESS F fun;
};

} // namespace etl::ranges

#endif // TETL_ALGORITHM_RANGES_IN_FUN_RESULT_HPP
