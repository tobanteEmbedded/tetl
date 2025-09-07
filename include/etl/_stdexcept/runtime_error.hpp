// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_STDEXCEPT_RUNTIME_ERROR_HPP
#define TETL_STDEXCEPT_RUNTIME_ERROR_HPP

#include <etl/_exception/exception.hpp>

namespace etl {

struct runtime_error : exception {
    constexpr runtime_error() = default;

    constexpr explicit runtime_error(char const* what)
        : exception{what}
    {
    }
};

} // namespace etl

#endif // TETL_STDEXCEPT_RUNTIME_ERROR_HPP
