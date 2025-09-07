// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_FORMAT_FORMAT_ARG_STORE_HPP
#define TETL_FORMAT_FORMAT_ARG_STORE_HPP

#include <etl/_array/array.hpp>
#include <etl/_format/basic_format_arg.hpp>

namespace etl::detail {

template <typename Context, typename... Args>
struct format_arg_store {
    array<basic_format_arg<Context>, sizeof...(Args)> args;
};

} // namespace etl::detail

#endif // TETL_FORMAT_FORMAT_ARG_STORE_HPP
