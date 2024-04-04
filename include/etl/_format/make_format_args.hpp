// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FORMAT_MAKE_FORMAT_ARGS_HPP
#define TETL_FORMAT_MAKE_FORMAT_ARGS_HPP

#include <etl/_format/basic_format_context.hpp>
#include <etl/_format/format_arg_store.hpp>
#include <etl/_utility/forward.hpp>

namespace etl {

template <typename Context = etl::format_context, typename... Args>
auto make_format_args(Args&&... args) -> detail::format_arg_store<Context, Args...>
{
    return {etl::forward<Args>(args)...};
}

template <typename... Args>
auto make_wformat_args(Args&&... args) -> detail::format_arg_store<wformat_context, Args...>
{
    return {etl::forward<Args>(args)...};
}

} // namespace etl

#endif // TETL_FORMAT_MAKE_FORMAT_ARGS_HPP
