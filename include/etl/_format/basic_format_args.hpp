// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FORMAT_BASIC_FORMAT_ARGS_HPP
#define TETL_FORMAT_BASIC_FORMAT_ARGS_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_format/basic_format_arg.hpp>
#include <etl/_format/basic_format_context.hpp>
#include <etl/_format/format_arg_store.hpp>
#include <etl/_span/span.hpp>

namespace etl {

template <typename Context>
struct basic_format_args {
    constexpr basic_format_args() noexcept = default;

    template <typename... Args>
    constexpr basic_format_args(detail::format_arg_store<Context, Args...> const& store) noexcept : args_ { store.args }
    {
    }

    [[nodiscard]] constexpr auto get(size_t i) const noexcept -> basic_format_arg<Context>
    {
        if (i >= args_.size()) { return basic_format_arg<Context> {}; }
        return args_[i];
    }

private:
    span<basic_format_arg<Context> const> args_;
};

using format_args  = basic_format_args<format_context>;
using wformat_args = basic_format_args<wformat_context>;

} // namespace etl

#endif // TETL_FORMAT_BASIC_FORMAT_ARGS_HPP
