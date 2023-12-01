// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FORMAT_FMT_BUFFER_HPP
#define TETL_FORMAT_FMT_BUFFER_HPP

#include <etl/_format/basic_format_context.hpp>
#include <etl/_format/format_arg_store.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_utility/forward.hpp>

namespace etl::detail {

template <typename CharType>
struct fmt_buffer {
    using value_type = CharType;

    template <typename It>
    fmt_buffer(It out) noexcept
        : it_ { addressof(out) }, pushBack_ { [](void* ptr, CharType ch) { (*static_cast<It*>(ptr)) = ch; } }
    {
    }

    auto push_back(CharType ch) -> void { (pushBack_)(it_, ch); }

private:
    using push_back_func_t = void (*)(void*, CharType);

    void* it_;
    push_back_func_t pushBack_;
};

} // namespace etl::detail

#endif // TETL_FORMAT_FMT_BUFFER_HPP
