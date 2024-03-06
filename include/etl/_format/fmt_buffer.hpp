// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FORMAT_FMT_BUFFER_HPP
#define TETL_FORMAT_FMT_BUFFER_HPP

#include <etl/_format/format_arg_store.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_utility/forward.hpp>

namespace etl::detail {

template <typename CharType>
struct fmt_buffer {
    using value_type = CharType;

    template <typename It>
    fmt_buffer(It out) noexcept
        : _it {addressof(out)}, _pushBack {[](void* ptr, CharType ch) { (*static_cast<It*>(ptr)) = ch; }}
    {
    }

    auto push_back(CharType ch) -> void { (_pushBack)(_it, ch); }

private:
    using push_back_func_t = void (*)(void*, CharType);

    void* _it;
    push_back_func_t _pushBack;
};

} // namespace etl::detail

#endif // TETL_FORMAT_FMT_BUFFER_HPP
