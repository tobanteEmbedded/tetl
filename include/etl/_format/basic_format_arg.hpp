/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FORMAT_BASIC_FORMAT_ARG_HPP
#define TETL_FORMAT_BASIC_FORMAT_ARG_HPP

#include <etl/_cstddef/nullptr_t.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_format/basic_format_parse_context.hpp>
#include <etl/_string/basic_static_string.hpp>
#include <etl/_string_view/basic_string_view.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_variant/variant.hpp>

namespace etl {

template <typename Context>
struct basic_format_arg;

namespace detail {
template <typename Context, typename T>
[[nodiscard]] constexpr auto make_arg(T&& value) -> basic_format_arg<Context>;
}

template <typename Context>
struct basic_format_arg {
private:
    using char_type = typename Context::char_type;

    template <typename ContextType, typename T>
    friend constexpr auto detail::make_arg(T&& value) -> basic_format_arg<ContextType>;

public:
    struct handle {
        auto format(basic_format_parse_context<char_type>&, Context& ctx) const -> void;

    private:
        friend struct basic_format_arg<Context>;

        template <typename T>
        explicit handle(T&& val) noexcept;

        void const* ptr_;
        void (*format_)(basic_format_parse_context<char_type>&, Context&, void const*);
    };

    basic_format_arg() noexcept = default;

    explicit operator bool() const noexcept { return holds_alternative<monostate>(value_); }

    template <typename T>
    explicit basic_format_arg(T&& v) noexcept;
    explicit basic_format_arg(float n) noexcept;
    explicit basic_format_arg(double n) noexcept;
    explicit basic_format_arg(long double n) noexcept;
    explicit basic_format_arg(char_type const* s);

    template <typename Traits>
    explicit basic_format_arg(basic_string_view<char_type, Traits> s) noexcept;

    template <etl::size_t Capacity, typename Traits>
    explicit basic_format_arg(basic_static_string<char_type, Capacity, Traits> const& s) noexcept;

    explicit basic_format_arg(nullptr_t) noexcept;

    template <typename T>
    explicit basic_format_arg(T* p) noexcept;

    variant<                          //
        monostate,                    //
        bool,                         //
        char_type,                    //
        int,                          //
        unsigned int,                 //
        long long int,                //
        unsigned long long int,       //
        float,                        //
        double,                       //
        long double,                  //
        char_type const*,             //
        basic_string_view<char_type>, //
        void const*,                  //
        handle                        //
        >
        value_ { monostate {} };
};

namespace detail {
template <typename Context, typename T>
[[nodiscard]] constexpr auto make_arg(T&& value) -> basic_format_arg<Context>
{
    return { forward<T>(value) };
}
} // namespace detail

} // namespace etl

#endif // TETL_FORMAT_BASIC_FORMAT_ARG_HPP
