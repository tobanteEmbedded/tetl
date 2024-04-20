

// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_FUNCTION_REF_HPP
#define TETL_FUNCTIONAL_FUNCTION_REF_HPP

#include <etl/_functional/invoke_r.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_type_traits/add_pointer.hpp>
#include <etl/_type_traits/decay.hpp>
#include <etl/_type_traits/is_invocable_r.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/swap.hpp>

namespace etl {

namespace detail {

template <bool Noexcept, typename Signature>
struct function_ref;

template <bool Noexcept, typename R, typename... Args>
struct function_ref<Noexcept, R(Args...)> {
    template <typename F>
        requires(not etl::is_same_v<decay_t<F>, function_ref> and etl::is_invocable_r_v<R, F &&, Args...>)
    function_ref(F&& f) noexcept
        : _obj(const_cast<void*>(reinterpret_cast<void const*>(etl::addressof(f))))
        , _callable{+[](void* obj, Args... args) -> R {
            auto* func = reinterpret_cast<etl::add_pointer_t<F>>(obj);
            return etl::invoke_r<R>(*func, etl::forward<Args>(args)...);
        }}
    {
    }

    constexpr function_ref(function_ref const&) noexcept                    = default;
    constexpr auto operator=(function_ref const&) noexcept -> function_ref& = default;

    template <typename T>
    auto operator=(T /*t*/) -> function_ref& = delete;

    auto operator()(Args... args) const noexcept(Noexcept) -> R { return _callable(_obj, etl::forward<Args>(args)...); }

private:
    using internal_signature_t = R (*)(void*, Args...) noexcept(Noexcept);

    void* _obj{nullptr};
    internal_signature_t _callable{nullptr};
};
} // namespace detail

/// Non-owning view of a callable.
///
/// https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p0792r14.html
/// https://github.com/TartanLlama/function_ref
template <typename Signature>
struct function_ref;

template <typename R, typename... Args>
struct function_ref<R(Args...)> : etl::detail::function_ref<false, R(Args...)> {
    using etl::detail::function_ref<false, R(Args...)>::function_ref;
};

template <typename R, typename... Args>
struct function_ref<R(Args...) noexcept> : etl::detail::function_ref<true, R(Args...)> {
    using etl::detail::function_ref<true, R(Args...)>::function_ref;
};

template <typename R, typename... Args>
function_ref(R (*)(Args...)) -> function_ref<R(Args...)>;

} // namespace etl

#endif // TETL_FUNCTIONAL_FUNCTION_REF_HPP
