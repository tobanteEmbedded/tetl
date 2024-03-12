

// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_FUNCTION_REF_HPP
#define TETL_FUNCTIONAL_FUNCTION_REF_HPP

#include <etl/_functional/invoke.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_type_traits/add_pointer.hpp>
#include <etl/_type_traits/decay.hpp>
#include <etl/_type_traits/is_invocable_r.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/swap.hpp>

namespace etl {

template <typename Signature>
struct function_ref;

/// Non-owning view of a callable.
///
/// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p0792r4.html
/// https://github.com/TartanLlama/function_ref
template <typename R, typename... Args>
struct function_ref<R(Args...)> {
private:
    using internal_signature_t = R (*)(void*, Args...);

    void* _obj{nullptr};
    internal_signature_t _callable{nullptr};

public:
    /// \brief Constructs a function_ref referring to f.
    template <typename F>
        requires(not is_same_v<decay_t<F>, function_ref> and is_invocable_r_v<R, F &&, Args...>)
    function_ref(F&& f) noexcept
        : _obj(const_cast<void*>(reinterpret_cast<void const*>(addressof(f))))
        , _callable{
              +[](void* obj, Args... args) -> R {
                  auto* func = reinterpret_cast<add_pointer_t<F>>(obj);
                  return invoke(*func, forward<Args>(args)...);
              },
          }
    {
    }

    /// \brief Reassigns this function_ref to refer to f.
    template <typename F>
        requires(is_invocable_r_v<R, F &&, Args...>)
    auto operator=(F&& f) noexcept -> function_ref&
    {
        _obj      = reinterpret_cast<void*>(addressof(f));
        _callable = +[](void* obj, Args... args) {
            auto* func = reinterpret_cast<add_pointer_t<F>>(obj);
            return invoke(*func, forward<Args>(args)...);
        };

        return *this;
    }

    function_ref(function_ref const& /*other*/) = default;

    auto operator=(function_ref const& /*other*/) -> function_ref& = default;

    /// Exchanges the values of *this and rhs.
    auto swap(function_ref& other) noexcept -> void
    {
        using etl::swap;
        swap(_obj, other._obj);
        swap(_callable, other._callable);
    }

    /// Equivalent to return invoke(f, forward<Args>(args)...);, where f is the
    /// callable object referred to by *this, qualified with the same
    /// cv-qualifiers as the function type Signature.
    auto operator()(Args... args) const -> R { return _callable(_obj, forward<Args>(args)...); }
};

template <typename R, typename... Args>
function_ref(R (*)(Args...)) -> function_ref<R(Args...)>;

/// Exchanges the values of lhs and rhs. Equivalent to lhs.swap(rhs).
template <typename R, typename... Args>
auto swap(function_ref<R(Args...)>& lhs, function_ref<R(Args...)>& rhs) noexcept -> void
{
    lhs.swap(rhs);
}

} // namespace etl

#endif // TETL_FUNCTIONAL_FUNCTION_REF_HPP
