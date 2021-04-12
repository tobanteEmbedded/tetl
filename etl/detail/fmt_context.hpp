#ifndef TAETL_EXPERIMENTAL_FORMAT_CONTEXT_HPP
#define TAETL_EXPERIMENTAL_FORMAT_CONTEXT_HPP

#include "etl/algorithm.hpp"
#include "etl/iterator.hpp"
#include "etl/warning.hpp"

namespace etl
{
template <typename T, typename CharT>
struct formatter;

/// \brief Provides access to formatting state consisting of the formatting
/// arguments and the output iterator.
///
/// The behavior is undefined if OutputIt does not model output_iterator<const
/// CharT&>.
///
/// \notes
/// [cppreference.com/w/cpp/utility/format/basic_format_context](https://en.cppreference.com/w/cpp/utility/format/basic_format_context)
template <typename OutputIt, typename CharT>
class basic_format_context
{
  public:
  using iterator  = OutputIt;
  using char_type = CharT;

  explicit constexpr basic_format_context(OutputIt pos) noexcept
      : pos_ {pos} { }

  template <typename T>
  using formatter_type = formatter<T, CharT>;

  /// \brief Returns the iterator to the output buffer.
  [[nodiscard]] constexpr auto out() noexcept -> iterator { return pos_; }

  /// \brief Sets the output iterator to it. After a call to advance_to,
  /// subsequent calls to out() will return a copy of it.
  constexpr auto advance_to(iterator it) noexcept -> void { pos_ = it; }

  private:
  OutputIt pos_;
};

/// \brief Provides access to formatting state consisting of the formatting
/// arguments and the output iterator.
///
/// \details The first template argument is an output iterator that appends to
/// etl::static_string, such as etl::back_insert_iterator<etl::static_string>.
/// Implementations are encouraged to use an iterator to type-erased buffer type
/// that supports appending to any contiguous and resizable container.
///
/// The behavior is undefined if OutputIt does not model output_iterator<const
/// CharT&>.
///
/// \notes
/// [cppreference.com/w/cpp/utility/format/basic_format_context](https://en.cppreference.com/w/cpp/utility/format/basic_format_context)
template <typename ContainerT>
using format_context
  = basic_format_context<etl::back_insert_iterator<ContainerT>, char>;

}  // namespace etl

#endif  // TAETL_EXPERIMENTAL_FORMAT_CONTEXT_HPP
