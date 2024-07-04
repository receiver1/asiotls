#ifndef ASIOTLS_CONTEXT_HPP
#define ASIOTLS_CONTEXT_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif  // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <system_error>

#include "context_base.hpp"
#include "verify_mode.hpp"

namespace asiotls {
class context : public context_base {
 public:
  /// The native handle type of the SSL context.
  using native_handle_type = int;

  /// Constructor.
  explicit context(method m);

  /// Construct to take ownership of a native handle.
  explicit context(native_handle_type native_handle);

  /// Move-construct a context from another.
  context(context&& other);

  /// Move-assign a context from another.
  context& operator=(context&& other);

  /// Destructor.
  ~context();

  /// Get the underlying implementation in the native type.
  native_handle_type native_handle();

  /// Clear options on the context.
  void clear_options(options o);

  /// Clear options on the context.
  void clear_options(options o, std::error_code& ec);

  /// Set options on the context.
  void set_options(options o);

  /// Set options on the context.
  void set_options(options o, std::error_code& ec);

  /// Set the peer verification mode.
  void set_verify_mode(verify_mode v);

  /// Set the peer verification mode.
  void set_verify_mode(verify_mode v, std::error_code& ec);
};
}  // namespace asiotls

#include "impl/context.ipp"

#endif  // ASIOTLS_CONTEXT_HPP