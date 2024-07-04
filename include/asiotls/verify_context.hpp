#ifndef ASIOTLS_VERIFY_CONTEXT_HPP
#define ASIOTLS_VERIFY_CONTEXT_HPP

namespace asiotls {
class verify_context {
 public:
  /// The native handle type of the verification context.
  using native_handle_type = int;

  /// Constructor.
  explicit verify_context(native_handle_type handle);

  /// Get the underlying implementation in the native type.
  native_handle_type native_handle() { return handle_; }

 private:
  native_handle_type handle_;
};
}  // namespace asiotls

#include "impl/verify_context.ipp"

#endif  // ASIOTLS_VERIFY_CONTEXT_HPP