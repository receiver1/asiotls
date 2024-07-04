#ifndef ASIOTLS_STREAM_HPP
#define ASIOTLS_STREAM_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif  // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <mbedtls/ssl.h>

#include <system_error>
#include <type_traits>

#include "context.hpp"
#include "stream_base.hpp"

namespace asiotls {
template <class Stream>
class stream : public stream_base {
 public:
  using native_handle_type = mbedtls_ssl_context;
  using next_layer_type = std::remove_reference_t<Stream>;
  using lowest_layer_type = typename next_layer_type::lowest_layer_type;
  using executor_type = typename lowest_layer_type::executor_type;

  /// Construct a stream.
  template <class Arg>
  stream(Arg&& arg, context& ctx) : next_layer_{static_cast<Arg&&>(arg)} {
    mbedtls_ssl_init(&native_handle_);
  }

  /// Construct a stream from an existing native implementation.
  template <class Arg>
  stream(Arg&& arg, native_handle_type handle)
      : next_layer_{static_cast<Arg&&>(arg)}, native_handle_{handle} {}

  /// Move-assign a stream from another.
  stream& operator=(stream&& other) {
    // if (this != &other) {
    //   next_layer_ = static_cast<Stream&&>(other.next_layer_);
    //   core_ = static_cast<detail::stream_core&&>(other.core_);
    // }
    // return *this;
  }

  /// Destructor.
  ~stream() { mbedtls_ssl_free(&native_handle_); }

  /// Get the executor associated with the object.
  executor_type get_executor() noexcept {
    return next_layer_.lowest_layer().get_executor();
  }

  /// Get the underlying implementation in the native type.
  native_handle_type native_handle() { return native_handle_; }

  /// Get a reference to the next layer.
  const next_layer_type& next_layer() const { return next_layer_; }

  /// Get a reference to the next layer.
  next_layer_type& next_layer() { return next_layer_; }

  /// Get a reference to the lowest layer.
  lowest_layer_type& lowest_layer() { return next_layer_.lowest_layer(); }

  /// Get a reference to the lowest layer.
  const lowest_layer_type& lowest_layer() const {
    return next_layer_.lowest_layer();
  }

  /// Set the peer verification mode.
  // TODO

  /// Set the peer verification depth.
  // TODO

  /// Set the callback used to verify peer certificates.
  // TODO

  /// Perform SSL handshaking.
  void handshake(handshake_type type) {
    std::error_code ec;
    handshake(type, ec);
    // asio::detail::throw_error(ec, "handshake");
  }

  void handshake(handshake_type type, std::error_code& ec) {
    // mbedtls_ssl_handshake(&next_layer_);
    // detail::io(next_layer_, core_, detail::handshake_op(type), ec);
    // ASIO_SYNC_OP_VOID_RETURN(ec);
  }

 private:
  Stream next_layer_;
  native_handle_type native_handle_;
};
}  // namespace asiotls

#endif  // ASIOTLS_STREAM_HPP