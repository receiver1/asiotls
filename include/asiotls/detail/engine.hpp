#ifndef ASIOTLS_DETAIL_ENGINE_HPP
#define ASIOTLS_DETAIL_ENGINE_HPP

#include <mbedtls/ssl.h>

#include <asio/error.hpp>
#include <functional>
#include <system_error>

namespace asiotls::detail::engine {
enum class want {
  input_and_retry = -2,

  // Returned by functions to indicate that the engine wants to write output.
  // The output buffer points to the data to be written. The engine then
  // needs to be called again to retry the operation.
  output_and_retry = -1,

  // Returned by functions to indicate that the engine doesn't need input or
  // output.
  nothing = 0,

  // Returned by functions to indicate that the engine wants to write output.
  // The output buffer points to the data to be written. After that the
  // operation is complete, and the engine does not need to be called again.
  output = 1
};

inline want perform(const std::function<int(void*, std::size_t)>& op,
                    void* data, std::size_t size,
                    std::size_t& bytes_transferred, std::error_code& ec) {
  int result = std::invoke(op, data, size);

  if (result > 0) bytes_transferred = static_cast<std::size_t>(result);

  if (result == 0) {
    // TODO: Rewrite for std::error_code on Boost.
    ec = asio::error::make_error_code(asio::error::eof);
    return want::nothing;
  } else if (result == MBEDTLS_ERR_SSL_WANT_READ) {
    ec = {};
    return want::input_and_retry;
  } else if (result == MBEDTLS_ERR_SSL_WANT_WRITE) {
    ec = {};
    return want::output;
  }

  return want::nothing;
}
}  // namespace asiotls::detail::engine

#endif  // ASIOTLS_DETAIL_ENGINE_HPP