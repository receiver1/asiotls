#ifndef ASIOTLS_DETAIL_READ_OP_HPP
#define ASIOTLS_DETAIL_READ_OP_HPP

#include <mbedtls/ssl.h>

#include <asio/buffer.hpp>
#include <asio/detail/buffer_sequence_adapter.hpp>
#include <limits>
#include <system_error>

#include "engine.hpp"

namespace asiotls {
namespace detail {
template <class MutableBufferSequence>
class read_op {
 public:
  static constexpr const char* tracking_name() {
    return "asiotls::stream<>::async_read_some";
  }

  read_op(const MutableBufferSequence& buffers) : buffers_{buffers} {}

  engine::want operator()(mbedtls_ssl_context* context,
                          std::size_t& bytes_transferred, std::error_code& ec) {
    asio::mutable_buffer buffer{asio::detail::buffer_sequence_adapter<
        asio::mutable_buffer, MutableBufferSequence>::first(buffers_)};

    if (!buffer.size()) {
      ec = {};
      return engine::want::nothing;
    }

    return engine::perform(
        [context](void* buffer, std::size_t size) {
          return mbedtls_ssl_read(context, buffer,
                                  size < std::numeric_limits<int>::max()
                                      ? size
                                      : std::numeric_limits<int>::max());
        },
        buffer.data(), buffer.size(), bytes_transferred, ec);
  }

 private:
  MutableBufferSequence buffers_;
};
}  // namespace detail
}  // namespace asiotls

#endif  // ASIOTLS_DETAIL_READ_OP_HPP