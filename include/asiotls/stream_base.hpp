#ifndef ASIOTLS_STREAM_BASE_HPP
#define ASIOTLS_STREAM_BASE_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif  // defined(_MSC_VER) && (_MSC_VER >= 1200)

namespace asiotls {
class stream_base {
 public:
  /// Different handshake types.
  enum handshake_type {
    /// Perform handshaking as a client.
    client,

    /// Perform handshaking as a server.
    server
  };

 protected:
  /// Protected destructor to prevent deletion through this type.
  ~stream_base() {}
};
}  // namespace asiotls

#endif  // ASIOTLS_STREAM_BASE_HPP