#ifndef ASIOTLS_CONTEXT_BASE_HPP
#define ASIOTLS_CONTEXT_BASE_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif  // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <cstdint>

namespace asiotls {
class context_base {
 public:
  enum method {
    /// Generic SSL version 2.
    sslv2,

    /// SSL version 2 client.
    sslv2_client,

    /// SSL version 2 server.
    sslv2_server,

    /// Generic SSL version 3.
    sslv3,

    /// SSL version 3 client.
    sslv3_client,

    /// SSL version 3 server.
    sslv3_server,

    /// Generic TLS version 1.
    tlsv1,

    /// TLS version 1 client.
    tlsv1_client,

    /// TLS version 1 server.
    tlsv1_server,

    /// Generic SSL/TLS.
    sslv23,

    /// SSL/TLS client.
    sslv23_client,

    /// SSL/TLS server.
    sslv23_server,

    /// Generic TLS version 1.1.
    tlsv11,

    /// TLS version 1.1 client.
    tlsv11_client,

    /// TLS version 1.1 server.
    tlsv11_server,

    /// Generic TLS version 1.2.
    tlsv12,

    /// TLS version 1.2 client.
    tlsv12_client,

    /// TLS version 1.2 server.
    tlsv12_server,

    /// Generic TLS version 1.3.
    tlsv13,

    /// TLS version 1.3 client.
    tlsv13_client,

    /// TLS version 1.3 server.
    tlsv13_server,

    /// Generic TLS.
    tls,

    /// TLS client.
    tls_client,

    /// TLS server.
    tls_server
  };

  /// Bitmask type for SSL options.
  using options = std::uint64_t;

  /// Implement various bug workarounds.
  static const std::uint64_t default_workarounds = 0;

  /// Disable SSL v2.
  static const std::uint64_t no_sslv2 = 0;

  /// Disable SSL v3.
  static const std::uint64_t no_sslv3 = 0;

  /// Disable TLS v1.
  static const std::uint64_t no_tlsv1 = 0;

  /// Disable TLS v1.1.
  static const std::uint64_t no_tlsv1_1 = 0;

  /// Disable TLS v1.2.
  static const std::uint64_t no_tlsv1_2 = 0;

  /// Disable TLS v1.3.
  static const std::uint64_t no_tlsv1_3 = 0;

  /// Disable compression. Compression is disabled by default.
  static const std::uint64_t no_compression = 0;

  /// File format types.
  enum file_format {
    /// ASN.1 file.
    asn1,

    /// PEM file.
    pem
  };

  /// Purpose of PEM password.
  enum password_purpose {
    /// The password is needed for reading/decryption.
    for_reading,

    /// The password is needed for writing/encryption.
    for_writing
  };

 protected:
  ~context_base() {}
};
}  // namespace asiotls

#endif  // ASIOTLS_CONTEXT_BASE_HPP