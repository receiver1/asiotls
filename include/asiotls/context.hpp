#ifndef ASIOTLS_CONTEXT_HPP
#define ASIOTLS_CONTEXT_HPP

#include <mbedtls/ssl.h>
#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif  // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <asio/buffer.hpp>
#include <system_error>

#include "context_base.hpp"
#include "verify_mode.hpp"

namespace asiotls {
class context : public context_base {
 public:
  /// The native handle type of the SSL context.
  using native_handle_type = mbedtls_ssl_config;

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

  /// Set the peer verification depth.
  void set_verify_depth(int depth);

  /// Set the peer verification depth.
  void set_verify_depth(int depth, std::error_code& ec);

  /// Set the callback used to verify peer certificates.
  template <class VerifyCallback>
  void set_verify_callback(VerifyCallback callback);

  /// Set the callback used to verify peer certificates.
  template <typename VerifyCallback>
  void set_verify_callback(VerifyCallback callback, std::error_code& ec);

  /// Load a certification authority file for performing verification.
  void load_verify_file(const std::string& filename);

  /// Load a certification authority file for performing verification.
  void load_verify_file(const std::string& filename, std::error_code& ec);

  /// Add certification authority for performing verification.
  void add_certificate_authority(const asio::const_buffer& ca);

  /// Add certification authority for performing verification.
  void add_certificate_authority(const asio::const_buffer& ca,
                                 std::error_code& ec);

  /// Configures the context to use the default directories for finding
  /// certification authority certificates.
  void set_default_verify_paths();

  /// Configures the context to use the default directories for finding
  /// certification authority certificates.
  void set_default_verify_paths(std::error_code& ec);

  /// Add a directory containing certificate authority files to be used for
  /// performing verification.
  void add_verify_path(const std::string& path);

  /// Add a directory containing certificate authority files to be used for
  /// performing verification.
  void add_verify_path(const std::string& path, std::error_code& ec);

  /// Use a certificate from a memory buffer.
  void use_certificate(const asio::const_buffer& certificate,
                       file_format format);

  /// Use a certificate from a memory buffer.
  void use_certificate(const asio::const_buffer& certificate,
                       file_format format, std::error_code& ec);

  /// Use a certificate from a file.
  void use_certificate_file(const std::string& filename, file_format format);

  /// Use a certificate from a file.
  void use_certificate_file(const std::string& filename, file_format format,
                            std::error_code& ec);

  /// Use a certificate chain from a memory buffer.
  void use_certificate_chain(const asio::const_buffer& chain);

  /// Use a certificate chain from a memory buffer.
  void use_certificate_chain(const asio::const_buffer& chain,
                             std::error_code& ec);

  /// Use a certificate chain from a file.
  void use_certificate_chain_file(const std::string& filename);

  /// Use a certificate chain from a file.
  void use_certificate_chain_file(const std::string& filename,
                                  std::error_code& ec);

  /// Use a private key from a memory buffer.
  void use_private_key(const asio::const_buffer& private_key,
                       file_format format);

  /// Use a private key from a memory buffer.
  void use_private_key(const asio::const_buffer& private_key,
                       file_format format, std::error_code& ec);

  /// Use a private key from a file.
  void use_private_key_file(const std::string& filename, file_format format);

  /// Use a private key from a file.
  void use_private_key_file(const std::string& filename, file_format format,
                            std::error_code& ec);

  /// Use an RSA private key from a memory buffer.
  // void use_rsa_private_key(const asio::const_buffer& private_key,
  //  file_format format);

  /// Use an RSA private key from a memory buffer.
  // void use_rsa_private_key(const asio::const_buffer& private_key,
  // file_format format, std::error_code& ec);

  /// Use an RSA private key from a file.
  // void use_rsa_private_key_file(const std::string& filename,
  // file_format format);

  /// Use an RSA private key from a file.
  // void use_rsa_private_key_file(const std::string& filename, file_format
  // format, std::error_code& ec);

  /// Use the specified memory buffer to obtain the temporary Diffie-Hellman
  /// parameters.
  // void use_tmp_dh(const asio::const_buffer& dh);

  /// Use the specified memory buffer to obtain the temporary Diffie-Hellman
  /// parameters.
  // void use_tmp_dh(const asio::const_buffer& dh, std::error_code& ec);

  /// Use the specified file to obtain the temporary Diffie-Hellman parameters.
  // void use_tmp_dh_file(const std::string& filename);

  /// Use the specified file to obtain the temporary Diffie-Hellman parameters.
  // void use_tmp_dh_file(const std::string& filename, std::error_code& ec);

  /// Set the password callback.
  // template <class PasswordCallback>
  // void set_password_callback(PasswordCallback callback);

  /// Set the password callback.
  // template <class PasswordCallback>
  // void set_password_callback(PasswordCallback callback, std::error_code& ec);

 private:
  // Translate an SSL error into an error code.
  static std::error_code translate_error(long error);

  // The underlying native implementation.
  native_handle_type handle_;
};
}  // namespace asiotls

#include "impl/context.ipp"

#endif  // ASIOTLS_CONTEXT_HPP