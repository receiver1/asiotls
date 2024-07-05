#ifndef ASIOTLS_IMPL_CONTEXT_IPP
#define ASIOTLS_IMPL_CONTEXT_IPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif  // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <asio/detail/throw_error.hpp>
#include <system_error>

#include "../context.hpp"
#include "../context_base.hpp"
#include "../error.hpp"

namespace asiotls {
context::context(context::method m) : handle_{} {
  mbedtls_ssl_config_init(&handle_);
  mbedtls_x509_crt_init(&cert_);
  mbedtls_pk_init(&privkey_);

  // TODO: Add support for UDP (MBEDTLS_SSL_TRANSPORT_DATAGRAM)
  bool is_server = (m == method::tlsv11_server || m == method::tlsv12_server ||
                    m == method::tlsv13_server || m == method::tls_server);

  mbedtls_ssl_config_defaults(
      &handle_, !is_server ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
      MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

  switch (m) {
#ifdef MBEDTLS_SSL_PROTO_TLS1_1
    case method::tlsv11_client:
    case method::tlsv11_server: {
      mbedtls_ssl_conf_min_version(&handle_, MBEDTLS_SSL_MAJOR_VERSION_3,
                                   MBEDTLS_SSL_MINOR_VERSION_2);
      mbedtls_ssl_conf_max_version(&handle_, MBEDTLS_SSL_MAJOR_VERSION_3,
                                   MBEDTLS_SSL_MINOR_VERSION_2);
    } break;
#endif
#ifdef MBEDTLS_SSL_PROTO_TLS1_2
    case method::tlsv12_client:
    case method::tlsv12_server: {
      mbedtls_ssl_conf_min_version(&handle_, MBEDTLS_SSL_MAJOR_VERSION_3,
                                   MBEDTLS_SSL_MINOR_VERSION_3);
      mbedtls_ssl_conf_max_version(&handle_, MBEDTLS_SSL_MAJOR_VERSION_3,
                                   MBEDTLS_SSL_MINOR_VERSION_3);
    } break;
#endif
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
    case method::tlsv13_client:
    case method::tlsv13_server: {
      mbedtls_ssl_conf_min_version(&handle_, MBEDTLS_SSL_MAJOR_VERSION_3,
                                   MBEDTLS_SSL_MINOR_VERSION_4);
      mbedtls_ssl_conf_max_version(&handle_, MBEDTLS_SSL_MAJOR_VERSION_3,
                                   MBEDTLS_SSL_MINOR_VERSION_4);
    } break;
#endif
    default: {
      mbedtls_ssl_conf_min_version(&handle_, MBEDTLS_SSL_MAJOR_VERSION_3,
                                   MBEDTLS_SSL_MINOR_VERSION_3);
      mbedtls_ssl_conf_max_version(&handle_, MBEDTLS_SSL_MAJOR_VERSION_3,
                                   MBEDTLS_SSL_MINOR_VERSION_4);
    } break;
  }

  mbedtls_ssl_conf_ca_chain(&handle_, cacerts_.data(), nullptr);
}

context::context(context::native_handle_type native_handle)
    : handle_{native_handle} {
  // if (!handle_) {
  //   throw
  //   std::system_error{std::make_error_code(std::errc::invalid_argument),
  //                           "context"};
  // }
}

context::context(context&& other) {
  handle_ = other.handle_;
  other.handle_ = {};
}

context& context::operator=(context&& other) {
  handle_ = other.handle_;
  other.handle_ = {};
  return *this;
}

context::~context() {
  mbedtls_ssl_config_free(&handle_);
  for (auto& cert : cacerts_) {
    mbedtls_x509_crt_free(&cert);
  }
  mbedtls_x509_crt_free(&cert_);
  mbedtls_pk_free(&privkey_);
}

context::native_handle_type context::native_handle() { return handle_; }

void context::clear_options(context::options o) {
  std::error_code ec{};
  clear_options(o, ec);
  asio::detail::throw_error(ec, "clear_options");
}

void context::clear_options(context::options o, std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::set_options(context::options o) {
  std::error_code ec{};
  set_options(o, ec);
  asio::detail::throw_error(ec, "set_options");
}

void context::set_options(context::options o, std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::set_verify_mode(verify_mode v) noexcept {
  mbedtls_ssl_conf_authmode(&handle_, v);
}

void context::load_verify_file(const std::string& filename) {
  std::error_code ec{};
  load_verify_file(filename, ec);
  asio::detail::throw_error(ec, "load_verify_file");
}

void context::load_verify_file(const std::string& filename,
                               std::error_code& ec) {
  mbedtls_x509_crt cert{};
  mbedtls_x509_crt_init(&cert);

  if (auto ret = mbedtls_x509_crt_parse_file(&cert, filename.c_str());
      ret != 0) {
    ec.assign(ret, error::get_tls_category());
    mbedtls_x509_crt_free(&cert);
    return;
  }

  cacerts_.push_back(std::move(cert));
}

void context::add_certificate_authority(const asio::const_buffer& ca) {
  std::error_code ec{};
  add_certificate_authority(ca, ec);
  asio::detail::throw_error(ec, "add_certificate_authority");
}

void context::add_certificate_authority(const asio::const_buffer& ca,
                                        std::error_code& ec) {
  mbedtls_x509_crt cert{};
  mbedtls_x509_crt_init(&cert);

  if (auto ret = mbedtls_x509_crt_parse(
          &cert, static_cast<const unsigned char*>(ca.data()), ca.size());
      ret != 0) {
    ec.assign(ret, error::get_tls_category());
    mbedtls_x509_crt_free(&cert);
    return;
  }

  cacerts_.push_back(std::move(cert));
}

void context::set_default_verify_paths() {
  std::error_code ec{};
  set_default_verify_paths(ec);
  asio::detail::throw_error(ec, "set_default_verify_paths");
}

void context::set_default_verify_paths(std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::add_verify_path(const std::filesystem::path& path) {
  std::error_code ec{};
  add_verify_path(path, ec);
  asio::detail::throw_error(ec, "add_verify_path");
}

void context::add_verify_path(const std::filesystem::path& path,
                              std::error_code& ec) {
  for (const auto& entry : std::filesystem::directory_iterator{path}) {
    if (entry.is_directory()) continue;
  }
}

void context::use_certificate(const asio::const_buffer& certificate) {
  std::error_code ec{};
  use_certificate(certificate, ec);
  asio::detail::throw_error(ec, "use_certificate");
}

void context::use_certificate(const asio::const_buffer& certificate,
                              std::error_code& ec) {
  if (auto ret = mbedtls_x509_crt_parse(
          &cert_, static_cast<const unsigned char*>(certificate.data()),
          certificate.size());
      ret != 0) {
    ec.assign(ret, error::get_tls_category());
    return;
  }
  if (auto ret = mbedtls_ssl_conf_own_cert(&handle_, &cert_, &privkey_);
      ret != 0)
    ec.assign(ret, error::get_tls_category());
}

void context::use_certificate_file(const std::string& filename) {
  std::error_code ec{};
  use_certificate_file(filename, ec);
  asio::detail::throw_error(ec, "use_certificate_file");
}

void context::use_certificate_file(const std::string& filename,
                                   std::error_code& ec) {
  if (auto ret = mbedtls_x509_crt_parse_file(&cert_, filename.c_str());
      ret != 0) {
    ec.assign(ret, error::get_tls_category());
    return;
  }
  if (auto ret = mbedtls_ssl_conf_own_cert(&handle_, &cert_, &privkey_);
      ret != 0)
    ec.assign(ret, error::get_tls_category());
}

void context::use_certificate_chain(const asio::const_buffer& chain) {
  std::error_code ec{};
  use_certificate_chain(chain, ec);
  asio::detail::throw_error(ec, "use_certificate_chain");
}

void context::use_certificate_chain(const asio::const_buffer& chain,
                                    std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::use_certificate_chain_file(const std::string& filename) {
  std::error_code ec{};
  use_certificate_chain_file(filename, ec);
  asio::detail::throw_error(ec, "use_certificate_chain_file");
}

void context::use_certificate_chain_file(const std::string& filename,
                                         std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::use_private_key(const asio::const_buffer& private_key) {
  std::error_code ec{};
  use_private_key(private_key, ec);
  asio::detail::throw_error(ec, "use_private_key");
}

void context::use_private_key(const asio::const_buffer& private_key,
                              std::error_code& ec) {
  if (auto ret = mbedtls_pk_parse_key(
          &privkey_, static_cast<const unsigned char*>(private_key.data()),
          private_key.size(), NULL, 0ULL, nullptr, nullptr);
      ret != 0) {
    ec.assign(ret, error::get_tls_category());
    return;
  }
  if (auto ret = mbedtls_ssl_conf_own_cert(&handle_, &cert_, &privkey_);
      ret != 0)
    ec.assign(ret, error::get_tls_category());
}

void context::use_private_key_file(const std::string& filename) {
  std::error_code ec{};
  use_private_key_file(filename, ec);
  asio::detail::throw_error(ec, "use_private_key_file");
}

void context::use_private_key_file(const std::string& filename,
                                   std::error_code& ec) {
  if (auto ret = mbedtls_pk_parse_keyfile(&privkey_, filename.c_str(), NULL,
                                          0ULL, nullptr);
      ret != 0) {
    ec.assign(ret, error::get_tls_category());
    return;
  }
  if (auto ret = mbedtls_ssl_conf_own_cert(&handle_, &cert_, &privkey_);
      ret != 0)
    ec.assign(ret, error::get_tls_category());
}

}  // namespace asiotls

#endif  // ASIOTLS_IMPL_CONTEXT_IPP