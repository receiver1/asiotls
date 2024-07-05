#ifndef ASIOTLS_IMPL_CONTEXT_IPP
#define ASIOTLS_IMPL_CONTEXT_IPP

#include <mbedtls/ssl.h>

#include <asio/detail/throw_error.hpp>
#include <system_error>

#include "asiotls/context_base.hpp"

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif  // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "../context.hpp"

namespace asiotls {
context::context(context::method m) : handle_{} {
  mbedtls_ssl_config_init(&handle_);
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

context::~context() { mbedtls_ssl_config_free(&handle_); }

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

void context::set_verify_mode(verify_mode v) {
  std::error_code ec{};
  set_verify_mode(v, ec);
  asio::detail::throw_error(ec, "set_verify_mode");
}

void context::set_verify_mode(verify_mode v, std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::set_verify_depth(int depth) {
  std::error_code ec{};
  set_verify_depth(depth, ec);
  asio::detail::throw_error(ec, "set_verify_depth");
}

void context::set_verify_depth(int depth, std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::load_verify_file(const std::string& filename) {
  std::error_code ec{};
  load_verify_file(filename, ec);
  asio::detail::throw_error(ec, "load_verify_file");
}

void context::load_verify_file(const std::string& filename,
                               std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::add_certificate_authority(const asio::const_buffer& ca) {
  std::error_code ec{};
  add_certificate_authority(ca, ec);
  asio::detail::throw_error(ec, "add_certificate_authority");
}

void context::add_certificate_authority(const asio::const_buffer& ca,
                                        std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::set_default_verify_paths() {
  std::error_code ec{};
  set_default_verify_paths(ec);
  asio::detail::throw_error(ec, "set_default_verify_paths");
}

void context::set_default_verify_paths(std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::add_verify_path(const std::string& path) {
  std::error_code ec{};
  add_verify_path(path, ec);
  asio::detail::throw_error(ec, "add_verify_path");
}

void context::add_verify_path(const std::string& path, std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::use_certificate(const asio::const_buffer& certificate,
                              file_format format) {
  std::error_code ec{};
  use_certificate(certificate, format, ec);
  asio::detail::throw_error(ec, "use_certificate");
}

void context::use_certificate(const asio::const_buffer& certificate,
                              file_format format, std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::use_certificate_file(const std::string& filename,
                                   file_format format) {
  std::error_code ec{};
  use_certificate_file(filename, format, ec);
  asio::detail::throw_error(ec, "use_certificate_file");
}

void context::use_certificate_file(const std::string& filename,
                                   file_format format, std::error_code& ec) {
  throw "Function is not implemented yet";
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

void context::use_private_key(const asio::const_buffer& private_key,
                              file_format format) {
  std::error_code ec{};
  use_private_key(private_key, format, ec);
  asio::detail::throw_error(ec, "use_private_key");
}

void context::use_private_key(const asio::const_buffer& private_key,
                              file_format format, std::error_code& ec) {
  throw "Function is not implemented yet";
}

void context::use_private_key_file(const std::string& filename,
                                   file_format format) {
  std::error_code ec{};
  use_private_key_file(filename, format, ec);
  asio::detail::throw_error(ec, "use_private_key_file");
}

void context::use_private_key_file(const std::string& filename,
                                   file_format format, std::error_code& ec) {
  throw "Function is not implemented yet";
}

}  // namespace asiotls

#endif  // ASIOTLS_IMPL_CONTEXT_IPP