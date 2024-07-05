#ifndef ASIOTLS_ERROR_HPP
#define ASIOTLS_ERROR_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif  // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <system_error>

namespace asiotls {
namespace error {
enum tls_errors {
  // Error numbers are those produced by mbedtls.
};

extern const std::error_category& get_tls_category();

static const std::error_category& tls_category [[maybe_unused]] =
    asiotls::error::get_tls_category();

inline std::error_code make_error_code(tls_errors e) {
  return std::error_code{static_cast<int>(e), get_tls_category()};
}
}  // namespace error
}  // namespace asiotls

namespace std {
template <>
struct is_error_code_enum<asiotls::error::tls_errors> {
  static const bool value = true;
};
}  // namespace std

#include "impl/error.ipp"

#endif  // ASIOTLS_ERROR_HPP
