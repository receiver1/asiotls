#ifndef ASIOTLS_IMPL_ERROR_IPP
#define ASIOTLS_IMPL_ERROR_IPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif  // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <mbedtls/error.h>

#include <system_error>

#include "../error.hpp"

namespace asiotls {
namespace error {
namespace detail {
class tls_category : public std::error_category {
 public:
  const char* name() const noexcept { return "asiotls"; }

  std::string message(int v) const {
    char buffer[256];
    mbedtls_strerror(v, buffer, sizeof(buffer));
    return buffer;
  }
};
}  // namespace detail

const std::error_category& get_tls_category() {
  static detail::tls_category instance;
  return instance;
}
}  // namespace error
}  // namespace asiotls

#endif  // ASIOTLS_IMPL_ERROR_IPP