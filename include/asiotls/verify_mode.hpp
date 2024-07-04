#ifndef ASIOTLS_VERIFY_MODE_HPP
#define ASIOTLS_VERIFY_MODE_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif  // defined(_MSC_VER) && (_MSC_VER >= 1200)

namespace asiotls {
using verify_mode = int;

const int verify_none = 0;
const int verify_peer = 0;
const int verify_fail_if_no_peer_cert = 0;
const int verify_client_once = 0;
}  // namespace asiotls

#endif  // ASIOTLS_VERIFY_MODE_HPP