
#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>
#include <asiotls.hpp>
#include <iostream>

int main() {
  asio::io_context service{};

  asiotls::context context{asiotls::context::method::tlsv13};
  asiotls::stream<asio::ip::tcp::socket> stream{service, context};
  asio::connect(stream.lowest_layer(),
                asio::ip::tcp::resolver{service}.resolve("google.com", "80"));

  stream.handshake(asiotls::stream_base::handshake_type::client);

  service.run();

  return 0;
}