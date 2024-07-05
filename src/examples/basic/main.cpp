
#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>
#include <asiotls.hpp>
#include <filesystem>
#include <iostream>
#include <system_error>

int main() {
  using namespace std;
  using namespace asio;

  try {
    io_context service{};

    asiotls::context context{asiotls::context::method::tlsv13};
    context.add_verify_path(std::filesystem::current_path() / "certs");

    asiotls::stream<ip::tcp::socket> stream{service, context};
    connect(stream.lowest_layer(),
            ip::tcp::resolver{service}.resolve("google.com", "80"));

    stream.handshake(asiotls::stream_base::handshake_type::client);

    service.run();
  } catch (std::system_error& ec) {
    cout << ec.what() << endl;
  }

  return 0;
}