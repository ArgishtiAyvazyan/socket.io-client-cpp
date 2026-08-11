//
//  sio_client.h
//
//  Created by Melo Yao on 3/25/15.
//

#ifndef SIO_CLIENT_H
#define SIO_CLIENT_H
#include "sio_message.h"
#include "sio_socket.h"
#include <cstddef>
#include <functional>
#include <string>

namespace asio {
class io_context;
}

namespace sio {
class client_impl;

enum log_level {
  log_level_debug,
  log_level_info,
  log_level_warning,
  log_level_error
};

typedef std::function<void(log_level, const std::string &)> log_handler;

#if SIO_TLS
// Peer certificate material for one verification callback invocation.
//
// No OpenSSL handle is exposed. sioclient_tls links its own OpenSSL and, when
// built as a shared library, does not export it; a consumer linking a different
// OpenSSL that dereferenced an X509 or X509_STORE_CTX from here would read
// private, layout-unstable structs through the wrong offsets. Certificates
// therefore cross the boundary as DER bytes, which the consumer parses with
// whichever OpenSSL it links itself.
//
// The DER buffers are owned by sioclient_tls and valid only for the duration of
// the callback. Copy anything that must outlive it.
class tls_verify_context {
public:
  struct der_cert {
    const unsigned char *data;
    std::size_t size;
  };

  // Certificate at the current verification depth.
  der_cert current_cert() const { return m_current; }

  // End-entity certificate of the peer chain.
  der_cert leaf_cert() const { return m_leaf; }

  // Certificates the peer sent during the handshake, leaf first.
  std::size_t chain_size() const { return m_chain_size; }

  der_cert chain_cert(std::size_t index) const {
    return index < m_chain_size ? m_chain[index] : der_cert{nullptr, 0};
  }

  // Depth of current_cert(); 0 is the leaf.
  int depth() const { return m_depth; }

  // Current OpenSSL verification error (an X509_V_* code).
  int error() const { return m_error; }

  // Records an X509_V_* code to store on the underlying verification context.
  // sioclient_tls applies it with its own OpenSSL once the callback returns.
  void set_error(int error) {
    m_error = error;
    m_error_overridden = true;
  }

private:
  friend class client_impl;
  tls_verify_context() = default;

  der_cert m_current{nullptr, 0};
  der_cert m_leaf{nullptr, 0};
  const der_cert *m_chain = nullptr;
  std::size_t m_chain_size = 0;
  int m_depth = 0;
  int m_error = 0;
  bool m_error_overridden = false;
};
#endif

struct client_options {
  asio::io_context *io_context = nullptr;
};

class client {
public:
  enum close_reason { close_reason_normal, close_reason_drop };

  typedef std::function<void(void)> con_listener;

  typedef std::function<void(close_reason const &reason)> close_listener;

  typedef std::function<void(unsigned, unsigned)> reconnect_listener;

  typedef std::function<void(std::string const &nsp)> socket_listener;

#if SIO_TLS
  typedef std::function<bool(bool, tls_verify_context &)> tls_verify_callback;
#endif

  client();
  client(client_options const &options);
  ~client();

  // set listeners and event bindings.
  void set_open_listener(con_listener const &l);

  void set_fail_listener(con_listener const &l);

  void set_reconnecting_listener(con_listener const &l);

  void set_reconnect_listener(reconnect_listener const &l);

  void set_close_listener(close_listener const &l);

  void set_socket_open_listener(socket_listener const &l);

  void set_socket_close_listener(socket_listener const &l);

  void clear_con_listeners();

  void clear_socket_listeners();

  // Client Functions - such as send, etc.
  void connect(const std::string &uri);

  void connect(const std::string &uri, const message::ptr &auth);

  void connect(const std::string &uri,
               const std::map<std::string, std::string> &query);

  void connect(const std::string &uri,
               const std::map<std::string, std::string> &query,
               const message::ptr &auth);

  void connect(const std::string &uri,
               const std::map<std::string, std::string> &query,
               const std::map<std::string, std::string> &http_extra_headers);

  void connect(const std::string &uri,
               const std::map<std::string, std::string> &query,
               const std::map<std::string, std::string> &http_extra_headers,
               const message::ptr &auth);

  void set_reconnect_attempts(int attempts);

  void set_reconnect_delay(unsigned millis);

  void set_reconnect_delay_max(unsigned millis);

  void set_logs_default();

  void set_logs_quiet();

  void set_logs_verbose();

  void set_log_handler(log_handler const &handler);

  sio::socket::ptr const &socket(const std::string &nsp = "");

  // Closes the connection
  void close();

  void sync_close();

  void set_proxy_basic_auth(const std::string &uri, const std::string &username,
                            const std::string &password);

  void set_ssl_verify_mode(bool verify);

  void set_ssl_ca_certificates_pem(const std::string &pem_chain);

#if SIO_TLS
  void set_tls_verify_callback(tls_verify_callback const &cb);
#endif

  bool opened() const;

  std::string const &get_sessionid() const;

private:
  // disable copy constructor and assign operator.
  client(client const &) {}
  void operator=(client const &) {}

  client_impl *m_impl;
};

} // namespace sio

#endif // __SIO_CLIENT__H__
