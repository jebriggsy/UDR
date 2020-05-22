
#ifndef UDR_RSH_H
#define UDR_RSH_H

#include "udr_threads.h"
#include "udr_crypt.h"

#include <string>

#include <poll.h>

#include <udt.h>

// a class to manage buffers.  Can provide autogrow functionality
class udr_buffer
{
public:
    udr_buffer();
    ~udr_buffer();
    // make sure that at leas s bytes are in buffer or return false
    bool set_size(size_t s);
    // report how much of buffer was actually used, so that it may potentially grow
    void set_used(size_t s);  
    // get buffer
    char *get();
    // get size
    size_t get_size();
    size_t get_used();
private:

    char *buf;
    size_t bufsize;
    size_t bufused;
    char sbuf[16*1024];
};


class udr_socketpump
{
public:
    udr_socketpump(const char *_name, UDTSOCKET sock, int readhandle, int writehandle);
    bool start();
    bool should_stop();
    void stop();
    bool join();
    bool pipe_defunct();
    bool socket_defunct();

private:
    // thread funcs for either direction
    void *udt_read_func();
    void *udt_write_func();
    bool s_read(size_t &byte_read);
    bool s_write(char *data, size_t len, size_t &bytes_written);
    bool h_read(size_t &byte_read);
    bool h_write(char *data, size_t len, size_t &bytes_written);

    bool adjust_handles();
    static bool fd_set_blocking(int fd, bool blocking);

    // thread objects for either direction
    udr_memberthread<udr_socketpump> udt_read_thread;
    udr_memberthread<udr_socketpump> udt_write_thread;
    const std::string name;
    const UDTSOCKET socket = 0;
    const int hread = -1;
    const int hwrite = -1;
    const int udt_timeout = 10;  // timeout in milliseconds

    bool s_err = false, s_eof = false;
    bool h_rerr = false, h_werr = false, h_eof = false;
    udr_buffer h_readbuf, h_cryptbuf;
    udr_buffer s_readbuf, s_cryptbuf;
    bool do_stop = false;
};


class udr_rsh_remote
{
public:
    udr_rsh_remote();
    ~udr_rsh_remote();
    bool run();
    int get_child_status() const {return child_waited?child_status:-1;}

private:
    bool bind_server();
    void send_port();
    bool accept(int ms);
    void close_handles();

    std::string udt_recv_string();
    std::string get_command(const std::string &cmd);
    bool start_child(const std::string &cmd);
    bool is_stdin_closed(int timeout);
    bool poll_child(bool non_blocking);

    UDTSOCKET serv = 0;
    UDTSOCKET socket = 0;
    int serv_port = 0;
    int from_child = -1, to_child = -1;
    int child_pid = 0;

    udr_socketpump *pump = nullptr;

    bool child_waited = false;
    int child_status = -1;
};

#endif  /* UDR_RSH_H */