
#ifndef UDR_RSH_H
#define UDR_RSH_H

#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>

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
    udr_socketpump(UDTSOCKET sock, int readhandle, int writehandle);
    bool start();
    bool should_stop();
    void stop();
    bool join();
    bool pipe_defunct();
    bool socket_defunct();

    std::mutex mutex;
    std::condition_variable cond;

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
    std::thread udt_write_thread;
    std::thread udt_read_thread;
    const UDTSOCKET socket = 0;
    const int hread = -1;
    const int hwrite = -1;
    const int udt_timeout = 10;  // timeout in milliseconds

    // helper to set flags in a synchronous way
    void set_flag(bool &flag);
    bool s_err = false, s_eof = false;
    bool h_rerr = false, h_werr = false, h_eof = false;
    bool do_stop = false;
    udr_buffer h_readbuf, h_cryptbuf;
    udr_buffer s_readbuf, s_cryptbuf;
};


class udr_rsh_base
{
public:
    bool get_child_status(int &status) const;
    int get_child_status() const;
    virtual ~udr_rsh_base();
    virtual void close(bool abortive=false);

protected:
    bool start_pump(UDTSOCKET s, int h_read, int h_write);
    bool start_child(const std::string &what, const std::string &cmd);
    bool poll_child(bool non_blocking);

    bool udt_send_string(const std::string &str);
    bool udt_recv_string(std::string &result);

    int from_child = -1, to_child = -1;
    std::unique_ptr<udr_socketpump> pump;
    UDTSOCKET socket = 0;

private:
    int child_pid = 0;
    bool child_waited = false;
    int child_status = -1;
};


// This class manages the remote part of udr_rsh, listening to UDT connection,
// running child process, pumping data and shutting down connection etc.
class udr_rsh_remote : public udr_rsh_base
{
public:
    bool run();

private:
    bool bind_server();
    void send_port();
    bool accept(int ms);

    std::string get_command(const std::string &cmd);
    bool is_stdin_closed(int timeout);

    UDTSOCKET serv = 0;
    int serv_port = 0;

};

// This class represents the local part of an rsh.
// It will connect to a remote UDT socket and pump data
// to the handles provided.
class udr_rsh_local : public udr_rsh_base
{
public:
    udr_rsh_local(int hread=-1, int hwrite=-1);
    virtual ~udr_rsh_local();
    bool run(const std::string &host, int port, const std::string &cmd);

private:
    bool connect(const std::string &host, int port, int ms);
    void close_handles();

    std::string udt_recv_string();
    std::string get_command(const std::string &cmd);

    int h_read = -1, h_write = -1;
};



#endif  /* UDR_RSH_H */