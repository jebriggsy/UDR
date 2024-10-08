#ifndef UDR_PROCESS_H
#define UDR_PROCESS_H


#include "udr_options.h"
#include <sys/types.h>
#include <signal.h>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>


// a subprocess class, with similar semantics to std::thread
// A signal handler is used to deal with SIGCHLD delivery and
// we then maintain a set of caught child signals.  This allows
// us to use timed thread wait to wait for children
// rather than the rudimentary wait facilities available in
// waitpid()

class udr_process
{
public:
    udr_process() noexcept ;
    udr_process(udr_process &&other) noexcept;
    udr_process(const udr_process &other) = delete;
    udr_process(const std::vector<std::string> &args, bool capture, bool tty);
    virtual ~udr_process();
    udr_process &operator=(udr_process &&other) noexcept;
    bool waitable() const noexcept;
    bool wait(int timeout_ms);
    int exit_status(int &signal) const noexcept;
    int exit_status()const noexcept;
    void close()noexcept;
    void get_handles(int &hin, int &hout)const noexcept;
    pid_t get_id() const noexcept;

private:
    static void init();
    static void handler(int sig, siginfo_t *info, void *ctx);

    int h_in=0, h_out=0;
    pid_t pid = 0;
    bool waited = false;
    int exit_code = 0;
    int exit_signal;

    static bool is_init;
    static std::mutex mt;
    static std::condition_variable cv;
    static std::set<pid_t> handled;
};

pid_t fork_execvp(const udr_args &cmd, int *p_to_c=nullptr, int *c_to_p=nullptr);
pid_t fork_execvp(const std::string &what, const udr_args &cmd, int *p_to_c=nullptr, int *c_to_p=nullptr);
pid_t fork_execvp_pty(const udr_args &cmd, int &master);
pid_t fork_execvp_pty(const std::string &what, const udr_args &cmd, int &master);


#endif /* UDR_PROCESS_H */