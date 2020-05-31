#include "udr_process.h"
#include "udr_exception.h"

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>

using std::endl;


// udr_process class implementation
bool udr_process::is_init = false;
std::mutex udr_process::mt;
std::condition_variable udr_process::cv;
std::set<pid_t> udr_process::handled;

udr_process::udr_process() noexcept
{}

udr_process::udr_process(udr_process &&other) noexcept
{
    pid = other.pid;
    other.pid = 0;
    h_in = other.h_in;
    h_out = other.h_out;
    other.h_in = other.h_out = -1;
    waited = other.waited;
    exit_code = other.exit_code;
    exit_signal = other.exit_signal;
}

// we don't attempt to kill or wait for the current process.
// assume that the user knows what he is doing.
udr_process &udr_process::operator=(udr_process &&other) noexcept
{
    pid = other.pid;
    other.pid = 0;
    h_in = other.h_in;
    h_out = other.h_out;
    other.h_in = other.h_out = -1;
    waited = other.waited;
    exit_code = other.exit_code;
    exit_signal = other.exit_signal;
    return *this;
}


udr_process::udr_process(const std::vector<std::string> &args, bool capture, bool tty)
{
    init();
    if(tty) {
        pid = fork_execvp_pty(args, h_in);
        h_out = h_in;
    }
    else if (capture) {
        pid = fork_execvp(args, &h_in, &h_out);
    } else {
        pid = fork_execvp(args);
    }
}
udr_process::~udr_process()
{
    close();
}

void udr_process::get_handles(int &hin, int &hout) const noexcept
{
    hin = h_in;
    hout = h_out;
}

void udr_process::close() noexcept
{
    if (h_in)
        ::close(h_in);
    if (h_out && h_out != h_in)
        ::close(h_out);
    h_in = h_out = 0;
}

bool udr_process::waitable() const noexcept
{
    return pid != 0;
}

// we use condition variables to properly wait for
// exit status.  sigchld handler does notify us.
bool udr_process::wait(int timeout_ms)
{

    if (!pid)
        return false;
    if (waited)
        return true;
    bool ok=false;
    {
        std::unique_lock<std::mutex> lock(mt);
        if (timeout_ms == 0) {
            ok = handled.count(pid) > 0;
        } else if (timeout_ms < 0) {
            cv.wait(lock, [&]{return handled.count(pid)>0;});
            ok = true;
        } else {
            ok = cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]{return handled.count(pid)>0;});
        }
        if (ok)
            handled.erase(pid);
    }
    if (ok) {
        waited = true;
        int status;
        for(;;) {
            pid_t res = waitpid(pid, &status, 0);
            if (res < 0) {
                if (errno != EAGAIN && errno != EINTR)
                    throw udr_sysexception("waitpid()");
            } else
                break;
        }
        if (WIFEXITED(status))
            exit_code = WEXITSTATUS(status);
        if (WIFSIGNALED(status))
            exit_signal = WTERMSIG(status);

    }
    return ok;
}

pid_t udr_process::get_id() const noexcept
{
    return pid;
}

int udr_process::exit_status(int &sig) const noexcept
{
    sig = exit_signal;
    return exit_code;
}
int udr_process::exit_status() const noexcept
{
    int sig;
    int e = exit_status(sig);
    if (sig)
        return -sig;
    return e;
}

// set a signal handler for SIGCHLD
void udr_process::init()
{   
    std::lock_guard<std::mutex> lock(mt);
    if (is_init)
        return;
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = handler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGCHLD, &act, 0);
    is_init = true;
}

void udr_process::handler(int sig, siginfo_t *info, void *ctx)
{
    std::lock_guard<std::mutex> lock(mt);
    handled.insert(info->si_pid);
    cv.notify_all();
}


// raw process forking functions

static void print_args(const std::string &what, const udr_args &args)
{
    goptions.verb() << " executing " << what << endl;
    for (size_t i = 0; i < args.size(); i++)
        goptions.verb() << " argv[" << i << "]: " << args[i] << endl;
}

pid_t fork_execvp(const udr_args &cmdargs, int *ptc, int *ctp)
{
    return fork_execvp(cmdargs.at(0), cmdargs, ptc, ctp);
}

pid_t fork_execvp(const std::string &what, const udr_args &cmdargs, int *ptc, int *ctp)
{
    if (!cmdargs.size())
    {
        throw udr_argexception(std::string("mising command for ") + what);
    }
    print_args(what, cmdargs);
    // extract the command, removing any initial dash, which is left in the argv.
    auto cmd = cmdargs[0];
    if (cmd.size() > 1 && cmd[0] == '-')
        cmd = cmd.substr(1, std::string::npos);

    std::unique_ptr<char *[]> argv{new char* [cmdargs.size() + 1]};
    for(size_t i=0; i<cmdargs.size(); i++)
        argv[i] = (char*)cmdargs[i].c_str();
    argv[cmdargs.size()] = 0;
    
    int parent_to_child[2], child_to_parent[2];

    if (ptc) {
        if(pipe(parent_to_child) != 0 )
            throw udr_sysexception("pipe()");
    }
    if (ctp) {
        if(pipe(child_to_parent) != 0 )
            throw udr_sysexception("pipe()");
    }

    pid_t pid = fork();
    if(pid == -1)
        throw udr_sysexception("fork()");
    if (pid > 0) {
         //parent
        if(ptc) {
            close(parent_to_child[0]);
            *ptc = parent_to_child[1];
        }
        if (ctp) {
            close(child_to_parent[1]);
            *ctp = child_to_parent[0];
        }
        return pid;
    }


    //child
    if (ptc) {
        close(parent_to_child[1]);
        if (-1 == dup2(parent_to_child[0], STDIN_FILENO)) {
            throw udr_sysexception("dup2()");
        }
        close(parent_to_child[0]);
    }
    if (ctp) {
        close(child_to_parent[0]);
        if (-1 == dup2(child_to_parent[1], STDOUT_FILENO)){
            throw udr_sysexception("dup2()");
        }
        close(child_to_parent[1]);
    }
    execvp(cmd.c_str(), argv.get());
    // Uh oh, we failed
    throw udr_sysexception("execvp() " + cmd);
    return 0;
}

pid_t fork_execvp_pty(const udr_args &cmdargs, int &master)
{
    return fork_execvp_pty(cmdargs.at(0), cmdargs, master);
}

pid_t fork_execvp_pty(const std::string &what, const udr_args &cmdargs, int &master){
    if (!cmdargs.size())
    {
        throw udr_argexception(std::string("mising command for ") + what);
    }
    print_args(what, cmdargs);
    // extract the command, removing any initial dash, which is left in the argv.
    auto cmd = cmdargs[0];
    if (cmd.size() > 1 && cmd[0] == '-')
        cmd = cmd.substr(1, std::string::npos);

    std::unique_ptr<char *[]> argv{new char* [cmdargs.size() + 1]};
    for(size_t i=0; i<cmdargs.size(); i++)
        argv[i] = (char*)cmdargs[i].c_str();
    argv[cmdargs.size()] = 0;
    
    // create pty
    master = posix_openpt(O_RDWR);
    if (master == -1) {
        throw udr_sysexception("posix_openpt()");
    }
    if (grantpt(master)) {
        throw udr_sysexception("pgrantpt()");
    }
    if (unlockpt(master)) {
        throw udr_sysexception("unlockpt()");
    }

    pid_t pid = fork();
    if (pid == -1)
        throw udr_sysexception("fork()");
    if (pid > 0) {
         //parent
        return pid;
    }
   
    // child
    if (-1 == setsid())
        throw udr_sysexception("setsid()");
    int slave = open(ptsname(master), O_RDWR);
    if (slave == -1)
        throw udr_sysexception("open()");
    close(master);
    if (-1 == dup2(slave, STDIN_FILENO))
        throw udr_sysexception("dup2()");
    if (-1 == dup2(slave, STDOUT_FILENO))
        throw udr_sysexception("dup2()");
    close(slave);

    execvp(cmd.c_str(), argv.get());
    throw udr_sysexception("execvp() " + cmd);
    return 0;
}
