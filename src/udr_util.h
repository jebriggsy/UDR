/*****************************************************************************
Copyright 2012 Laboratory for Advanced Computing at the University of Chicago

This file is part of UDR.

Licensed under the Apache License, Version 2.0 (the "License"); 
you may not use this file except in compliance with the License. 
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS, 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
See the License for the specific language governing permissions 
and limitations under the License.
*****************************************************************************/

#ifndef UDR_PROCESSES_H
#define UDR_PROCESSES_H

#include "udr_options.h"
#include <sys/types.h>
#include <signal.h>
#include <string>
#include <sstream>
#include <vector>
#include <mutex>
#include <condition_variable>


// a subprocess class, with similar semantics to std::thread

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

template <typename T>
std::string n_to_string ( T Number )
{
    std::ostringstream ss;
    ss << Number;
    return ss.str();
}

pid_t fork_execvp(const udr_args &cmd, int *p_to_c=nullptr, int *c_to_p=nullptr);
pid_t fork_execvp(const std::string &what, const udr_args &cmd, int *p_to_c=nullptr, int *c_to_p=nullptr);
pid_t fork_execvp_pty(const udr_args &cmd, int &master);
pid_t fork_execvp_pty(const std::string &what, const udr_args &cmd, int &master);
int get_server_connection(const std::string &host, int port, const std::string &udr_cmd, char * line, int line_size);

// join argv into a shell command
std::string args_join(const udr_args &args, bool escape=false);
std::string arg_escape(const std::string &arg);
        
#endif
