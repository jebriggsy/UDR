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

#include "udr_util.h"
#include "udr_exception.h"
#include <iostream>
#include <memory>
#include <stdlib.h>

#include <cstdlib>
#include <cstring>
#include <cstdio>

#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>

using std::cerr;
using std::endl;

std::string args_join(const udr_args &args, bool escape)
{
    if (args.size() == 0)
        return "";
    std::string r = args[0];
    for(unsigned i=1; i < args.size(); i++)
        r += " " + (escape ? arg_escape(args[i]) : args[i]);
    return r;
}

std::string arg_escape(const std::string &arg)
{
    // TODO: Implement escaping of quotes, quoting args with spaces, etc
    return arg;
}

static void print_args(const std::string &what, const udr_args &args)
{
    goptions.verb() << " executing " << what << endl;
    for (size_t i = 0; i < args.size(); i++)
        goptions.verb() << " argv[" << i << "]: " << args[i] << endl;
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

void sigchld_handler(int s)
{
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int get_server_connection(const std::string &host, int port, const std::string &udr_cmd, char * line, int line_size)
{
    //first check to see udr server is running.... 

    int sockfd, numbytes;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if((rv = getaddrinfo(host.c_str(), n_to_string(port).c_str(), &hints, &servinfo)) != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 0;
    }

    for(p = servinfo; p != NULL; p = p->ai_next){
        if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            //perror("udr client: socket");
            continue;
        }

        if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1){
            close(sockfd);
            //perror("udr client: connect");
            continue;
        }

        break;
    }

    if(p == NULL){
        //fprintf(stderr, "udr error: failed to connect\n");
        return 0;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);

    //First send the udr command
    //printf("client should be sending: %s\n", udr_cmd);

    if(send(sockfd, udr_cmd.c_str(), udr_cmd.size(), 0) == -1){
        perror("udr send");
        exit(1);
    }

    freeaddrinfo(servinfo);

    if ((numbytes = recv(sockfd, line, line_size-1, 0)) == -1) {
        perror("udr recv");
        exit(1);
    }

    line[numbytes] = '\0';

    close(sockfd);

    return 1;
}
