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

#ifndef UDR_OPTIONS_H
#define UDR_OPTIONS_H
#include <string>
#include <vector>
#include <netdb.h>
#include <limits.h>

typedef std::vector<std::string> udr_args;

struct UDR_Options{
    UDR_Options();
    int get_options(int argc, char * argv[]);
    void get_host_username();
    int parse_port(const char *arg, const char *argname);
    int parse_int(const char *arg, const char *argname);

    // The port UDR will attempt the initial SSH connection over
    int ssh_port;
    int start_port;
    int end_port;
    int timeout;

    bool tflag;
    bool sflag;
    bool verbose;
    bool encryption;
    bool version_flag;
    bool server_connect;

    std::string udr_program_src;
    std::string udr_program_dest;
    std::string ssh_program;
    std::string rsync_program;
    std::string rsync_timeout;
    std::string shell_program;

    std::string key_base_filename;
    std::string key_filename;

    std::string host;
    int port_num;
    std::string username;
    std::string which_process;
    std::string version;
    std::string server_dir;
    int server_port;

    std::string server_config;

    std::string encryption_type;

    std::string specify_ip;

    uid_t rsync_uid;
    gid_t rsync_gid;

    // the rsync part of the command ine, starting with the rsync cmd itself.
    std::vector<std::string> args;  // args uptil rsync
    std::vector<std::string> rsync_args; // rsync and following args
};

void usage();

#endif
