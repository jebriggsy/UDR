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

#include "udr_crypt.h"
#include "udr_util.h"
#include "udr_exception.h"
#include "udr_options.h"
#include "udr_rsh.h"
#include "cc.h"

#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <sstream>
#include <limits.h>
#include <signal.h>
#include <getopt.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <udt.h>
#include "version.h"

using namespace std;

static int main_guarded(int argc, char * argv[]);
static int run_udr_main(UDR_Options &options);
static int run_udr_rsh_client(UDR_Options &options);
static int run_udr_rsh_server(const UDR_Options &options);
static std::string get_remote_udr_cmd(const UDR_Options &options);
static std::string get_rsh_udr_cmd(const UDR_Options &options);
static udr_args get_extra_args(const UDR_Options &options);
static void print_version();

int main(int argc, char* argv[]) {
    int result = EXIT_FAILURE;
    try {
        result = main_guarded(argc, argv);
    }
    catch (udr_argexception &e)
    {
        goptions.err() << e.what() << endl;
        usage(false);
        result = 2;
    }
    catch (udr_exitexception &e)
    {
        result = e.exitval;
    } 
    catch (udr_exception &e) {
        goptions.err() << e.what() << endl;
    }
    return result;
}


//only going to go from local -> remote and remote -> local, remote <-> remote maybe later, but local -> local doesn't make sense for UDR
int main_guarded(int argc, char* argv[]) {

    //now get the options using udr_options.
    struct UDR_Options &options = goptions;

    options.get_options(argc, argv);

    if (options.version_flag || options.verbose) {
        print_version();
        if (!options.verbose)
            return 0;
    }

    if (options.tflag) {
        // I am the rsh remote 
        return run_udr_rsh_server(options);
    }

    if (options.sflag) {
        // I am the rsh client
        return run_udr_rsh_client(options);
    }

    return run_udr_main(options);
}


int run_udr_main(UDR_Options &options)
{
    // We are the main program.

    if (!options.extra_args.size())
        usage();

    //get the host and username first
    options.get_host_username();

    std::string udr_cmd = get_remote_udr_cmd(options);

    int line_size = NI_MAXSERV + PASSPHRASE_SIZE * 2 + 1;
    char * line = (char*) malloc(line_size);
    line[0] = '\0';
    udr_process ssh;

    /* if given double colons then use the server connection: options.server_connect, options.server is for the udr server */
    if (options.server_connect) {
        options.verb() << " trying server connection" << endl;

        int server_exists = get_server_connection(options.host, options.server_port, udr_cmd.c_str(), line, line_size);

        if (!server_exists) {
            cerr << "UDR ERROR: Cannot connect to server at " << options.host << ":" << options.server_port << endl;
            exit(EXIT_FAILURE);
        }
    }
    /* If not try ssh */
    else {
        // We are starting the ssh child process to start udr executable on the other
        // side!
        int sshchild_to_parent, sshparent_to_child;

        // todo: allow user to specify ssh program and args
        std::vector<std::string> args;
        args.push_back(options.ssh_program);

        // Add ssh port
        if (options.ssh_port) {
            args.push_back("-p");
            args.push_back(n_to_string(options.ssh_port));
        }

        if (!options.username.empty()) {
            args.push_back("-l");
            args.push_back(options.username);
        }

        args.push_back(options.host);
        args.push_back(udr_cmd);
        ssh = udr_process{args, true, false};
        ssh.get_handles(sshparent_to_child, sshchild_to_parent);

        // read one line from ssh
        ssize_t nbytes = 0;
        for(;;) {
            ssize_t bytes = read(sshchild_to_parent, line+nbytes, 1);
            if (bytes >= 0) {
                nbytes += bytes;
                if (bytes == 0 || line[nbytes-1] == '\n')
                break;
            } else {
                if (errno == EINTR)
                continue;
                perror("read from ssh");
                exit(EXIT_FAILURE);
            }
        }
        line[nbytes] = '\0';
        // remove trailing newline
        if (nbytes && line[nbytes-1] == '\n')
            line[nbytes-1] = '\0';

        options.verb() << " Received string: " << line << endl;

        if (nbytes <= 0) {
            options.err() << "UDR ERROR: unexpected response from remote, exiting." << endl;
            exit(EXIT_FAILURE);
        }
    }

    // Now, start the rsync process, parsing the info from remote

    if (strlen(line) == 0) {
        options.err() << "UDR ERROR: unexpected response from remote, exiting." << endl;
        exit(EXIT_FAILURE);
    }

    options.port_num = atoi(strtok(line, " "));    
    char * hex_pp = strtok(NULL, " ");

    options.verb() << " port_num: " << options.port_num << " passphrase: " <<  hex_pp << endl;

    if (options.encryption) {
        FILE *key_file = fopen(options.key_filename.c_str(), "w");
        int fail = chmod(options.key_filename.c_str(), S_IRUSR | S_IWUSR);

        if (key_file == NULL || fail) {
            options.err() << "UDR ERROR: could not write key file: " << options.key_filename << endl;
            exit(EXIT_FAILURE);
        }
        fprintf(key_file, "%s", hex_pp);
        fclose(key_file);
    }

    //Invoke rsync
    udr_args args = get_extra_args(options);

    //pid_t local_rsync_pid = fork_execvp("rsync", args);
    udr_process rsync(args, false, false);
    /options.verb() << " rsync pid: " << rsync.get_id() << endl;
    rsync.wait(-1);
    return rsync.exit_status();
}

// Udr was invoked as an rsh client by rsync.  Perform this mode.
int run_udr_rsh_client(UDR_Options &options)
{
    char hex_pp[HEX_PASSPHRASE_SIZE];
    hex_pp[0] = '\0';

    if (options.encryption) {
        options.verb() << " Key filename: " << options.key_filename << endl;
        FILE* key_file = fopen(options.key_filename.c_str(), "r");
        if (key_file == NULL) {
            cerr << options.which_process << " UDR ERROR: could not read from key_file " << options.key_filename << endl;
            exit(EXIT_FAILURE);
        }
        fscanf(key_file, "%s", hex_pp);
        fclose(key_file);
        remove(options.key_filename.c_str());
    }

    // target host is the last argument
    udr_args args = options.extra_args;
    if (!args.size()) {
        options.err() << "remote hostname missing" << endl;
        return -1;
    }
    options.host = args.front();

    // all the rest is the remote command
    args.erase(args.begin());
    std::string remote_command = args_join(args); 

    options.verb() << " rsh host: " << options.host << " cmd: \"" << remote_command << "\"" << endl;
    udr_rsh_local local(STDIN_FILENO, STDOUT_FILENO);
    local.run(goptions.host, goptions.port_num, remote_command);

    options.verb () << " run_sender done" << endl;
    return 0;
}

// We are the rsh server, invoked on remote to talk to the rsh client
// over which rsync will communicate
int run_udr_rsh_server(const UDR_Options &options)
{
    udr_rsh_remote remote;
    remote.run();
    int status;
    remote.get_child_status(status);
    return status;
}

// Get the argv to invoke rsync
static udr_args get_extra_args(const UDR_Options &options)
{
     //parse the rsync options
    udr_args args;

    args.push_back(options.extra_args.front());
    // todo: make udr work with non-blocking io in its rsh role
    args.push_back("--blocking-io");

    // add the rsh arg to rsync:
    args.push_back("-e");
    args.push_back(get_rsh_udr_cmd(options));

    // add remaining rsync args from the command line
    for (size_t i = 1; i < options.extra_args.size(); i++)
        args.push_back(options.extra_args[i]);
   return args;    
}

// Get the "udr" command that is passed to ssh to invoke udr on the other side
std::string get_remote_udr_cmd(const UDR_Options &options) {

    udr_args args;
    args.push_back(options.udr_program_dest);
    if (options.encryption) {
        args.push_back("-n");
        args.push_back(options.encryption_type);
    }

    args.push_back("-d");
    args.push_back(n_to_string(options.timeout));

    if (options.get_verbosity()) {
        std::ostringstream os;
        os << "--verbosity=" << options.get_verbosity();
        args.push_back(os.str());
    }

    if (!options.specify_ip.empty()) {
        args.push_back("-i");
        args.push_back(options.specify_ip);
    }

    if (!options.server_connect) {
        args.push_back("-a");
        args.push_back(n_to_string(options.start_port));
        args.push_back("-b");
        args.push_back(n_to_string(options.end_port));
    }
    // the -t arg flags it as remote rsh part, rsync is used for syntax.
    args.push_back("-t");
    args.push_back("rsync");

    return args_join(args);
}

// get the command to invoke a rsh like version of udr, for rsync to communicate over
std::string get_rsh_udr_cmd(const UDR_Options &options) {
    // construct the rsh argument to rsync
    udr_args rsh_args;
    rsh_args.push_back(options.udr_program_src);
    if (options.get_verbosity()) {
        std::ostringstream os;
        os << "--verbosity=" << options.get_verbosity();
        rsh_args.push_back(os.str());
    }

    // 'sender' part of rsh, connect to remote udt
    // tells udr to mimic rsh in the way it parses arguments
    rsh_args.push_back("--sender=" + n_to_string(options.port_num));
    
    if (options.encryption) {
        rsh_args.push_back("-n");
        rsh_args.push_back(options.encryption_type);
        if (!options.key_filename.empty()) {
            rsh_args.push_back("-p");
            rsh_args.push_back(options.key_filename);
        }
    }
    
    return args_join(rsh_args);
}


void print_version() {
    cerr << "UDR version " << version << endl;
}
