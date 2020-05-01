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
#include "crypto.h"
#include "cc.h"
#include "udr_threads.h"
#include "udr_util.h"
#include "udr_options.h"
#include "version.h"

using namespace std;

static int run_udr_main(UDR_Options &curr_options);
static int run_udr_rsh_client(UDR_Options &curr_options);
static int run_udr_rsh_server(const UDR_Options &curr_options);
static std::string get_remote_udr_cmd(const UDR_Options &options);
static std::string get_rsh_udr_cmd(const UDR_Options &options);
static udr_args get_rsync_args(const UDR_Options &options);
static void print_version();

//only going to go from local -> remote and remote -> local, remote <-> remote maybe later, but local -> local doesn't make sense for UDR
int main(int argc, char* argv[]) {

    //now get the options using udr_options.
    struct UDR_Options curr_options;

    curr_options.get_options(argc, argv);

    if (curr_options.version_flag || curr_options.verbose) {
        print_version();
        if (!curr_options.verbose)
            return 0;
    }

    if (curr_options.tflag) {
        // I am the rsh remote 
        return run_udr_rsh_server(curr_options);
    }

    if (curr_options.sflag) {
        // I am the rsh client
        return run_udr_rsh_client(curr_options);
    }

    return run_udr_main(curr_options);
}


int run_udr_main(UDR_Options &curr_options)
{
    // We are the main program.

    if (!curr_options.rsync_args.size())
        usage();

    //get the host and username first
    curr_options.get_host_username();

    std::string udr_cmd = get_remote_udr_cmd(curr_options);

    int line_size = NI_MAXSERV + PASSPHRASE_SIZE * 2 + 1;
    char * line = (char*) malloc(line_size);
    line[0] = '\0';

    /* if given double colons then use the server connection: curr_options.server_connect, curr_options.server is for the udr server */
    if (curr_options.server_connect) {
        if(curr_options.verbose){
            cerr << curr_options.which_process << " trying server connection" << endl;
        }

        int server_exists = get_server_connection(curr_options.host, curr_options.server_port, udr_cmd.c_str(), line, line_size);

        if (!server_exists) {
            cerr << "UDR ERROR: Cannot connect to server at " << curr_options.host << ":" << curr_options.server_port << endl;
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
        args.push_back(curr_options.ssh_program);

        // Add ssh port
        if (curr_options.ssh_port) {
            args.push_back("-p");
            args.push_back(n_to_string(curr_options.ssh_port));
        }

        if (!curr_options.username.empty()) {
            args.push_back("-l");
            args.push_back(curr_options.username);
        }

        args.push_back(curr_options.host);
        args.push_back(udr_cmd);
        fork_exec("ssh_program", curr_options, args, sshparent_to_child, sshchild_to_parent);

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

        if (curr_options.verbose) {
            cerr << curr_options.which_process << " Received string: " << line << endl;
        }

        if (nbytes <= 0) {
            fprintf(stderr, "UDR ERROR: unexpected response from server, exiting.\n");
            exit(EXIT_FAILURE);
        }
    }

    // Now, start the rsync process, parsing the info from remote

    if (strlen(line) == 0) {
        fprintf(stderr, "UDR ERROR: unexpected response from server, exiting.\n");
        exit(EXIT_FAILURE);
    }

    curr_options.port_num = atoi(strtok(line, " "));    
    char * hex_pp = strtok(NULL, " ");

    if (curr_options.verbose) {
        cerr << curr_options.which_process << " port_num: " << curr_options.port_num << " passphrase: " <<  hex_pp << endl;
    }

    if (curr_options.encryption) {
        FILE *key_file = fopen(curr_options.key_filename.c_str(), "w");
        int fail = chmod(curr_options.key_filename.c_str(), S_IRUSR | S_IWUSR);

        if (key_file == NULL || fail) {
            cerr << "UDR ERROR: could not write key file: " << curr_options.key_filename << endl;
            exit(EXIT_FAILURE);
        }
        fprintf(key_file, "%s", hex_pp);
        fclose(key_file);
    }

    //Invoke rsync
    udr_args args = get_rsync_args(curr_options);

    pid_t local_rsync_pid = fork_exec("rsync", curr_options, args);
    if (curr_options.verbose)
        cerr << curr_options.which_process << " rsync pid: " << local_rsync_pid << endl;

    //at this point this process should wait for the rsync process to end
    int rsync_exit_status;
    do {
        pid_t w = waitpid(local_rsync_pid, &rsync_exit_status, WUNTRACED | WCONTINUED);
        if (w == -1) {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }
    } while (!WIFEXITED(rsync_exit_status) && !WIFSIGNALED(rsync_exit_status));
    exit(WEXITSTATUS(rsync_exit_status));
}

// Udr was invoked as an rsh client by rsync.  Perform this mode.
int run_udr_rsh_client(UDR_Options &curr_options)
{
    char hex_pp[HEX_PASSPHRASE_SIZE];
    unsigned char passphrase[PASSPHRASE_SIZE];

    if (curr_options.encryption) {
        if (curr_options.verbose)
            cerr << curr_options.which_process << " Key filename: " << curr_options.key_filename << endl;
        FILE* key_file = fopen(curr_options.key_filename.c_str(), "r");
        if (key_file == NULL) {
            cerr << curr_options.which_process << " UDR ERROR: could not read from key_file " << curr_options.key_filename << endl;
            exit(EXIT_FAILURE);
        }
        fscanf(key_file, "%s", hex_pp);
        fclose(key_file);
        remove(curr_options.key_filename.c_str());

        for (unsigned int i = 0; i < strlen(hex_pp); i = i + 2) {
            unsigned int c;
            sscanf(&hex_pp[i], "%02x", &c);
            passphrase[i / 2] = (unsigned char) c;
        }
    }

    // target host is the last argument
    udr_args args = curr_options.rsync_args;
    curr_options.host = args.front();

    // all the rest is the remote command
    args.erase(args.begin());
    std::string remote_command = args_join(args); 

    if (curr_options.verbose)
        cerr << curr_options.which_process << " rsh host: " << curr_options.host << " cmd: \"" << remote_command << "\"" << endl;

    run_sender(curr_options, passphrase, remote_command);

    if (curr_options.verbose)
        cerr << curr_options.which_process << " run_sender done" << endl;
    return 0;
}

// We are the rsh server, invoked on remote to talk to the rsh client
// over which rsync will communicate
int run_udr_rsh_server(const UDR_Options &curr_options)
{
    return run_receiver(curr_options);
}

// Get the argv to invoke rsync
static udr_args get_rsync_args(const UDR_Options &options)
{
     //parse the rsync options
    udr_args args;

    args.push_back(options.rsync_args.front());
    // todo: make udr work with non-blocking io in its rsh role
    args.push_back("--blocking-io");

    // add the rsh arg to rsync:
    args.push_back("-e");
    args.push_back(get_rsh_udr_cmd(options));

    // add remaining rsync args from the command line
    for (size_t i = 1; i < options.rsync_args.size(); i++)
        args.push_back(options.rsync_args[i]);
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

    if (options.verbose)
        args.push_back("-v");

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
    if (options.verbose)
        rsh_args.push_back("-v");

    // 'sender' part of rsh, connect to remote udt
    // tells udr to mimic rsh in the way it parses arguments
    rsh_args.push_back("--sender");
    rsh_args.push_back(n_to_string(options.port_num));
    
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
