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

char * get_udr_cmd(UDR_Options * udr_options) {
    char udr_args[PATH_MAX];
    if (udr_options->encryption) {
        strcpy(udr_args, "-n ");
        strcat(udr_args, udr_options->encryption_type);
        strcat(udr_args, " ");
    }
    else
        udr_args[0] = '\0';

    char delay_args[PATH_MAX];
    sprintf(delay_args, " -d %d ", udr_options->timeout);
    strcat(udr_args, delay_args);

    if (udr_options->verbose)
        strcat(udr_args, "-v");

    if (udr_options->specify_ip){
    char specify_ip_arg[PATH_MAX];
    sprintf(specify_ip_arg, " -i%s", udr_options->specify_ip);
    strcat(udr_args, specify_ip_arg);
    }

    if (udr_options->server_connect) {
        sprintf(udr_args, "%s %s", udr_args, "-t rsync");
    }
    else {
        sprintf(udr_args, "%s -a %d -b %d %s", udr_args, udr_options->start_port, udr_options->end_port, "-t rsync");
    }

    char* udr_cmd = (char *) malloc(strlen(udr_options->udr_program_dest) + strlen(udr_args) + 3);
    sprintf(udr_cmd, "%s %s\n", udr_options->udr_program_dest, udr_args);

    return udr_cmd;
}

void print_version() {
    fprintf(stderr, "UDR version %s\n", version);
}

//only going to go from local -> remote and remote -> local, remote <-> remote maybe later, but local -> local doesn't make sense for UDR
int main(int argc, char* argv[]) {
    int rsync_arg_idx;

    // if we want this to be C #include <stdbool.h>
    bool use_rsync = false;
    rsync_arg_idx = -1;

    // argv[0] should always be "udr" hence starting at 1
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "rsync") == 0) {
            use_rsync = true;
            rsync_arg_idx = i;
            break;
        }
    }

    if (!use_rsync) {
        rsync_arg_idx = argc;
    }

    //now get the options using udr_options.
    struct UDR_Options curr_options;

    get_udr_options(&curr_options, argc, argv, rsync_arg_idx);

    if (curr_options.version_flag)
        print_version();

    if (!use_rsync)
        usage();

    if (curr_options.tflag) {
        return run_receiver(&curr_options);
    }//now for server mode
    //else if (curr_options.server) {
    //    return run_as_server(&curr_options);
    //}

    else if (curr_options.sflag) {
        string arguments = "";
        string sep = " ";
        char** rsync_args = &argv[rsync_arg_idx];
        int rsync_argc = argc - rsync_arg_idx;
        char hex_pp[HEX_PASSPHRASE_SIZE];
        unsigned char passphrase[PASSPHRASE_SIZE];

        if (curr_options.encryption) {
            if (curr_options.verbose)
                fprintf(stderr, "%s Key filename: %s\n", curr_options.which_process, curr_options.key_filename);
            FILE* key_file = fopen(curr_options.key_filename, "r");
            if (key_file == NULL) {
                fprintf(stderr, "UDR ERROR: could not read from key_file %s\n", curr_options.key_filename);
                exit(EXIT_FAILURE);
            }
            fscanf(key_file, "%s", hex_pp);
            fclose(key_file);
            remove(curr_options.key_filename);

            for (unsigned int i = 0; i < strlen(hex_pp); i = i + 2) {
                unsigned int c;
                sscanf(&hex_pp[i], "%02x", &c);
                passphrase[i / 2] = (unsigned char) c;
            }
        }

        snprintf(curr_options.host, PATH_MAX, "%s", argv[rsync_arg_idx - 1]);

        if (curr_options.verbose)
            fprintf(stderr, "%s Host: %s\n", curr_options.which_process, curr_options.host);

        for (int i = 0; i < rsync_argc; i++) {
            if (curr_options.verbose)
                fprintf(stderr, "%s rsync arg[%d]: %s\n", curr_options.which_process, i, rsync_args[i]);

            //hack for when no directory is specified -- because strtok is lame, probably should write own tokenizer, but this will do for now
            if (strlen(rsync_args[i]) == 0)
                arguments += ".";
            else
                arguments += rsync_args[i];

            arguments += sep;
        }

        run_sender(&curr_options, passphrase, arguments.c_str(), rsync_argc, rsync_args);

        if (curr_options.verbose)
            fprintf(stderr, "%s run_sender done\n", curr_options.which_process);
    }
    else {
        //get the host and username first
        get_host_username(&curr_options, argc, argv, rsync_arg_idx);

        char * udr_cmd = get_udr_cmd(&curr_options);
        if (curr_options.verbose){
            fprintf(stderr, "%s udr_cmd %s\n", curr_options.which_process, udr_cmd);
        }

        int line_size = NI_MAXSERV + PASSPHRASE_SIZE * 2 + 1;
        char * line = (char*) malloc(line_size);
        line[0] = '\0';

        /* if given double colons then use the server connection: curr_options.server_connect, curr_options.server is for the udr server */
        if (curr_options.server_connect) {
            if(curr_options.verbose){
                fprintf(stderr, "%s trying server connection\n", curr_options.which_process);
            }

            int server_exists = get_server_connection(curr_options.host, curr_options.server_port, udr_cmd, line, line_size);

            if (!server_exists) {
                fprintf(stderr, "UDR ERROR: Cannot connect to server at %s:%s\n", curr_options.host, curr_options.server_port);
                exit(EXIT_FAILURE);
            }
        }
        /* If not try ssh */
        else {
            // We are starting the ssh child process to start udr executable on the other
            // side!
            int sshchild_to_parent, sshparent_to_child;

            int ssh_argc;
            if (strlen(curr_options.username) != 0)
                ssh_argc = 8;
            else
                ssh_argc = 7;

            std::vector<std::string> args;
            char ** ssh_argv;
            ssh_argv = (char**) malloc(sizeof (char *) * ssh_argc);
            int ssh_idx = 0;

            ssh_argv[ssh_idx++] = curr_options.ssh_program;
            args.push_back(curr_options.ssh_program);

            // Add ssh port
            char ssh_port_str[15];
            snprintf(ssh_port_str, 15, "%d", curr_options.ssh_port);
            ssh_argv[ssh_idx++] = (char*)"-p";
            ssh_argv[ssh_idx++] = ssh_port_str;
            args.push_back("-p");
            args.push_back(n_to_string(curr_options.ssh_port));

            if (strlen(curr_options.username) != 0) {
                ssh_argv[ssh_idx++] = (char*)"-l";
                ssh_argv[ssh_idx++] = curr_options.username;
                args.push_back("-l");
                args.push_back(curr_options.username);
            }

            ssh_argv[ssh_idx++] = curr_options.host;
            ssh_argv[ssh_idx++] = udr_cmd;
            ssh_argv[ssh_idx++] = NULL;
            args.push_back(curr_options.host);
            args.push_back(udr_cmd);

            if (curr_options.verbose) {
                fprintf(stderr, "ssh_program %s\n", curr_options.ssh_program);
                for (unsigned i = 0; i < args.size(); i++) {
                    fprintf(stderr, "ssh_argv[%d]: %s\n", i, args[i].c_str());
                }
            }

            fork_exec(args, sshparent_to_child, sshchild_to_parent);

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

            if (curr_options.verbose) {
                fprintf(stderr, "%s Received string: %s\n", curr_options.which_process, line);
            }

            if (nbytes <= 0) {
                fprintf(stderr, "UDR ERROR: unexpected response from server, exiting.\n");
                exit(EXIT_FAILURE);
            }
        }
        /* Now do the exact same thing no matter whether server or ssh process */

        if (strlen(line) == 0) {
            fprintf(stderr, "UDR ERROR: unexpected response from server, exiting.\n");
            exit(EXIT_FAILURE);
        }

        snprintf(curr_options.port_num, PATH_MAX, "%s", strtok(line, " "));

        char * hex_pp = strtok(NULL, " ");

        if (curr_options.verbose) {
            fprintf(stderr, "%s port_num: %s passphrase: %s\n", curr_options.which_process, curr_options.port_num, hex_pp);
        }

        if (curr_options.encryption) {
            FILE *key_file = fopen(curr_options.key_filename, "w");
            int fail = chmod(curr_options.key_filename, S_IRUSR | S_IWUSR);

            if (key_file == NULL || fail) {
                fprintf(stderr, "UDR ERROR: could not write key file: %s\n", curr_options.key_filename);
                exit(EXIT_FAILURE);
            }
            fprintf(key_file, "%s", hex_pp);
            fclose(key_file);
        }

        //make sure the port num str is null terminated
        char * ptr;
        if ((ptr = strchr(curr_options.port_num, '\n')) != NULL)
            *ptr = '\0';

        int parent_to_child, child_to_parent;

        //parse the rsync options
        char ** rsync_argv;

        int rsync_argc = argc - rsync_arg_idx + 5; //need more spots
        rsync_argv = (char**) malloc(sizeof (char *) * rsync_argc);

        int rsync_idx = 0;
        rsync_argv[rsync_idx++] = strdup(argv[rsync_arg_idx]);

        rsync_argv[rsync_idx++] = (char*)"--blocking-io";

        //rsync_argv[rsync_idx++] = curr_options.rsync_timeout;

        rsync_argv[rsync_idx++] = (char*)"-e";

        char udr_rsync_args1[100];

        if (curr_options.encryption) {
            strcpy(udr_rsync_args1, "-n ");
            strcat(udr_rsync_args1, curr_options.encryption_type);
            strcat(udr_rsync_args1, " ");
        }
        else
            udr_rsync_args1[0] = '\0';

        if (curr_options.verbose)
            strcat(udr_rsync_args1, "-v ");

        strcat(udr_rsync_args1, "-s");

        const char * udr_rsync_args2 = "-p";

        int length = snprintf(0, 0, "%s %s %s %s %s", curr_options.udr_program_src, udr_rsync_args1, curr_options.port_num, udr_rsync_args2, curr_options.key_filename);
        char *buf = (char*)malloc(length + 1);
            snprintf(buf, length + 1, "%s %s %s %s %s", curr_options.udr_program_src, udr_rsync_args1, curr_options.port_num, udr_rsync_args2, curr_options.key_filename);
        rsync_argv[rsync_idx++] = buf;

        //fprintf(stderr, "first_source_idx: %d\n", first_source_idx);
        for (int i = rsync_arg_idx + 1; i < argc; i++) {
            rsync_argv[rsync_idx++] = strdup(argv[i]);
        }

        rsync_argv[rsync_idx] = NULL;

        pid_t local_rsync_pid = fork_execvp(curr_options.rsync_program, rsync_argv, &parent_to_child, &child_to_parent);
        if (curr_options.verbose)
            fprintf(stderr, "%s rsync pid: %d\n", curr_options.which_process, local_rsync_pid);

        //at this point this process should wait for the rsync process to end
        const int buf_size = 4096;
        char rsync_out_buf[buf_size];

        //This prints out the stdout from rsync to stdout
        for(;;) {
                ssize_t bytes_read = read(child_to_parent, rsync_out_buf, buf_size);
            if (bytes_read == 0)
            break; // EOF
            if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            perror("read from rsync process");
            exit(EXIT_FAILURE);
            }
            ssize_t bytes_written = 0;
            while (bytes_written < bytes_read) {
            ssize_t wrote = write(STDOUT_FILENO, rsync_out_buf+bytes_written, bytes_read-bytes_written);
                if (wrote < 0) {
                if (errno == EINTR)
                continue;
                perror("write to stdout");
                exit(EXIT_FAILURE);
            }
            bytes_written += wrote;
            }
        }

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
}
