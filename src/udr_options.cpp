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

#include "udr_options.h"
#include "udr_exception.h"

#include <iostream>
#include <cstdlib>
#include <cstring>

#include <stdio.h>
#include <getopt.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

using namespace std;


// classes to tee an ostream to two places

class teebuf: public std::streambuf
{
public:
    // Construct a streambuf which tees output to both input
    // streambufs.
    teebuf(std::streambuf * sb1, std::streambuf * sb2)
        : sb1(sb1)
        , sb2(sb2)
    {
    }
private:
    // This tee buffer has no buffer. So every character "overflows"
    // and can be put directly into the teed buffers.
    virtual int overflow(int c)
    {
        if (c == EOF)
        {
            return !EOF;
        }
        else
        {
            int const r1 = sb1->sputc(c);
            int const r2 = sb2->sputc(c);
            return r1 == EOF || r2 == EOF ? EOF : c;
        }
    }
    
    // Sync both teed buffers.
    virtual int sync()
    {
        int const r1 = sb1->pubsync();
        int const r2 = sb2->pubsync();
        return r1 == 0 && r2 == 0 ? 0 : -1;
    }   
private:
    std::streambuf * sb1;
    std::streambuf * sb2;
};

class teestream : public std::ostream
{
public:
    // Construct an ostream which tees output to the supplied
    // ostreams.
    teestream(std::ostream & o1, std::ostream & o2);
private:
    teebuf tbuf;
};

teestream::teestream(std::ostream & o1, std::ostream & o2)
  : std::ostream(&tbuf)
  , tbuf(o1.rdbuf(), o2.rdbuf())
{}

void usage(bool do_exit) {
    fprintf(stderr, "usage: udr [UDR options] rsync [rsync options]\n\n");
    fprintf(stderr, "UDR options:\n");
    fprintf(stderr, "\t[-n aes-128 | aes-192 | aes-256 | bf | des-ede3] Encryption cypher\n");
    fprintf(stderr, "\t[-v] Run UDR with verbosity\n");
    fprintf(stderr, "\t[-d timeout] Data transfer timeout in seconds\n");
    fprintf(stderr, "\t[-a port] Local UDT port\n");
    fprintf(stderr, "\t[-b port] Remote UDT port\n");
    fprintf(stderr, "\t[-c path] Remote UDR executable\n");
    fprintf(stderr, "\t[-P ssh-port] Remote port to connect to via SSH\n");
    fprintf(stderr, "\t[-r max-bw] Max bandwidth to utilize (Mbps)\n");
    if (do_exit)
        throw udr_exitexception(1);
}

UDR_Options::UDR_Options()
{
    ssh_port = 0;
    port_num = 0;
    start_port = 9000;
    end_port = 9100;
    timeout = 15;
    tflag = false;
    sflag = false;
    verbose = 0;
    encryption = false;
    encryption_type = "aes-128";
    version_flag = false;
    server_connect = false;
    bandwidthcap = 0;

    udr_program_dest = "udr";
    ssh_program = "ssh";
    rsync_program = "rsync";
    rsync_timeout = "--timeout=0";
    shell_program = "sh";
    key_base_filename = ".udr_key";

    server_port = 9000;

    rsync_uid = 0;
    rsync_gid = 0;

    nullstream.setstate(std::ios_base::badbit);
    
    const char *shell = getenv("SHELL");
    if (shell)
        shell_program = shell;
}

int UDR_Options::parse_port(const char *p, const char *argname)
{
    errno=0;
    int result = strtol(p, NULL, 10);
    if (errno != 0 || result <= 0) {
        cerr << "Invalid value for '" << argname <<"': " << p << endl;
        usage();
    }
    return result;
}

int UDR_Options::parse_int(const char *p, const char *argname)
{
    errno=0;
    int result = strtol(p, NULL, 10);
    if (errno != 0) {
        cerr << "Invalid value for '" << argname <<"': " << p << endl;
        usage();
    }
    return result;
}

// logging and verbosity helpers
ostream & UDR_Options::err()
{
    return *mycerr << which_process << "(error) ";
}

ostream & UDR_Options::err(int errnum)
{
    return *mycerr << which_process << "(error " << errnum << ":" << strerror(errnum) << ") ";
}
ostream &UDR_Options::err(UDT::ERRORINFO &err)
{
    return *mycerr << which_process << "(UDT error " << err.getErrorCode() << ":" << err.getErrorMessage() << ") ";
}

ostream & UDR_Options::verb()
{
    if (is_verbose())
        return *mycerr << which_process << ' ';
    return nullstream;
}
ostream & UDR_Options::dbg()
{
    if (is_debug())
        return *mycerr << which_process << "(dbg) ";
    return nullstream;
}
ostream & UDR_Options::dbg2()
{
    if (is_debug2())
        return *mycerr << which_process << "(dbg2) ";
    return nullstream;
}


int UDR_Options::get_options(int argc, char * argv[])
{
    std::string key_dir;

    // Save all args for posterity
    for (int i = 0; i < argc; i++)
        args.push_back(argv[i]);
    
    udr_program_src = argv[0];    
    static struct option long_options[] = {
        {"verbose", no_argument, NULL, 'v'},
        {"verbosity", required_argument, NULL, 0},
        {"version", no_argument, NULL, 0},
        {"ssh-port", required_argument, NULL, 'P'},
        {"start-port", required_argument, NULL, 'a'},
        {"end-port", required_argument, NULL, 'b'},
        {"receiver", no_argument, NULL, 't'},
        {"server", required_argument, NULL, 'd'},
        {"encrypt", optional_argument, NULL, 'n'},
        {"sender", required_argument, NULL, 's'},
        {"login-name", required_argument, NULL, 'l'},
        {"keyfile", required_argument, NULL, 'p'},
        {"keydir", required_argument, NULL, 'k'},
        {"remote-udr", required_argument, NULL, 'c'},
        {"server-port", required_argument, NULL, 'o'},
        {"max-bw", required_argument, NULL, 'r'},
        {"rsync-uid", required_argument, NULL, 0},
        {"rsync-gid", required_argument, NULL, 0},
        {"config", required_argument, NULL, 0},
        {0, 0, 0, 0}
    };

    int option_index = 0;

    // parse opptions, stop at the first non-option (for ssh compatibility when invoked by rsync)
    // other options needed for ssh compatibility: l  (login-name)
    const char* opts = "+P:i:tl:vxa:b:s:d:h:p:c:k:o:r:n::";

    int ch;
    while ((ch = getopt_long(argc, argv, opts, long_options, &option_index)) != -1) {
        switch (ch) {
        case 'P':
            ssh_port = parse_port(optarg, "ssh-port");
            break;
        case 'a':
            start_port = parse_port(optarg, "start-port");
            break;
        case 'd':
            timeout = parse_int(optarg, "server");
            break;
        case 'b':
            end_port = parse_port(optarg, "end-port");
            break;
        case 't':
            tflag = true;
            break;
        case 'n':
            encryption = true;
            if (optarg) {
                encryption_type = optarg;
            }
            break;
        case 's':
            sflag = true;
            port_num = parse_port(optarg, "sender");
            break;
        case 'l':
            username = optarg;
            break;
        case 'p':
            key_filename = optarg;
            break;
        case 'c':
            udr_program_dest = optarg;
            break;
        case 'k':
            key_dir = optarg;
            break;
        case 'v':
            verbose += 1;
            break;
        case 'o':
            server_port =  parse_port(optarg, "server-port");
            break;
        case 'r':
            //udr_options->bandwidthcap = atoi(optarg);
            bandwidthcap = parse_int(optarg, "bandwidthcap");
            break;

        case 'i':
            specify_ip = optarg;
            break;

        case 'x':
            server_connect = true;
        case 0:
            if (strcmp("version", long_options[option_index].name) == 0) {
                version_flag = true;
            }
            else if (strcmp("config", long_options[option_index].name) == 0){
                server_config = optarg;
            }
            else if (strcmp("rsync-uid", long_options[option_index].name) == 0){
                rsync_uid = parse_int(optarg, "rsync-uid");
            }
            else if (strcmp("rsync-gid", long_options[option_index].name) == 0){
                rsync_gid = parse_int(optarg, "rsync-gid");
            }
            else if (strcmp("verbosity", long_options[option_index].name) == 0){
                verbose = parse_int(optarg, "verbosity");
            }
            break;
        default:
            fprintf(stderr, "Illegal argument: %c\n", ch);
            usage();
        }
    }
    if (start_port > end_port) {
        cerr << "invalid port range " << start_port << "-" << end_port<<endl;
        usage();
    }

    // all the non-options are the so-called extra args
    while(argv[optind])
        extra_args.push_back(argv[optind++]);
    
    // verify that timeout duration > 0
    if (timeout < 1){
       cerr << "Please specify a timeout duration [-d timeout] greater than 0s." << endl;
       exit(1);
    }

    //Finish setting up the key file path
    if (key_dir.size() == 0) {
        key_filename = key_base_filename;
    } else {
        key_filename = key_dir + "/" + key_base_filename;
    }

    //Set which_process for debugging output

    if (sflag) {
        which_process = "[udr sender]";  // rsh initiator
    }
    else if (tflag) {
        which_process = "[udr receiver]";
        //logstream.open("/tmp/udr_recv.log");
        //mycerr = new teestream(*mycerr, logstream);
        //mycerr = &logstream;

    }
    else {
        // original process must have the rsync cmd in extra args
        which_process = "[udr original]";
        if (!extra_args.size() || extra_args[0] != "rsync") {
            usage();
        }
        //check that -e/--rsh flag has not been used with rsync
        for(size_t i = 1; i < extra_args.size(); i++){
            const std::string &arg = extra_args[i];
            if(arg.find("-e") == 0 || arg == "--rsh"){
                cerr << "UDR ERROR: UDR overrides the -e, --rsh flag of rsync, so they cannot be used in the provided rsync command" << endl;
                throw udr_exitexception(1);
            }
        }
    }

    if (is_verbose()) {
        // print the command arguments
        cerr << which_process << " args: ";
        for(udr_args::iterator it=args.begin(); it != args.end(); ++it)
                cerr << " \"" << *it << '"';
        //cerr << which_process << " nonopt: ";
        //for(udr_args::iterator it=extra_args.begin(); it != extra_args.end(); it++)
            //    cerr << " \"" << *it << '"';
        cerr << endl;
    }

    
    return 1;
}


// extract a username and host name from a rsync destination path
void parse_host_username(const std::string &source, std::string &username, std::string &hostname, bool &double_colon)
{
    size_t colon_loc = source.find_first_of(':');
    size_t at_loc = source.find_first_of('@');
    username = hostname = "";
    double_colon = false;

    if (colon_loc == std::string::npos)
        return;

    if (colon_loc + 1 < source.size() && source[colon_loc + 1] == ':')
        double_colon = true;
    
    if (at_loc != std::string::npos){
        username = source.substr(0, at_loc);
        hostname = source.substr(at_loc + 1,  colon_loc - (at_loc + 1));
    } else {
        username = "";
        hostname = source.substr(0, colon_loc);
    }
}

//Gets the host and username by parsing the rsync options
void UDR_Options::get_host_username()
{
    //destination is always the last one
    std::string dest_username;
    std::string dest_host;
    bool dest_double_colon = false;

    std::string src_username;
    std::string src_host;
    bool src_double_colon = false;

    // destination is the last argument
    const std::string dest = extra_args.back();
    parse_host_username(dest, dest_username, dest_host, dest_double_colon);
    bool dest_remote = dest_host != "";

    // sources are all the others that aren't options.  Note that one could be
    // an option argument, but we assume that those
    // go backwards until find first option, we'll call those the source
    int src_num = 0;
    for(ssize_t i = extra_args.size() - 2; i > 0; i--){
//        fprintf(stderr, "i: %d argv: %s\n", i, argv[i]);
        if(extra_args[i][0] == '-')
            break;
//            fprintf(stderr, "parsing: %s\n", argv[i]);
//            fprintf(stderr, "src username: %s\n", src_username );
//            fprintf(stderr, "src host: %s\n", src_host);
        std::string next_src_username;
        std::string next_src_host;
        bool next_src_double_colon = false;
        parse_host_username(extra_args[i], next_src_username, next_src_host, next_src_double_colon);
//            fprintf(stderr, "next src username: %s\n", next_src_username );
//            fprintf(stderr, "next src host: %s\n", next_src_host);
        if(src_num == 0) {
            src_username = next_src_username;
            src_host = next_src_host;
            src_double_colon = next_src_double_colon;
        } else if (next_src_username.size()) {

            // if we have a hostname, we must ensure that it is the same as the sources
            // if we don't have a hostname, this could be an option argument and not a source
            if(src_username != next_src_username || src_host != next_src_host || src_double_colon != next_src_double_colon){
                //have a problem
                cerr << "UDR ERROR: sources must use the same host and username" << endl;
                exit(-1);
            }
        }
        src_num++;
    }
    bool src_remote = src_host != "";

    if(src_remote == dest_remote){
        cerr << "UDR ERROR: UDR only does remote -> local or local -> remote transfers" << endl;
        exit(-1);
    }

    if(src_remote){
        host = src_host;
        username = src_username;
        server_connect = src_double_colon;
    }
    else{
        host = dest_host;
        username = dest_username;
        server_connect = dest_double_colon;
    }
}


UDR_Options goptions;
