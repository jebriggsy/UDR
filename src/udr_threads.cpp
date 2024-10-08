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

#include "udr_threads.h"
#include "udr_util.h"
#include "udr_crypt.h"

#include <udt.h>

#include <string.h>

#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <glob.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>

#include <sstream>

using std::string;
using std::endl;

int ppid_poll = 5;
bool thread_log = false;

//for debugging
string local_logfile_dir = "../log";

thread_data::thread_data():
    udt_socket(NULL),
    fd(0), id(-1),
    crypt(NULL),
    debug(false),
    log(false),
    is_complete(false)
{}

// Ever TRANSFER_TIMEOUT interval, check to see if data has been exchanged
// if timeout_sem = 1 then data has been exchanged
// if timeout_sem = 2 then data has not been exchanged but
//     the connection has not been established so don't exit
int timeout_sem;
void *monitor_timeout(void* _arg) {

    timeout_mon_args *args = (timeout_mon_args*) _arg;
    FILE* logfile = args->logfile;

    while (1){

        sleep(args->timeout);

        if (timeout_sem == 0){

            if (logfile) {
                fprintf(logfile, "Data transfer timeout. Exiting\n");
                fclose(logfile);
            }
            exit(1);

        } else {
            // continue on as normal
        }

        // If timeout_sem == 2, the connection has not been made -> no timeout next round
        if (timeout_sem != 2)
            timeout_sem = 0;

    }
}


void print_bytes(FILE* file, const void *object, size_t size) {
    size_t i;

    fprintf(file, "[ ");
    for(i = 0; i < size; i++)
    {
        fprintf(file, "%02x ", ((const unsigned char *) object)[i] & 0xff);
    }
    fprintf(file, "]\n");
}

string convert_int(int number) {
    std::ostringstream ss;
    ss << number;
    return ss.str();
}

//perhaps want a timeout here now with server mode?
string udt_recv_string( int udt_handle ) {
    char buf[ 2 ];
    buf[ 1 ] = '\0';

    string str = "";

    for( ;; ) {
        int bytes_read = UDT::recv( udt_handle , buf , 1 , 0 );
        if ( bytes_read == UDT::ERROR ){
            goptions.err() << "recv:" << UDT::getlasterror().getErrorMessage() << endl;
            break;
        }
        if ( bytes_read == 1 ) {
            if ( buf[ 0 ] == '\0' )
                break;
            str += buf;
        }
        else {
            sleep(1);
        }
    }
    return str;
}

void sigexit(int signum) {
    exit(EXIT_SUCCESS);
}    /* Exit successfully */




void *handle_to_udt(void *threadarg) {
    signal(SIGUSR1,sigexit);

    struct thread_data *my_args = (struct thread_data *) threadarg;
    char indata[max_block_size];
    char outdata[max_block_size];
    FILE*  logfile;

    if(my_args->log) {
        string filename = my_args->logfile_dir + convert_int(my_args->id) + "_log.txt";
        logfile = fopen(filename.c_str(), "w");
    }
    //struct timeval tv;
    //fd_set readfds;
    int bytes_read;
    while(true) {
        if(my_args->log) {
            fprintf(logfile, "%d: Should be reading from process...\n", my_args->id);
            fflush(logfile);
        }

        if(my_args->crypt != NULL)
            bytes_read = read(my_args->fd, indata, max_block_size);
        else
            bytes_read = read(my_args->fd, outdata, max_block_size);

        timeout_sem = 1;

        if(bytes_read < 0){
            if(my_args->log){
                fprintf(logfile, "Error: bytes_read %d %s\n", bytes_read, strerror(errno));
                fclose(logfile);
            }
            my_args->is_complete = true;
            return NULL;
        }
        if(bytes_read == 0) {
            if (my_args->debug)
                std::cerr << my_args->thread_name << " got EOF" << endl;
            if(my_args->log){
                fprintf(logfile, "%d Got %d bytes_read, exiting\n", my_args->id, bytes_read);
                fclose(logfile);
            }
            my_args->is_complete = true;
            return NULL;
        }

        if(my_args->crypt != NULL)
            my_args->crypt->encrypt(indata, outdata, bytes_read);

        if(my_args->log){
            fprintf(logfile, "%d bytes_read: %d\n", my_args->id, bytes_read);
            // print_bytes(logfile, outdata, bytes_read);
            fflush(logfile);
        }

        int ssize = 0;
        while(ssize < bytes_read) {
            int ss;
            if (UDT::ERROR == (ss = UDT::send(*my_args->udt_socket, outdata + ssize, bytes_read - ssize, 0))) {

                if(my_args->log) {
                    fprintf(logfile, "%d send error: %s\n", my_args->id, UDT::getlasterror().getErrorMessage());
                    fclose(logfile);
                }
                my_args->is_complete = true;
                return NULL;
            }

            ssize += ss;
            if(my_args->log) {
                fprintf(logfile, "%d sender on socket %d bytes read: %d ssize: %d\n", my_args->id, *my_args->udt_socket, bytes_read, ssize);
                fflush(logfile);
            }
        }
    }
    my_args->is_complete = true;
}

void *udt_to_handle(void *threadarg) {
    struct thread_data *my_args = (struct thread_data *) threadarg;
    char indata[max_block_size];
    char outdata[max_block_size];
    FILE* logfile;

    if(my_args->log) {
        std::string filename = my_args->logfile_dir + convert_int(my_args->id) + "_log.txt";
        logfile = fopen(filename.c_str(), "w");
    }

    while(true) {
        int rs;

        if(my_args->log) {
            fprintf(logfile, "%d: Should now be receiving from udt...\n", my_args->id);
            fflush(logfile);
        }

        if (UDT::ERROR == (rs = UDT::recv(*my_args->udt_socket, indata, max_block_size, 0))) {
            if(my_args->log){
                fprintf(logfile, "%d recv error: %s\n", my_args->id, UDT::getlasterror().getErrorMessage());
                fclose(logfile);
            }
            my_args->is_complete = true;
            return NULL;
        }

        if (my_args->debug)
                std::cerr << my_args->thread_name << " got EOF" << endl;
            
        int written_bytes;
        if(my_args->crypt != NULL) {
            my_args->crypt->encrypt(indata, outdata, rs);
            written_bytes = write(my_args->fd, outdata, rs);
        }
        else {
            written_bytes = write(my_args->fd, indata, rs);
        }
        timeout_sem = 1;

        if(my_args->log) {
            fprintf(logfile, "%d recv on socket %d rs: %d written bytes: %d\n", my_args->id, *my_args->udt_socket, rs, written_bytes);
            fflush(logfile);
        }

        if(written_bytes < 0) {
            if(my_args->log){
                fprintf(logfile, "Error: written_bytes: %d %s\n", written_bytes, strerror(errno));
                fclose(logfile);
            }
            my_args->is_complete = true;
            return NULL;
        }
    }
    my_args->is_complete = true;
}


int run_sender(const UDR_Options &udr_options, const std::string &passphrase, const std::string &cmd) {
    UDT::startup();
    struct addrinfo hints, *local, *peer;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_num = n_to_string(udr_options.port_num);
    if (0 != getaddrinfo(NULL, port_num.c_str(), &hints, &local)) {
        goptions.err() << " incorrect network address.\n" << endl;
        return 1;
    }

    UDTSOCKET client = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);

    freeaddrinfo(local);

    goptions.verb() << " connecting to " << udr_options.host << ":" << udr_options.port_num << endl;
    if (0 != getaddrinfo(udr_options.host.c_str(), port_num.c_str(), &hints, &peer)) {
        goptions.err() << " incorrect server/peer address. " << udr_options.host << ":" << udr_options.port_num << endl;
        return 1;
    }
    
    /*
     * TODO
     * Get a C programmer to verify that this just needs to change to dot notation
     * Note from jebriggsy fork merge project
     */
    /*if (udr_options->bandwidthcap > 0) {
        uint64_t opt = udr_options->bandwidthcap * 125000; // Mbps to byte/sec
        UDT::setsockopt(client, 0, UDT_MAXBW, &opt, sizeof(opt));
    }*/
    if (udr_options.bandwidthcap > 0) {
        uint64_t opt = udr_options.bandwidthcap * 125000; // Mbps to byte/sec
        UDT::setsockopt(client, 0, UDT_MAXBW, &opt, sizeof(opt));
    }

    if (UDT::ERROR == UDT::connect(client, peer->ai_addr, peer->ai_addrlen)) {
        goptions.err() << " connect: " << UDT::getlasterror().getErrorMessage() << endl;
        return 1;
    }
    goptions.verb() << " connected." << endl;

    freeaddrinfo(peer);

    // not using CC method yet
    //CUDPBlast* cchandle = NULL;
//  int value;
//  int temp;

    ssize_t n;

    //very first thing we send is the rsync argument so that the rsync server can be started and piped to from the UDT connection
    n = cmd.size() + 1;
    int ssize = 0;
    while(ssize < n) {
        int ss;
        if (UDT::ERROR == (ss = UDT::send(client, cmd.c_str() + ssize, n - ssize, 0)))
        {
            goptions.err() << " Send:" << UDT::getlasterror().getErrorMessage() << endl;
            break;
        }

        ssize += ss;
    }
    goptions.verb() << " sent command of " << ssize << " bytes" << endl;

    struct thread_data sender_to_udt;
    sender_to_udt.thread_name = "sender_to_udt";
    sender_to_udt.id = 0;
    sender_to_udt.udt_socket = &client;
    sender_to_udt.fd = STDIN_FILENO; //stdin of this process, from stdout of rsync
    sender_to_udt.log = thread_log;
    sender_to_udt.logfile_dir = local_logfile_dir;

    struct thread_data udt_to_sender;
    udt_to_sender.thread_name = "udt_to_sender";
    udt_to_sender.id = 1;
    udt_to_sender.udt_socket = &client;
    udt_to_sender.fd = STDOUT_FILENO; //stdout of this process, going to stdin of rsync, rsync defaults to set this is non-blocking
    udt_to_sender.log = thread_log;
    udt_to_sender.logfile_dir = local_logfile_dir;

    if(udr_options.encryption){
        udr_crypt encrypt(udr_crypt::ENCRYPT, udr_options.encryption_type, passphrase);
        udr_crypt decrypt(udr_crypt::DECRYPT, udr_options.encryption_type, passphrase);
        // free_key(passphrase);
        sender_to_udt.crypt = &encrypt;
        udt_to_sender.crypt = &decrypt;
    }
    

    pthread_t sender_to_udt_thread;
    pthread_create(&sender_to_udt_thread, NULL, handle_to_udt, (void *)&sender_to_udt);

    pthread_t udt_to_sender_thread;
    pthread_create(&udt_to_sender_thread, NULL, udt_to_handle, (void*)&udt_to_sender);

    int rc1 = pthread_join(udt_to_sender_thread, NULL);

    goptions.verb() << " joined on udt_to_sender_thread " << rc1 << endl;

    pthread_kill(sender_to_udt_thread, SIGUSR1);

    int rc2 = pthread_join(sender_to_udt_thread, NULL);

    goptions.verb() << " joined on sender_to_udt_thread " << rc2 << endl;

    if(udr_options->encryption){
	delete sender_to_udt.crypt;
	delete udt_to_sender.crypt;
    }
    UDT::close(client);
    UDT::cleanup();

    return 0;
}


int run_receiver(const UDR_Options &udr_options) {
    string filename = local_logfile_dir + "receiver_log.txt";
    //FILE * logfile = fopen(filename.c_str(), "w");

    int orig_ppid = getppid();

    UDT::startup();

    addrinfo hints;
    addrinfo* res;

    struct sockaddr_in my_addr;

    // switch to turn on ip specification or not
    int specify_ip = !udr_options.specify_ip.empty();

    if (specify_ip)
        goptions.verb() << "Specifying on specific ip: " << udr_options.specify_ip << endl;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string receiver_port;
    UDTSOCKET serv;

    bool bad_port = false;

    if(udr_options.start_port > udr_options.end_port){
        goptions.err() << " ERROR: invalid port range: " << udr_options.start_port << " - " << udr_options.end_port << endl;;
        return 0;
    }

    for(int port_num = udr_options.start_port; port_num <= udr_options.end_port; port_num++) {
        bad_port = false;
        receiver_port = n_to_string(port_num);

        if (0 != getaddrinfo(NULL, receiver_port.c_str(), &hints, &res)) {
            bad_port = true;
        }
        else {

            serv = UDT::socket(res->ai_family, res->ai_socktype, res->ai_protocol);

            int r;

            //
            //TODO
            //Need C programmer to verify dot notation change is all that's needed
            //Note from jebriggsy fork merge project
            //
	          /*if (udr_options->bandwidthcap > 0) {
	              uint64_t opt = udr_options->bandwidthcap * 125000; // Mbps to byte/sec
	              UDT::setsockopt(serv, 0, UDT_MAXBW, &opt, sizeof(opt));
	          }*/
            if (udr_options->bandwidthcap > 0) {
	              uint64_t opt = udr_options->bandwidthcap * 125000; // Mbps to byte/sec
	              UDT::setsockopt(serv, 0, UDT_MAXBW, &opt, sizeof(opt));
	          }

            if (specify_ip){
                my_addr.sin_family = AF_INET;
                my_addr.sin_port = htons(port_num);
                my_addr.sin_addr.s_addr = inet_addr(udr_options.specify_ip.c_str());
                bzero(&(my_addr.sin_zero), 8);

                r = UDT::bind(serv, (struct sockaddr *)&my_addr, sizeof(struct sockaddr));
            } else {
                r = UDT::bind(serv, res->ai_addr, res->ai_addrlen);
            }

            if (UDT::ERROR == r){
                bad_port = true;
            }
        }

        freeaddrinfo(res);

        if(!bad_port)
            break;
    }

    if(bad_port){
        goptions.err() << " ERROR: could not bind to any port in range: " << udr_options.start_port << " - " << udr_options.end_port << endl;;
        return 0;
    }

    auto key = udr_crypt::rand_bytes(PASSPHRASE_SIZE);
    auto ekey = udr_crypt::encode_hex(key);
    
    //stdout port number and password -- to send back to the client
    std::cout << receiver_port << " " << ekey << std::endl << std::flush;
    
    goptions.verb() << " server is ready at port " << receiver_port << " pw " << ekey << endl;

    if (UDT::ERROR == UDT::listen(serv, 10)) {
        goptions.err() << " listen: " << UDT::getlasterror().getErrorMessage() << endl;
        return 0;
    }

    sockaddr_storage clientaddr;
    int addrlen = sizeof(clientaddr);

    UDTSOCKET recver;

    if (UDT::INVALID_SOCK == (recver = UDT::accept(serv, (sockaddr*)&clientaddr, &addrlen))) {
        goptions.err() << " accept: " << UDT::getlasterror().getErrorMessage() << endl;
        return 0;
    }

    char clienthost[NI_MAXHOST];
    char clientservice[NI_MAXSERV];
    getnameinfo((sockaddr *)&clientaddr, addrlen, clienthost, sizeof(clienthost), clientservice, sizeof(clientservice), NI_NUMERICHOST|NI_NUMERICSERV);


    //If in server mode, need to check that --sender is a option (read-only) and change the directory to be in the directory that is being served up.
//  const char * sender_flag = "--sender";
    bool seen_sender = false;
//  bool after_dot = false;
//  int file_idx = -1;
//  bool called_glob = false;


    string cmd_str = udt_recv_string(recver);
    const char * cmd = cmd_str.c_str();

    //perhaps want to at least check that starts with rsync?
    if(strncmp(cmd, "rsync ", 5) != 0){
//      const char * error_msg = "UDR ERROR: non-rsync command detected\n";
        exit(1);
    }

    char * rsync_cmd;
    if(udr_options.server_connect){
        goptions.verb() << " server connect mode" << endl;

        rsync_cmd = (char *)malloc(100);

        if(!udr_options.server_config.empty()){
            sprintf(rsync_cmd, "%s%s %s", "rsync --config=", udr_options.server_config.c_str(), " --server --daemon .");
        }
        else{
            strcpy(rsync_cmd, "rsync --server --daemon .");
        }
    }
    else{
        rsync_cmd = (char *)malloc(strlen(cmd) + 1);
        strcpy(rsync_cmd, cmd);
    }

    goptions.verb() << " rsync cmd: " << rsync_cmd << endl;

    char ** sh_cmd = (char **)malloc(sizeof(char *) * 4);
    sh_cmd[0] = (char*)udr_options.shell_program.c_str();
    sh_cmd[1] = (char*)"-c";
    sh_cmd[2] = rsync_cmd;
    sh_cmd[3] = NULL;

    //now fork and exec the rsync on the remote side using sh (so that wildcards will be expanded properly)
    int child_to_parent, parent_to_child;
    int rsync_pid = fork_execvp((char*)udr_options.shell_program.c_str(), sh_cmd, &parent_to_child, &child_to_parent);

    //now if we're in server mode need to drop privileges if specified
    if(udr_options.rsync_gid > 0){
        setgid(udr_options.rsync_gid);
    }
    if(udr_options.rsync_uid > 0){
        setuid(udr_options.rsync_uid);
    }

    goptions.verb() << " rsync pid: " << rsync_pid << endl;

    struct thread_data recv_to_udt;
    recv_to_udt.udt_socket = &recver;
    recv_to_udt.thread_name = "recv_to_udt";
    recv_to_udt.id = 2;
    recv_to_udt.fd = child_to_parent; //stdout of rsync server process
    recv_to_udt.log = thread_log;
    recv_to_udt.logfile_dir = local_logfile_dir;

    struct thread_data udt_to_recv;
    udt_to_recv.udt_socket = &recver;
    udt_to_recv.thread_name = "udt_to_recv";
    udt_to_recv.id = 3;
    udt_to_recv.fd = parent_to_child; //stdin of rsync server process
    udt_to_recv.log = thread_log;
    udt_to_recv.logfile_dir = local_logfile_dir;

    if(udr_options.encryption){
        udr_crypt encrypt(udr_crypt::ENCRYPT, udr_options.encryption_type, key);
        udr_crypt decrypt(udr_crypt::DECRYPT, udr_options.encryption_type, key);
        recv_to_udt.crypt = &encrypt;
        udt_to_recv.crypt = &decrypt;
    }

    pthread_t recv_to_udt_thread;
    pthread_create(&recv_to_udt_thread, NULL, handle_to_udt, (void *)&recv_to_udt);

    pthread_t udt_to_recv_thread;
    pthread_create(&udt_to_recv_thread, NULL, udt_to_handle, (void*)&udt_to_recv);

    timeout_sem = 2;
    pthread_t counter_thread;
    FILE* timeout_log = NULL;
    timeout_mon_args timeout_args;
    timeout_args.logfile = timeout_log;
    timeout_args.timeout = udr_options.timeout;

    if(thread_log) {
        string filename = local_logfile_dir + "timeout_monitor_log.txt";
        timeout_log = fopen(filename.c_str(), "w");
    }
    pthread_create(&counter_thread, NULL, &monitor_timeout, &timeout_args);

    goptions.verb() << " waiting to join on recv_to_udt_thread" << endl;
    goptions.verb() << " ppid " << getppid() << " pid " << getpid() << endl;

    //going to poll if the ppid changes then we know it's exited and then we exit all of our threads and exit as well
    //also going to check if either thread is complete, if one is then the other should also be killed
    //bit of a hack to deal with the pthreads
    while(true){
        if(getppid() != orig_ppid){
            pthread_kill(recv_to_udt_thread, SIGUSR1);
            pthread_kill(udt_to_recv_thread, SIGUSR1);
            break;
        }
        if(recv_to_udt.is_complete && udt_to_recv.is_complete){
            if(udr_options.verbose){
                fprintf(stderr, "[udr receiver] both threads are complete: recv_to_udt.is_complete %d udt_to_recv.is_complete %d\n", recv_to_udt.is_complete, udt_to_recv.is_complete);
            }
            break;
        }
        else if(recv_to_udt.is_complete){
            if(udr_options.verbose){
                fprintf(stderr, "[udr receiver] recv_to_udt is complete: recv_to_udt.is_complete %d udt_to_recv.is_complete %d\n", recv_to_udt.is_complete, udt_to_recv.is_complete);
            }
            break;
        }
        else if(udt_to_recv.is_complete){
            if(udr_options.verbose){
                fprintf(stderr, "[udr receiver] udt_to_recv is complete: recv_to_udt.is_complete %d udt_to_recv.is_complete %d\n", recv_to_udt.is_complete, udt_to_recv.is_complete);
            }
            break;
        }

        sleep(ppid_poll);
    }

    goptions.verb() << " Trying to close UDT socket" << endl;
    UDT::close(recver);
    //int rc1 = pthread_join(recv_to_udt_thread, NULL);
    //if(udr_options.verbose){
    //fprintf(stderr, "[udr receiver] Joined recv_to_udt_thread %d\n", rc1);
    //}

    goptions.verb() << " Closed UDT socket" << endl;
  

    UDT::close(serv);

    goptions.verb() << " Closed serv UDT socket" << endl;

    UDT::cleanup();

    goptions.verb() << " cleaned up" << endl;

    //int rc2 = pthread_join(udt_to_recv_thread, NULL);

    //if(udr_options.verbose){
    //fprintf(stderr, "[udr receiver] Joined udt_to_recv_thread %d Should be closing recver now\n", rc2);
    //}


    return 0;
}


udr_thread::~udr_thread()
{}


bool udr_thread::start()
{
    int res = pthread_create(&thread, NULL, _thread_func, static_cast<void*>(this));
    if (res) {
        goptions.err() << "failed to create thread: " << res << endl;
        return false;
    }
    started = true;
    return true;
}

bool udr_thread::cancel()
{
    if (pthread_cancel(thread)) {
        goptions.err() << "pthread_cancel() failed. " << endl;
        return false;
    }
    return true;
}

bool udr_thread::join(void * &_retval)
{
    if (!started || joined)
        return false;
    goptions.dbg2() << "joining thread " << thread << endl;
    if (pthread_join(thread, &retval)) {
        goptions.err() << "join() failed. " << endl;
        return false;
    }
    joined = true;
    _retval = retval;
    return true;
}

bool udr_thread::join()
{
    void *retval;
    return join(retval);
}

void * udr_thread::_thread_func(void* inst)
{
    udr_thread *self = static_cast<udr_thread*>(inst);
    void *result = self->thread_func();
    self->done = true;
    return result;
}

