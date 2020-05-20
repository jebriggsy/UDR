

#include "udr_rsh.h"
#include "udr_util.h"

//#include <sys/socket.h>
//#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <string.h>
#include <string>
#include <iostream>

using std::cerr;
using std::endl;
using std::string;

udr_rsh_remote::udr_rsh_remote():
    pump(0), child_waited(false)
{
    serv = socket = 0;
    serv_port = 0;
    memset(rand_pp, 0, sizeof(rand_pp));
    from_child = to_child  = -1;
    child_pid = 0;
    child_status = -1;
}

udr_rsh_remote::~udr_rsh_remote()
{
    delete pump;
}

bool udr_rsh_remote::run()
{   
    UDR_Options &options = goptions;
    if (!bind_server())
        return false;
    send_port();
    if (!accept( options.timeout > 0 ? options.timeout*1000 : 0))
        return false;

    std::string command = get_command(udt_recv_string());
    if (!start_child(command))
        return false;

    //now if we're in server mode need to drop privileges if specified
    if(options.rsync_gid > 0){
        setgid(options.rsync_gid);
    }
    if(options.rsync_uid > 0){
        setuid(options.rsync_uid);
    }

    // create the socketpump
    pump = new udr_socketpump("pump", socket, from_child, to_child);
    if (!pump->start()) {
        // child process isnt explicitly killed, it will die once it doesnt receive input/output
        return false;
    }

    // now, wait for any of: child exit, parent exit, pipe error
    while(pump->should_stop()) {
        // is parent still alive?
        bool stdin_closed = is_stdin_closed(10);
        if (stdin_closed) 
        {
            // just leave things and exit.  There is no one to report exit status to, or anything.
            return false;
        }
    }
    // close socket and pipe, wait for pump to drain and exit 
    pump->stop();
    pump->join();
    close_handles();
    
    // get the exit status
    poll_child(false);
    return true;
}

bool udr_rsh_remote::bind_server()
{
    addrinfo hints;
    addrinfo* res;

    struct sockaddr_in my_addr;

    // switch to turn on ip specification or not
    bool specify_ip = !goptions.specify_ip.empty();

    if (specify_ip)
        goptions.verb() << "Specifying on specific ip: " << goptions.specify_ip << endl;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string receiver_port;

    bool bad_port = false;

    int port_num;
    for(port_num = goptions.start_port; port_num <= goptions.end_port; port_num++) {
        bad_port = false;
        receiver_port = n_to_string(port_num);

        if (0 != getaddrinfo(NULL, receiver_port.c_str(), &hints, &res)) {
            bad_port = true;
        }
        else {

            serv = UDT::socket(res->ai_family, res->ai_socktype, res->ai_protocol);

            int r;

            if (specify_ip){

                my_addr.sin_family = AF_INET;
                my_addr.sin_port = htons(port_num);
                my_addr.sin_addr.s_addr = inet_addr(goptions.specify_ip.c_str());
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
        goptions.err() << "ERROR: could not bind to any port in range: " << goptions.start_port << " - " << goptions.end_port << endl;;
        return false;
    }
    if (UDT::ERROR == UDT::listen(serv, 10)) {
        goptions.err()  << "listen: " << UDT::getlasterror().getErrorMessage() << endl;
        return false;
    }
    goptions.verb() << "server is ready at port " << receiver_port << endl;
    serv_port = port_num;
    return true;
}   


void udr_rsh_remote::send_port()
{
    unsigned char rand_pp[PASSPHRASE_SIZE];
    if (goptions.encryption)
        RAND_bytes((unsigned char *) rand_pp, PASSPHRASE_SIZE);

    //stdout port number and password -- to send back to the client
    printf("%d ", serv_port);

    for(int i = 0; i < PASSPHRASE_SIZE; i++) {
        printf("%02x", rand_pp[i]);
    }
    printf(" \n");
    fflush(stdout);
}


// accept udt connection, while timing out and quitting if the parent process
// exits
bool udr_rsh_remote::accept(int ms)
{
    sockaddr_storage clientaddr;
    int addrlen = sizeof(clientaddr);
    int pollid = UDT::epoll_create();
    UDT::epoll_add_ssock(pollid, serv);
    int remaining = ms;
    bool result = false;
    const int waitmax = 100;
  
    while (ms <= 0 || remaining)
    {
        // poll for 100 ms at a time
        std::set<UDTSOCKET> readable;
        int wait = (ms <= 0 || remaining >= waitmax)? waitmax : remaining;
        remaining -= wait;
        int r = UDT::epoll_wait(pollid, NULL, NULL, wait);
        if (r == 0)
        {
            if (!is_stdin_closed(0))
                break;
        } else {
            if (UDT::INVALID_SOCK == (socket = UDT::accept(serv, (sockaddr*)&clientaddr, &addrlen))) {
                goptions.err() << "accept: " << UDT::getlasterror().getErrorMessage() << endl;
            } else
                result = true;
            break;
        }
    }
    // we only accept one connection
    UDT::close(serv);
    serv = 0;

    UDT::epoll_release(pollid);
    return result;
}

void udr_rsh_remote::close_handles()
{
    if (to_child >= 0) {
        close(to_child);
        to_child = -1;
    }
    if (from_child >= 0) {
        close(from_child);
        from_child = -1;
    }
    if (socket) {
        UDT::close(socket);
        socket = 0;
    }
}

// receive a null terminated string, which is ow rsh_local sends the command to run
std::string udr_rsh_remote::udt_recv_string()
{
    char buf[ 2 ];
    buf[ 1 ] = '\0';

    string str = "";

    for( ;; ) {
        int bytes_read = UDT::recv( socket , buf , 1 , 0 );
        if ( bytes_read == UDT::ERROR ){
            goptions.err() << "udt_recv_string:" << UDT::getlasterror().getErrorMessage() << endl;
            return "";
        }
        if ( bytes_read == 1 ) {
            if ( buf[ 0 ] == '\0' )
                break;
            str += buf[0];
        }
        else {
            goptions.err() << "udt_recv_string: EOF" << endl;
            return "";
        }
    }
    return str;
}


std::string udr_rsh_remote::get_command(const std::string &cmd)
{
    if(goptions.server_connect){
        goptions.verb() << "server connect mode" << endl;

        if(!goptions.server_config.empty()){
            return std::string("rsync --config=") + goptions. server_config +  "--server --daemon .";
        }
        else{
            return "rsync --server --daemon .";
        }
    }
    return cmd;
}

bool udr_rsh_remote::start_child(const std::string &cmd)
{
    udr_args args;
    args.push_back(goptions.shell_program);
    args.push_back("-c");
    args.push_back(cmd);
    child_pid =  fork_exec("remote command", args, to_child, from_child);
    goptions.verb() << "rsync pid: " << child_pid << endl;
    return child_pid != 0;
}


// check if the child is alive.  return false if it is dead
bool udr_rsh_remote::poll_child(bool non_blocking)
{
    if (child_waited)
        return false;
    int status;
    pid_t res = waitpid(child_pid, &status, non_blocking ? WNOHANG : 0);
    if (res == -1)
    {
        goptions.err(errno) << " in waitpid()" << endl;
        return false;
    }
    if (res == 0)
        return true;
    // chid has exited
    child_waited = true;
    if (WIFEXITED(status)) 
        child_status = WEXITSTATUS(status);
    else
        child_status = -1;
    return false;
}


// check if the standard input has been closed, by reading from it.
// This indicates the parent process (ssh remote) is dead.
// when this happens, the file becomes readable (and returns 0 bytes on read)
bool udr_rsh_remote::is_stdin_closed(int timeout)
{
    struct pollfd fd;
    fd.fd = STDIN_FILENO;
    fd.events = POLLIN;
    int r = poll(&fd, 1, timeout);
    if (r < 0)
        goptions.err(errno) << " in poll()" << endl;
    if (r == 1)
    {
        char buf;
        ssize_t nread = read(STDIN_FILENO, &buf, 1); 
        if (nread == 0)
            return true;
        if (nread < 0)
            goptions.err(errno) << " in read(STDIN_FILENO)" << endl;
        else
            goptions.err() << "unexpected read(STDIN_FILENO):  " << (int)buf << endl;
    }
    return false;
}



//////////////////////////////////////////////////////////////////////////////
// udr_socketpump impl.
// a the socketpump class, running two threads

udr_socketpump::udr_socketpump(const char *_name, UDTSOCKET sock, int readhandle, int writehandle) :
        udt_read_thread(*this, &udr_socketpump::udt_read_func),
        udt_write_thread(*this, &udr_socketpump::udt_write_func),
        name(_name),
        socket(sock),
        hread(readhandle),
        hwrite(writehandle)
{
    s_eof = s_err = false;
    h_eof = h_rerr = h_werr = false;
    do_stop = false;
}

bool udr_socketpump::start()
{
    if (!udt_read_thread.start())
        return false;
    if (!udt_write_thread.start())
    {
        udt_read_thread.cancel();
        return false;
    }

    return false;
}

// request a graceful stop of the pump
void udr_socketpump::stop()
{
    do_stop = true;
}

// wait for the pump threads to end
bool udr_socketpump::join()
{
    return udt_read_thread.join() && udt_write_thread.join();
}

// indicate an abnormal state on either pipe or socket
// this indicates that we should gracefully stop the pump
bool udr_socketpump::should_stop()
{
    return  (s_eof || s_err || h_werr || h_rerr || h_eof);
}

void *udr_socketpump::udt_read_func()
{
    while (! (s_eof || s_err || h_werr || do_stop))
    {
        size_t bytes_read;
        bool ok = s_read(bytes_read);
        if (!ok)
            continue;
        if (!bytes_read)
            continue; // timeout, try again or quit
        s_readbuf.used(bytes_read);
        // TODO add crypt step
        char *data = s_readbuf.get();
        size_t data_written = 0;
        // write the data until there is an error
        do
        {
            h_write(data, s_readbuf.get_size(), data_written);
        } while (!h_werr && data_written < s_readbuf.get_size());
    }
    return NULL;
}

void *udr_socketpump::udt_write_func()
{
    // read data until told to stop or there is error or no more data
     while (!(h_eof || h_rerr || s_err || do_stop))
    {
        size_t bytes_read;
        bool ok = h_read(bytes_read);
        if (!ok)
            continue;
        if (!bytes_read)
            continue; // timeout, try again or quit
        h_readbuf.used(bytes_read);
        // TODO add crypt step
        // write the data until there is an error
        char *data = h_readbuf.get();
        size_t data_written = 0;
        do
        {
            s_write(data, h_readbuf.get_size(), data_written);
        } while (!s_err && data_written < h_readbuf.get_size());
    }
    return NULL;
}


// read from handle.  Indicate err, eof, or timeout
bool udr_socketpump::h_read(size_t &bytes_read)
{
    // input file may be non-blocking.  Let's poll it for read for 100ms so that we can also
    // quit if asked to
    struct pollfd fd;
    fd.fd = hread;
    fd.events = POLLIN;
    int  r = poll(&fd, 1, 100);
    if (r == 0) {
        bytes_read = 0;
        return true;  // timeout, no error
    }
    if (r < 0)
    {
        if (errno == EINTR) {
            bytes_read = 0;
            return true;  // treat this as timeout too
        }
        goptions.err(errno) << "in poll() from handle" << endl;
        h_rerr = true;
        return false;
    }

    bytes_read = read(hread, h_readbuf.get(), h_readbuf.get_size());

    if(bytes_read < 0 ){
        if (errno == EAGAIN || errno == EINTR) {
            // timeout or signal interrupt
            return false;
        }
        goptions.err(errno) << "in read() from handle " << endl;
        h_rerr = true;
        return false;
    }
    if(bytes_read == 0) {
        goptions.dbg() << name << " got EOF from handle" << endl;
        h_eof = true;
        return false;
    }
    return true;
}

// should be called with bytes_written as zero. will return without error in case of timeout.
// caller must call this repeatedly to empty the buffer.
bool udr_socketpump::h_write(char *data, size_t len, size_t &bytes_written)
{
    struct pollfd fd;
    fd.fd = hwrite;
    fd.events = POLLOUT;
   
    // poll
    int r = poll(&fd, 1, 100);
    if (r == 0) 
        return false; // timeout
   
    if (r < 0)
    {
        if (errno == EINTR) {
            return true;  // treat this as timeout too
        }
        goptions.err(errno) << "in poll() to handle" << endl;
        h_werr = true;
        return false;
    }
    size_t wrote = write(hwrite, data + bytes_written, len - bytes_written);
    if (wrote > 0) {
        bytes_written += wrote;
        return true;
    } else {
        if (errno == EAGAIN || errno == EINTR)
            return true;
        h_werr = true;
        goptions.err(errno) << "in write() to handle" << endl;
        return false;
    }
    return true;
}

// read from socket.  Indicate err, eof, or timeout
bool udr_socketpump::s_read(size_t &bytes_read)
{
    // read block
    int rs = UDT::recv(socket, s_readbuf.get(), s_readbuf.get_size(), 0);

    if (rs == UDT::ERROR) {
        if (UDT::getlasterror().getErrorCode() == UDT::ERRORINFO::ETIMEOUT) {
            bytes_read = 0;
            return true;
        }
        goptions.err() << "udt recv error: " << UDT::getlasterror().getErrorMessage() << endl;
        s_err = true;
        return false;
    }

    bytes_read = rs;
    if (rs == 0) {
        s_eof = true;
        goptions.dbg() << name << " got EOF" << endl;
        return false;
    }
    return true;
}

// write to socket
//   should be called with bytes_written as zero. will return without error in case of timeout.
// caller must call this repeatedly to empty the buffer.
bool udr_socketpump::s_write(char *data, size_t len, size_t &bytes_written)
{
    int wrote = UDT::send(socket, data + bytes_written, len - bytes_written, 0);
    if (wrote == UDT::ERROR) {
        if (UDT::getlasterror().getErrorCode() == UDT::ERRORINFO::ETIMEOUT) {
            bytes_written= 0;
            return true;
        }
        goptions.err() << " UDT::send(): " << UDT::getlasterror().getErrorMessage() << endl;
        s_err = true;
        return false;
    }
    bytes_written += wrote;
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// udr_buffer impl.

udr_buffer::udr_buffer() :
    buf(0),  bufsize(0), bufused(0)
{}

udr_buffer::~udr_buffer()
{
    if(buf)
        free(buf);
}

char * udr_buffer::get()
{
    return buf ? buf : sbuf;
}

size_t udr_buffer::get_size()
{
    return buf ? bufsize : sizeof(sbuf);
}

size_t udr_buffer::get_used()
{
    return bufused;
}

bool udr_buffer::require(size_t s)
{
    if (s <= get_size())
        return true;
    char *nbuf;
    if (buf)
        nbuf = (char*)realloc(buf, s);
    else
        nbuf = (char*)malloc(s);
    if (nbuf) {
        buf = nbuf;
        bufsize = s;
        return true;
    }
    return false;
}
    
void udr_buffer::used(size_t s)
{
    // growth policy.  If we used more than three quarters of the buf, double the buffer
    if (s > ((get_size() * 3) >> 2))
        require(get_size() * 2);
    bufused = s;
}
