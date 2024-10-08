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
#include <iostream>
#include <memory>
#include <stdlib.h>

#include <cstdlib>
#include <cstring>
#include <cstdio>

#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

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


