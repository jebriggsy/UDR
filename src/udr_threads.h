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

#ifndef UDR_THREADS_H
#define UDR_THREADS_H

#include "udr_util.h"
#include "udr_options.h"
#include "crypto.h"

#include <string>

#include <udt.h>


const int max_block_size = 64*1024; //what should this be? maybe based on UDT buffer size?

typedef struct timeout_mon_args{
    FILE * logfile;
    int timeout;
} timeout_mon_args;
    
 
struct thread_data{
    thread_data();
    UDTSOCKET * udt_socket;
    int fd;
    int id;
    crypto * crypt;
    bool debug;
    bool log;
    std::string logfile_dir;
    bool is_complete;
    std::string thread_name;
};

void *handle_to_udt(void *threadarg);
void *udt_to_handle(void *threadarg);

int run_sender(const UDR_Options &udr_options, unsigned char * passphrase, const std::string &remote_cmd);
int run_receiver(const UDR_Options &udr_options);

#endif
