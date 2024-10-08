# -*- coding: utf-8 -*-
"""
conftest.py
----------------------------------

Setup for UDR pytest test suite
"""

from subprocess import Popen, PIPE
from os.path import dirname, realpath, join
from os import environ

import pytest


def raise_for_error(proc):
    """Raises a RuntimeError if :param:`proc` did not exit successfully"""

    proc.poll()
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.read())


@pytest.fixture(scope='session')
def ssh_port():
    return environ.get('UDT_SSH_PORT', '10022')


@pytest.fixture(scope='session')
def src_dir():
    return join(dirname(dirname(realpath(__file__))), 'src')


@pytest.fixture(scope='session')
def udr_path(src_dir):
    return join(src_dir(), 'udr')


@pytest.fixture(scope='session')
def fixture_dir():
    return join(dirname(dirname(realpath(__file__))), 'tests', 'fixtures')


@pytest.fixture(scope='session')
def default_args(udr_path, ssh_port):
    return [
        '-v',
        '-c'+udr_path,
        '-P'+ssh_port,
        'rsync',
    ]

@pytest.fixture
def udr(udr_path, src_dir):
    """Returns a Popen partial function to run UDR"""

    # Return a partial to start the process (savinging it in closure
    # bound _process to clean up later)
    processes = []
    def start_udr(args=[]):
        """Starts udr with arguments :param:`args`"""
        print(f'Running with args {args}')
        process = Popen([udr_path]+list(args), stdout=PIPE, stderr=PIPE)
        processes.append(process)
        return processes[-1]

    yield start_udr

    for process in processes:
        process.wait()
