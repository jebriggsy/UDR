# -*- coding: utf-8 -*-
"""
test_simple.py
----------------------------------

Simple test for UDR, test executable runs and help message
"""

from conftest import raise_for_error
from os import path


def test_usage(udr):
    assert b'usage: udr' in udr().stderr.read()

# FIXME
# Doesn't run on github, i think it's something to do with SSH
'''
def test_simple_transfer(udr, fixture_dir, default_args):
    inpath = path.join(fixture_dir, 'fixture1.txt')
    outpath = '/tmp/tixture1_out.txt'
    args = default_args + [inpath, '127.0.0.1:'+outpath]
    assert udr(args).wait() == 0

    with open(inpath, 'r') as f_in:
        with open(outpath, 'r') as f_out:
            assert f_in.read() == f_out.read()
'''
