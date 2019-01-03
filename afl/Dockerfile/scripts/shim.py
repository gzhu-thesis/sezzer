#!/usr/bin/env python

# kodos,  Oct 2016

# AFL docker management
# ---------------------
# Assumptions:
#   - target binary in /cbs/
#   - initial inputs for the cb are in /input
#   - outputs are in /output
#
# ---------------------

#import logging
import os
import argparse
import subprocess
import multiprocessing
import shlex

def get_terminal_width():
    ''' get the current width of the terminal '''
    cmd = shlex.split('stty size')
    process = subprocess.Popen(cmd, shell=False,
                            stderr=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    size, _ = process.communicate()

    if size:
        try:
            return [int(i) for i in size.split()]
        except Exception as _:
            pass
    return [0, 50]


def print_sep():
    ''' print seperate line according to the terminal size '''
    size = get_terminal_width()
    print '-' * size[1]


def launch(argv, worker_id):
    cmd = ""

    # always assume libpath
    cmd += 'LD_LIBRARY_PATH=/cblib:$LD_LIBRARY_PATH '

    if argv['fuzz_lib']:
        cmd += 'AFL_INST_LIBS=TRUE '

    if argv['timeout'] != '0':
        # print "run AFL for "+argv['timeout']+" seconds"
        cmd = "timeout "+argv['timeout']+" "

    if argv['arch'] == "i386":
        cmd += "/afl-i386/"
    else:                # default use x86_64
        cmd += "/afl-x86_64/"

    cmd += "afl-fuzz "

    # AFL option, default [qemu]
    if argv['qemu']:
        cmd += " -Q "

    if argv['dummy']:
        cmd += " -n "

    # in & out dirs
    if argv['resume']:
        cmd += " -i- "
    else:
        cmd += " -i " + argv['input']
    cmd += " -o " + argv['output']

    # if worker_id == 0:
    #     cmd += " -M master "
    # else:
    #     cmd += " -S slave{:02d}".format(worker_id)

    cmd += ' -M master_{}:{}/{} '.format(worker_id+1, worker_id+1, argv['parallel'])


    # if argv['arch'] == "i386":
    cmd += ' -m none'

    cmd += " -- " + " ".join(argv['cmdargs'])

    # wrap with 'bash -c'
    cmd = "bash -c '" + cmd + "'"

    print_sep()
    print 'launching afl instance with command:'
    print cmd

    # disable afl display
    # dup file handler?

    #result = subprocess.check_output(cmd, shell=True)

    cmd_list = shlex.split(cmd)

    if argv['debug']:
        p = subprocess.Popen(cmd_list,
                            shell=False,
                            stdout=subprocess.PIPE)
        while p.poll() is None:
            print p.stdout.readline(),
        print p.stdout.read()
    else:
        DEVNULL = open(os.devnull, 'wb')
        p = subprocess.Popen(cmd_list, stdout=DEVNULL, stderr=DEVNULL, shell=False)
        p.communicate()


def main(argv):
    # start the master anyway
    threads = []
    p = multiprocessing.Process(target=launch, args=[argv, 0])
    p.start()
    threads.append(p)

    # start n-1 slaves
    n_instances = argv['parallel']
    while n_instances > 1:
        n_instances -= 1
        p = multiprocessing.Process(target=launch, args=[argv, n_instances])
        p.start()
        threads.append(p)


def setup_argparse():
    parser = argparse.ArgumentParser()

    parser.add_argument('--timeout', default='0')
    parser.add_argument('--arch', default='x86_64')
    parser.add_argument('--cbname', default='/cbs/cb')
    parser.add_argument('--infile', action='store_true', default=False)
    parser.add_argument('--input', default='/input')
    parser.add_argument('--output', default='/output')
    parser.add_argument('--qemu', action='store_true', default=False)
    parser.add_argument('--dummy', action='store_true', default=False)
    parser.add_argument('--fuzz_lib', action='store_true', default=False)
    parser.add_argument('--resume', action='store_true', default=False)
    parser.add_argument('--parallel', type=int, default=1)
    parser.add_argument('--debug', action='store_true', default=False)
    parser.add_argument('cmdargs', type=str, help='cb cmdline arguments', nargs='*')

    args = parser.parse_args()
    kwargs = vars(args)
    return kwargs

if __name__ == '__main__':
    dict_args = setup_argparse()
    main(dict_args)

