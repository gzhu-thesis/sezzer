#!/usr/bin/env python
# -*- coding: utf-8 -*-
''' shared utility functions '''
import pkgutil
import shlex
import subprocess
import os
import platform
import tarfile
import hashlib
import urllib2
import json
import socket
import time
from threading import Timer
import pip


def get_available_port():
    """ get a random available port
    :returns: port number

    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def pip_check(check, install=None, url=None):
    """ check if check_name exists, and install install_name if it does not exist

    :check: the package name to be checked
    :install: the package to be installed

    """
    home = os.path.dirname(os.path.realpath(__file__))
    # if pkgutil.find_loader('pip') is None:
    #     pip_url = 'https://bootstrap.pypa.io/get-pip.py'
    #     package_name = os.path.basename(url_get_file(pip_url, home, 'getpip'))
    #     import getpip
    #     getpip.main()

    if pkgutil.find_loader(check) is None:
        if url is not None:
            package_name = os.path.basename(url_get_file(url, home))
        else:
            package_name = install if install is not None else check
        print '[CIMFUZZ]: setting up {}'.format(package_name)

        install_cmd = 'install --user --ignore-installed {}'.format(package_name)
        pip.main(shlex.split(install_cmd))


def run_command_noret(command, timeout=None, caller='CIMFUZZ', debug=False, queue=None, env=None):
    ''' execute command with subprocess and capture output '''
    cmd_list = shlex.split(command)

    # if env is None:
    #     env=os.environ.copy()

    if debug:
        process = subprocess.Popen(cmd_list,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                shell=False,
                                env=env)

        # if we pass in a queue to record the process information
        if queue is not None:
            queue.put(process)

        try:
            if timeout is not None:
                timer = Timer(timeout, kill_process, args=(process,timeout, command))
                timer.start()

            while process.poll() is None:
                line = process.stdout.readline()
                print '[{}]: {}'.format(caller, line),
            print '[{}]: {}'.format(caller, process.stdout.read())
        finally:
            if timeout is not None:
                timer.cancel()

    else:
        with open(os.devnull, 'wb') as devnull:
            stdin = None
            if cmd_list[-2] == '<':
                stdin = cmd_list[-1]
                cmd_list = cmd_list[:-2]

            process = subprocess.Popen(cmd_list,
                                       stdout=devnull,
                                       stderr=devnull,
                                       stdin=subprocess.PIPE,
                                       shell=False,
                                       env=env)

            # if we pass in a queue to record the process information
            if queue is not None:
                queue.put(process)

            try:
                if timeout is not None:
                    timer = Timer(timeout, kill_process, args=(process, timeout, command, env))
                    timer.start()

                process.communicate(stdin)
            except Exception:
                print 'S2E process communicate error'
                raise
            finally:
                # kill_process(process)
                if timeout is not None:
                    timer.cancel()


def run_command_ret(command, timeout=None):
    ''' execute command with subprocess and return output '''
    cmd_list = shlex.split(command)
    process = subprocess.Popen(cmd_list,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=False)
    return process.communicate()


def kill_process(process, timeout=None, command=None, env=None):
    ''' try to kill the subprocess.Popen() ed process '''
    pid = process.pid
    failed = False
    try:
        os.kill(pid, 9)
    except OSError:
        failed = True
    finally:
        if failed:
            print 'failed to kill process ({}) with timeout ({})'.format(pid, timeout)
        else:
            if timeout:
                print 'process ({}) terminated with timeout ({})'.format(pid, timeout)
            if env:
                print env
            if command:
                print command



def get_terminal_width():
    ''' get the current width of the terminal '''
    size, _ = run_command_ret('stty size')

    if size:
        try:
            return [int(i) for i in size.split()]
        except Exception:
            pass
    return [0, 50]


def print_sep():
    ''' print seperate line according to the terminal size '''
    size = get_terminal_width()
    print '-' * int(size[1])


def get_file_arch(binary):
    ''' get the architecture of the input binary '''
    return platform.architecture(binary)


def unzip(file_name, target_dir):
    ''' unzip the gzip file downloaded from remote and return the full
        path to unzipped directory '''
    try:
        tar = tarfile.open(file_name, 'r:gz')
        # assume the first node in the gzip file is the directory
        dir_name = tar.getnames()[0]
        # extract to target_dir
        tar.extractall(target_dir)
        tar.close()
    except Exception as excpt:
        raise excpt

    return '{}/{}'.format(target_dir, dir_name)


def check_dir(path):
    ''' create directory if not exists '''
    if not os.path.exists(path):
        try:
            os.makedirs(path)
        except OSError as exc: # Guard against race condition
            if exc.errno != os.errno.EEXIST:
                raise


def md5sum(binary):
    ''' calculate md5 hash of an input file '''
    hash_md5 = hashlib.md5()
    with open(binary, "rb") as file_d:
        for chunk in iter(lambda: file_d.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def url_get_file(uri, target_dir, target_name=None):
    ''' get file from an url '''
    file_size_dl = 0
    block_sz = 8192

    # try to format uri if start with '/' or '.'
    if uri.startswith('/') or uri.startswith('.'):
        uri = 'file://{}'.format(os.path.realpath(uri))

    print uri
    request = urllib2.urlopen(uri)
    meta = request.info()
    file_size = int(meta.getheaders("Content-Length")[0])
    print_sep()
    print "[CIMFUZZ]: Downloading:  [{}]".format(uri)
    print "[CIMFUZZ]: Size of file: [{}]".format(file_size)

    if target_name is None:
        file_name = '{}/{}'.format(target_dir, uri.split('/')[-1])
    else:
        file_name = '{}/{}'.format(target_dir, target_name)
    gz_file = open(file_name, 'wb')

    # print the progress
    status = ''
    bar_size = get_terminal_width()[1] / 2
    progress_size = 0
    blank_size = bar_size - progress_size
    os.system('setterm -cursor off')
    while True:
        buf = request.read(block_sz)
        if not buf:
            print '\n[CIMFUZZ]: Download Finished!'
            break

        if len(status) > 0:
            print chr(8)*(len(status)+2),

        file_size_dl += len(buf)
        percentage = float(file_size_dl) / file_size
        gz_file.write(buf)

        progress_size = int(bar_size * percentage)
        blank_size = bar_size - progress_size

        status = "[{0}{1}] {2:d}/{3:d}   [{4:.2%}]"\
                      .format('*' * progress_size,
                              ' ' * blank_size,
                              file_size_dl,
                              file_size,
                              percentage)
        print status,

    os.system('setterm -cursor on')
    gz_file.close()

    return file_name


def is_elf(f):
    fd = os.open(f,os.O_RDONLY)
    try:
        magic=os.read(fd,4)
    except:
        return False
    os.close(fd)
    if magic[1:] == 'ELF':
        return True
    else:
        return False


def serialize_sql(target, content):
    """ serialize sql template and store in target file """
    with open(target, 'a') as f:
        json.dump(content, f)


def build_cmds(basedir):
    ''' parse command file and build execute command of binary '''
    ret = []
    cmd_dir = '{}/cmd'.format(basedir)
    for root, _, files in os.walk(cmd_dir):
        for cmd_file in files:
            cmd_file = '{}/{}'.format(root, cmd_file)
            cmd = build_cmd(cmd_file, basedir=basedir)
            ret.append(cmd)
        break

    return ret


def build_cmd(cmd_file, basedir=None):
    ''' parse command file and build execute command of binary '''

    cmd = []
    basedir = basedir if basedir is not None else os.path.dirname(cmd_file)

    with open(cmd_file, 'r') as f_cmd:
        cmd_dict = json.load(f_cmd)

    cmd_len = cmd_dict.get('cmd_len')

    for idx in range(cmd_len):
        detail = cmd_dict.get('pos_{}'.format(idx))
        if detail['type'] in ('opt', 'input'):
            cmd.append(detail['value'])
        else:
            target = '{}/{}/{}'.format(basedir, detail['type'], detail['target'])
            cmd.append(detail['value'].format(target))

    return cmd

