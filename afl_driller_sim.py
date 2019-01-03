#!/usr/bin/env python
# -*- coding: utf-8 -*-
''' runtest '''

import os
import sys
import json
import time
import glob
import random
import pprint
import argparse
import traceback
from time import sleep
from datetime import datetime
from multiprocessing import Process, active_children, Queue
import setproctitle

# import utilities
import docker
from utils import print_sep, url_get_file, kill_process
from utils import run_command_ret, run_command_noret, check_dir
from utils import pip_check, get_file_arch, md5sum, unzip, build_cmd



HOME = os.path.dirname(os.path.realpath(__file__))
IMAGE_URL  = 'https://s3.amazonaws.com/cyberimmunitylab.com/pkgs/vms.tar.gz'
AFLDIR     = '{}/afl'.format(HOME)
S2EDIR     = '{}/s2e'.format(HOME)
WATCHERDIR = '{}/coverage'.format(HOME)
EUID       = os.geteuid()

BINARY     = 'binary'
INPUT      = 'input'
LIBRARY    = 'library'
EXPDATA    = 'expdata'
CMD        = 'cmd'
CFG        = 'cfg'
OUTPUT_AFL = 'output_afl'
OUTPUT_S2E = 'output_s2e'
INPUT_S2E  = 'input_s2e'


def run_afl(d_s, argv, queue=None):
    ''' start afl with its own launcher script '''
    import afl_launcher

    launcher_args = dict()
    launcher_args['qemu']      = True                   # qemumode
    launcher_args['fuzz_lib']  = argv['fuzz_lib']       # fuzz library
    launcher_args['debug']     = argv['debug']          # debug
    launcher_args['timeout']   = argv['timeout_afl']    # timeoutofafl
    launcher_args['fid']       = argv['fid']            # file id: first 8 bytes of md5
    launcher_args['uid']       = argv['docker_uid']     # real user id of the container
    launcher_args['docker_img']= argv['docker_afl']     # container name
    launcher_args['arch']      = argv['arch']           # binaryarchitecture
    launcher_args['parallel']  = argv['num_afl']        # numberofaflprocessestorun
    launcher_args['resume']    = argv['resume']
    launcher_args['mode']      = argv['mode_afl']
    launcher_args['basedir']   = d_s['.']
    launcher_args['cmd_file']  = '{}/command.json'.format(d_s['.'])
    launcher_args['masters']   = argv.get('num_master') if argv.get('num_master') is not None else argv.get('num_afl')
    launcher_args['container_name']= argv['docker_afl']

    print_sep()
    print '[C]: args used for launching AFL:'
    print ''
    pprint.pprint(launcher_args)
    print ''

    # call afl launcher
    launcher = afl_launcher.AFLLauncher(launcher_args)
    container = launcher.launch()
    if queue:
        queue.put(container)
    return container


def prepare_dir(dir_name):
    ''' prepare the test directory '''
    d_s = dict()
    d_s['.']       = '{}/'.format(dir_name)
    d_s['input']   = '{}/{}/'.format(dir_name, INPUT)
    d_s['binary']  = '{}/{}/'.format(dir_name, BINARY)
    d_s['cmd']     = '{}/{}/'.format(dir_name, CMD)
    d_s['cfg']     = '{}/{}/'.format(dir_name, CFG)
    d_s['in_afl']  = '{}/{}/'.format(dir_name, OUTPUT_AFL)
    d_s['out_afl'] = '{}/{}/'.format(dir_name, OUTPUT_AFL)
    d_s['in_s2e']  = '{}/{}/'.format(dir_name, INPUT_S2E)    # S2E seed files fetched from database
    d_s['out_s2e'] = '{}/{}/'.format(dir_name, OUTPUT_S2E)
    d_s['library'] = '{}/{}/'.format(dir_name, LIBRARY)
    d_s['expdata'] = '{}/{}/'.format(d_s['out_s2e'], EXPDATA)

    for key in d_s.iterkeys():
        check_dir(d_s[key])

    return d_s


def prepare_template(input_name, input_hash, dir_struct, argv):
    ''' prepare the lua config for s2e as well as bootstrap shell script '''
    current_dir = os.path.dirname(os.path.realpath(__file__))
    basedir = dir_struct['.']

    paths = dict()
    paths['library']  = '{}/library'.format(basedir)
    paths['config']   = '{}/output_s2e/config/{}'.format(basedir, input_hash)
    paths['testcases'] = '{}/output_s2e/testcases'.format(basedir)
    paths['template'] = os.path.join(current_dir, 'templates')

    if argv['arch'] == 'i386':
        paths['tools'] = '{}/build/bin/guest-tools32'.format(S2EDIR)
    elif argv['arch'] == 'x86_64':
        paths['tools'] = '{}/build/bin/guest-tools64'.format(S2EDIR)

    check_dir(paths['config'])
    check_dir(paths['testcases'])


    with open(os.path.join(paths['template'], 'analyze.lua.template.driller')) as f_lua_temp:
        lua_temp = f_lua_temp.read()
    lua_mod = lua_temp.format(PATH_BINARY  = '{}/binary'.format(basedir),
                              PATH_INPUT   = dir_struct['in_s2e'],
                              PATH_LIB     = paths['library'],
                              PATH_TOOLS   = paths['tools'],
                              PATH_CONFIG  = paths['config'],
                              PATH_TESTGEN = paths['testcases'])

    with open('{}/analyze.lua'.format(paths['config']), 'w') as f_lua:
        f_lua.write(lua_mod)

    # build the execute command according to
    # whether the input is from file or stdin ('@@' in command.json)
    command = build_cmd(os.path.join(basedir, 'command.json'))
    command[0] = os.path.basename(command[0])

    # replace the first occurance of '@@' in the command from right
    # if no '@@' found, meaning that input should be piped to stdin
    if '@@' in command:
        command[command.index('@@')] = '${SYMB_FILE}'
    else:
        command.append('< ${SYMB_FILE}')

    exec_cmd = ' '.join(command)

    libs = []
    for _, _, files in os.walk(paths['library']):
        for lib in files:
            libs.append('s2eget "{}"'.format(lib))
        break

    with open(paths['template']+'/bootstrap.sh.template') as f_bootstrap_temp:
        bs_temp = f_bootstrap_temp.read()
    bs_mod = bs_temp.format(_CB    = command[0],
                            _INPUT = '{}'.format(input_hash),
                            _CMD   = exec_cmd,
                            _LIBS  = '\n'.join(libs))

    with open(paths['config']+'/bootstrap.sh', 'w') as f_bs:
        f_bs.write(bs_mod)

    return paths['config']


def prepare_s2e_cmd(config_dir, dir_struct, argv):
    ''' generate S2E command and env '''
    s2e_env = dict()
    basedir = dir_struct['.']
    install_dir="{}/build/".format(S2EDIR)
    s2e_env['S2E_CONFIG']            = "{}/analyze.lua".format(config_dir)
    s2e_env['S2E_OUTPUT_DIR']        = "{}/output_s2e/expdata".format(basedir)
    s2e_env['S2E_SHARED_DIR']        = "{}/share/libs2e".format(install_dir)
    s2e_env['S2E_MAX_PROCESSES']     = '1'
    s2e_env['S2E_UNBUFFERED_STREAM'] = '1'
    s2e_env['LD_PRELOAD']            = "{}/share/libs2e/libs2e-{}-s2e.so".format(install_dir, argv['arch'])
    s2e_env['LD_LIBRARY_PATH']       = '{}/lib:{}'.format(install_dir, '$LD_LIBRARY_PATH')

    qemu_cmd = []
    qemu_cmd.append('{}/bin/qemu-system-{}'.format(install_dir, argv['arch']))
    qemu_cmd.append('-drive file={}/images/debian-8.7.1-{}/image.raw.s2e,format=s2e,cache=writeback'.format(S2EDIR, argv['arch']))
    qemu_cmd.append('-k en-us')
    qemu_cmd.append('-nographic')
    qemu_cmd.append('-monitor null')
    qemu_cmd.append('-m 256M')
    qemu_cmd.append('-enable-kvm')
    qemu_cmd.append('-serial file:/dev/null')
    qemu_cmd.append('-net none')
    qemu_cmd.append('-net nic,model=e1000')
    qemu_cmd.append('-loadvm ready')

    cmd = ' '.join(qemu_cmd)
    return (s2e_env, cmd)



def launch_driller(input_file, input_hash, dir_struct, argv, q):
    setproctitle.setproctitle('Driller Searcher launcher')

    config_dir = prepare_template(input_file, input_hash, dir_struct, argv)
    s2e_env, cmd = prepare_s2e_cmd(config_dir, dir_struct, argv)

    for key, val in s2e_env.iteritems():
        print '{}={} '.format(key,val),
    print cmd

    run_command_noret(cmd, caller='S2E', env=s2e_env, timeout=900, queue=q)


def get_cvg(dir_struct, argv):
    stats_secondary = glob.glob('{}/{}/second*/fuzzer_stats'.format(dir_struct['out_afl'], argv['fid']))
    stats_master = glob.glob('{}/{}/master*/fuzzer_stats'.format(dir_struct['out_afl'], argv['fid']))
    stats = stats_secondary + stats_master
    bitmap_cvg = dict()
    for fuzzer_stats in stats:
        node = os.path.basename(os.path.dirname(fuzzer_stats))
        with open(fuzzer_stats) as f_stats:
            lines = f_stats.read().split('\n')
        for line in lines:
            line = [e.strip() for e in line.split(':')]
            if line[0] == 'bitmap_cvg':
                bitmap_cvg[node] =  line[1]

    return bitmap_cvg






from inotify import adapters
from inotify.constants import IN_CREATE, IN_CLOSE_WRITE, IN_ISDIR
import shutil



def s2e_concolic_testcase_watcher(seedbox, testcases):
    setproctitle.setproctitle('S2E test case watcher')

    processed = set()
    count = 0

    i = adapters.InotifyTree(testcases, mask=IN_CLOSE_WRITE)
    for event in i.event_gen():
        # auto join child process
        if event is None:
            continue

        (_, _, path, filename) = event
        full_name = os.path.join(path,filename)

        md5 = md5sum(full_name)
        if md5 in processed:
            continue
        processed.add(md5)
        count += 1

        dst_file= 'id:{:06d},{}'.format(count, filename)
        dst = '{}/{}'.format(seedbox, dst_file)
        shutil.copyfile(full_name, dst)
        print '[{}] -> [{}]'.format(filename, dst_file)



def execute_aflonly(dir_struct, argv):
    try:
        container = run_afl(dir_struct, argv)
        prev_cvg = dict()

        seedbox_dir = os.path.join(dir_struct['out_afl'], argv['fid'], 'seedbox', 'queue')
        s2e_testcase_dir = '{}/testcases'.format(dir_struct['out_s2e'])

        print 'watching [{}]'.format(s2e_testcase_dir)
        check_dir(seedbox_dir)
        check_dir(s2e_testcase_dir)

        s2e_testcase_handler = Process(target=s2e_concolic_testcase_watcher, args=[seedbox_dir, s2e_testcase_dir])
        s2e_testcase_handler.start()

        processes = list()
        q = Queue()
        while True:
            print 'sleep'
            time.sleep(60)
            # updated = False
            # watch for afl fuzzer_stats change
            cur_cvg = get_cvg(dir_struct, argv)

            # __import__('pprint').pprint(cur_cvg)

            # if not prev_cvg:
            #     prev_cvg = cur_cvg
            #     continue


            # for node, cvg in cur_cvg.iteritems():
            #     if prev_cvg[node] != cvg:
            #         updated = True
            #         break

            # if updated:
            #     continue

            if len(processes) >= argv['num_s2e']:
                print argv['num_s2e']
                for p in processes:
                    print p
                active_children()
                processes[:] = [p for p in processes if p[0].is_alive()]
                continue

            # launch s2e with driller searcher, with .cur_input from first node:
            s2e_node = random.choice(cur_cvg.keys())
            seed = os.path.join(dir_struct['out_afl'], argv['fid'], s2e_node, '.cur_input')
            tmp_input_file = os.path.join(dir_struct['in_s2e'], 'seed')

            shutil.copyfile(seed, tmp_input_file)
            input_hash = md5sum(tmp_input_file)
            input_file = os.path.join(dir_struct['in_s2e'], input_hash)
            shutil.copyfile(tmp_input_file, input_file)

            process = Process(target=launch_driller, args=[input_file, input_hash, dir_struct, argv, q])
            # process.daemon=True
            process.start()
            qemu = q.get(timeout=5)
            processes.append((process,qemu))

    except KeyboardInterrupt:
        for p in processes:
            kill_process(p[0])
            kill_process(p[1])
        docker.from_env().containers.get(container).kill()
        kill_process(s2e_testcase_handler)


def run_fuzz(argv):
    ''' run the test '''
    # working directory name
    working_dir = '{}/cb_{}'.format(argv['cbhome'],
            str(datetime.now().strftime('%Y-%m-%d-%H%M%S.%f')))

    check_dir(working_dir)

    # 1. download from remote or get the file with path
    file_name = url_get_file(argv['uri'], working_dir)

    # 2. unzip the file
    dir_name = unzip(file_name, working_dir)
    argv['tar_file'] = file_name
    print_sep()
    print '[C]: working directory: [{}]'.format(dir_name)

    # prepare the experiment directory structure
    dir_struct = prepare_dir(dir_name)

    # get the architecture of the test binary
    binary = '{}/cb'.format(dir_struct['binary'])
    bin_arch = get_file_arch(binary)[0]
    if bin_arch not in ['32bit', '64bit']:
        print '[C]: unsupported file arch!, exiting now'
        exit(0)
    if bin_arch == '64bit':
        argv['arch'] = 'x86_64'
    if bin_arch == '32bit':
        argv['arch'] = 'i386'

    # first 8 bytes of md5 as file id
    argv['md5sum'] = md5sum(binary)
    argv['fid'] = argv['md5sum'][:8]
    check_dir('{}/{}'.format(dir_struct['out_afl'], argv['fid']))


    # save command to cimfuzz.cmd file
    argv.pop('func', None)
    with open('{}/cimfuzz.cmd'.format(dir_name), 'w') as fuzz_cmd:
        json.dump(argv, fuzz_cmd)

    execute_aflonly(dir_struct, argv)



def setup_argparse():
    ''' parse arguments '''
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    class CheckMinAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            if values < 5:
                parser.error("Minimum check interval for {0} is 5".format(option_string))
            setattr(namespace, self.dest, values)

    # command parser for launching fuzz engine
    sub_run = subparsers.add_parser('run')
    sub_run.set_defaults(func=run_fuzz)
    sub_run.add_argument('--cbhome', type=str, default='/opt/exp-data')
    sub_run.add_argument('--num_afl', type=int, default=5)
    sub_run.add_argument('--num_s2e', type=int, default=1)
    sub_run.add_argument('--timeout_afl', type=int, default=0)
    sub_run.add_argument('--timeout_s2e', type=int, default=900)
    sub_run.add_argument('--docker_uid', type=int, default=EUID)
    sub_run.add_argument('--docker_s2e', type=str, default='s2e_afl')
    sub_run.add_argument('--docker_afl', type=str, default='cim_fuzz')
    sub_run.add_argument('--fuzz_lib', action='store_true')
    sub_run.add_argument('--debug', action='store_true')
    sub_run.add_argument('--resume', action='store_true')
    sub_run.add_argument('--uri', type=str,
            help='The uri of the test archive, should be a .tar.gz or .tgz')
    sub_run.add_argument('--mode_afl', type=str, choices=['qemu', 'normal'], default='qemu')
    sub_run.add_argument('--num_master', type=int, default=None)

    sub_run.add_argument('--s2e_check_interval', type=int, action=CheckMinAction, default=10)
    sub_run.add_argument('--s2e_launch_threshold', type=int, default=4)
    sub_run.add_argument('--s2e_mem_limit', type=int, default=10*1024*1024*1024)
    sub_run.add_argument('--max_testcase_size', type=int, default=50*1024*1024)

    sub_run.add_argument('--cfg', type=str)

    sub_run.add_argument('--database', type=str, default='cyimmu')
    sub_run.add_argument('--user', type=str, default='postgres')
    sub_run.add_argument('--password', type=str, default='postgres')
    sub_run.add_argument('--host', type=str, default='127.0.0.1')
    sub_run.add_argument('--port', type=int, default=5432)

    sub_run.add_argument('--afl_only', action='store_true')


    args = parser.parse_args()
    kwargs = vars(args)


    args.func(kwargs)


if __name__ == "__main__":
    setup_argparse()
