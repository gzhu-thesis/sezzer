#!/usr/bin/env python
# -*- coding: utf-8 -*-
''' runtest
Assumptions:

    The VMs of s2e be placed at S2EDIR/vm/ directory, with
    name i386 and x86_64, the structure should look like:
    ========================================
        $ tree $S2EDIR/vm
        /$S2EDIR/vm
        ├── i386
        │   ├── disk.s2e
        │   └── disk.s2e.saved
        └── x86_64
            ├── disk.s2e
            └── disk.s2e.saved

    ========================================

    tar.gz file structure (take dwarfdump as example):
    ========================================
        $ tree ./test-dwarfdump/
        ./test_dwarfdump/
        ├── binary
        │   └── cb
        ├── cmd
        │   └── command.txt
        ├── input
        │   ├── dummy.elf
        │   └── HELLO.txt
        └── library
            ├── libdwarf.so
            ├── libdwarf.so.1
            ├── libelf-0.158.so
            ├── libelf.so
            └── libelf.so.1
        $ tar -zcf cb.tar.gz ./test-dwarfdump

    ========================================

    Binary be renamed to 'cb'

    The command.txt file should contain the full command used
    to execute the binary, without path infomation:
    ========================================
        $ cat ./test-dwarfdump/cmd/command.txt
        cb -ka -a @@

    ========================================
'''

import os
import sys
import json
import time
import pprint
import argparse
import traceback
from time import sleep
from datetime import datetime
from multiprocessing import Process, active_children, Queue

# import utilities
import docker
from utils import print_sep, url_get_file, kill_process
from utils import run_command_ret, run_command_noret, check_dir
from utils import pip_check, get_file_arch, md5sum, unzip



HOME = os.path.dirname(os.path.realpath(__file__))
IMAGE_URL  = 'https://s3.amazonaws.com/cyberimmunitylab.com/pkgs/vms.tar.gz'
AFLDIR     = '{}/afl'.format(HOME)
S2EDIR     = '{}/s2e'.format(HOME)
WATCHERDIR = '{}/coverage'.format(HOME)
EUID       = os.geteuid()

BINARY     = 'binary'
FILE       = 'file'
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
    setproctitle.setproctitle('cimfuzz FUZZ launcher')

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
    sys.stdout.flush()

    # import afl_no_docker
    # launcher = afl_no_docker.AFLLauncher(launcher_args)
    # container = launcher.launch()
    # return container


    # call afl launcher
    launcher = afl_launcher.AFLLauncher(launcher_args)
    container = launcher.launch()
    if queue:
        queue.put(container)
    return container


def run_watcher(d_s, argv):
    '''execute the directory watcher for each of the AFL instance '''
    setproctitle.setproctitle('cimfuzz file watcher')
    import watcher

    launcher_args = dict()
    db_config = dict()
    db_config['database']        = argv['database']
    db_config['user']            = argv['user']
    db_config['password']        = argv['password']
    db_config['host']            = argv['host']
    db_config['port']            = argv['port']

    launcher_args['db_config']   = db_config
    launcher_args['qemu']        = '{}/qemu-{}'.format(argv['qemu'], argv['arch'])
    launcher_args['project_id']  = argv['project_id']
    launcher_args['max_testcase_size']  = argv['max_testcase_size']
    launcher_args['basedir']     = d_s['.']
    # watcher related
    launcher_args['out_afl']     = '{}/{}'.format(d_s['out_afl'], argv['fid'])
    launcher_args['out_s2e']     = d_s['out_s2e']
    launcher_args['seedbox']     = '{}/seedbox/queue'.format(launcher_args['out_afl'])

    print_sep()
    print '[C]: args used for launching watcher:'
    print ''
    pprint.pprint(launcher_args)
    print ''

    watcher.launch(launcher_args)


def run_s2e(d_s, argv):
    ''' start s2e with its own launcher script '''
    setproctitle.setproctitle('cimfuzz SYM launcher')
    import s2e_launcher

    launcher_args = dict()

    launcher_args['basedir']    = d_s['.']          # /path/to/the/binary/
    launcher_args['process']    = argv['num_s2e']        # number of s2e processes to run
    launcher_args['timeout']    = argv['timeout_s2e']    # timeout time for a single s2e instance
    launcher_args['debug']      = argv['debug']          # debug
    launcher_args['project_id'] = argv['project_id']  # container name
    launcher_args['arch']       = argv['arch']                         # binaryarchitecture
    launcher_args['interval'] = argv['s2e_check_interval']
    launcher_args['threshold'] = argv['s2e_launch_threshold']
    launcher_args['mem_limit'] = argv['s2e_mem_limit']

    db_config = dict()
    db_config['database']       = argv['database']
    db_config['user']           = argv['user']
    db_config['password']       = argv['password']
    db_config['host']           = argv['host']
    db_config['port']           = argv['port']
    launcher_args['db_config']  = db_config


    print_sep()
    print '[C]: args used for launching S2E:'
    print ''
    pprint.pprint(launcher_args)
    print ''
    print_sep()

    launcher = s2e_launcher.S2ELauncher(launcher_args)
    launcher.start()


def prepare_dir(dir_name):
    ''' prepare the test directory '''
    d_s = dict()
    d_s['.']       = '{}/'.format(dir_name)
    d_s['input']   = '{}/{}/'.format(dir_name, INPUT)
    d_s['binary']  = '{}/{}/'.format(dir_name, BINARY)
    d_s['file']    = '{}/{}/'.format(dir_name, FILE)
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


def check_s2e_vm():
    ''' check whether s2e vm images exists '''
    vm_file_list = [
            '{}/vm/i386/disk.s2e'.format(S2EDIR),
            '{}/vm/i386/disk.s2e.saved'.format(S2EDIR),
            '{}/vm/x86_64/disk.s2e'.format(S2EDIR),
            '{}/vm/x86_64/disk.s2e.saved'.format(S2EDIR)
            ]

    need_get = False
    for vm_file in vm_file_list:
        if not os.path.isfile(vm_file):
            need_get = True

    if need_get == False:
        print_sep()
        print '[C]: s2e guest VM images found!'
        return need_get

    # download vm file
    print_sep()
    print '[C]: ONE OR MORE S2E VM IMAGE NOT FOUND at dir [{}/vm]'.format(S2EDIR)
    answer = 'input'
    while answer.lower() not in ['', 'y', 'n', 'yes', 'no']:
        answer = raw_input('Do you want the script to set it up? (Y/n):  ')

    if not answer.lower() in ['', 'y', 'yes']:
        print '[C]: cimfunzz won\'t work without s2e image, Exiting now ...'
        exit(0)

    return need_get


def build_or_import(root_dir, image, import_img=True):
    ''' prepare docker image '''
    image_tar = '{}/DockerImage/{}.tar'.format(root_dir, image)
    if os.path.isfile(image_tar) and import_img:
        print '[C]: FOUND local copy of the image at {}'.format(image_tar)
        print '[C]: Importing docker image from file ...'
        command = 'docker load -i {}'.format(image_tar)
    else:
        if import_img:
            print '[C]: NO local copy of the image found at {}'.format(image_tar)
        print '[C]: Building a new one with Dockerfile at {}/Dockerfile ...'.format(root_dir)
        command = 'docker build -t {} {}/Dockerfile'.format(image, root_dir)

    run_command_noret(command)
    print_sep()
    print '[C]: Build finished ...'


def export_docker_image(image, c_type):
    ''' export docker image to tar file '''
    root_dir = ''
    if c_type == 'afl':
        root_dir = AFLDIR
    elif c_type == 's2e':
        root_dir = S2EDIR

    command = 'docker save {0} -o {1}/DockerImage/{0}.tar'.format(image, root_dir)
    run_command_noret(command)


def check_docker_image_exist(image):
    ''' check whether the docker image already exists '''
    check_cmd = 'docker images -q {}'.format(image)
    exists, _ = run_command_ret(check_cmd)
    if exists:
        return True
    else:
        return False


def check_docker_image(image, c_type):
    ''' check the docker image and prepare the setup '''
    # if docker image already exists
    if check_docker_image_exist(image):
        return (False, False, False)

    print_sep()
    print '[C]: [{}] docker image [{}] not found!'.format(c_type.upper(), image)

    if c_type == 'afl':
        root_dir = AFLDIR
    elif c_type == 's2e':
        root_dir = S2EDIR
    else:
        print '[C]: container type not known, Exiting now ...'
        exit(0)

    # check tar file
    need_import = False
    need_build = False
    need_export = False
    image_tar = '{}/DockerImage/{}.tar'.format(root_dir, image)
    file_exist = os.path.isfile(image_tar)
    if file_exist:
        print '[C]: FOUND local copy of the image at {}'.format(image_tar)
        imp = 'input'
        while imp.lower() not in ['', 'y', 'n', 'yes', 'no']:
            imp = raw_input('Do you want the script to import it? (Y/n):  ')

        if imp.lower() in ['', 'y', 'yes']:
            need_import = True

    if need_import == False or not file_exist:
        build = 'input'
        while build.lower() not in ['', 'y', 'n', 'yes', 'no']:
            build = raw_input('Do you want the script to build the image? (Y/n):  ')

        if build.lower() in ['', 'y', 'yes']:
            need_build = True

            export = 'input'
            while export.lower() not in ['', 'y', 'n', 'yes', 'no']:
                export = raw_input('Export the image to a tar file after build? (Y/n):  ')

            if export.lower() in ['', 'y', 'yes']:
                need_export = True

    return (need_import, need_build, need_export)


def execute_aflonly(dir_struct, argv):
    try:
        container = run_afl(dir_struct, argv)
        while True:
            time.sleep(1)
    except (Exception, KeyboardInterrupt):
        print 'kill container'
        docker.from_env().containers.get(container).kill()
        traceback.print_exc()


def execute(dir_struct, argv):
    ''' launch watcher and execute afl/s2e launcher script '''

    # static analyze
    from analyze import StaticAnalyzer, DB
    db_config = {}
    db_config['host'] = argv['host']
    db_config['port'] = argv['port']
    db_config['database'] = argv['database']
    db_config['user'] = argv['user']
    db_config['password'] = argv['password']
    cfg = os.path.join(dir_struct['cfg'] + os.listdir(dir_struct['cfg'])[0])
    analyzer = StaticAnalyzer(db_config=db_config, cfg=cfg, basedir=dir_struct['.'],
                              tar=argv['tar_file'], arch=argv['arch'])

    processes = []
    container = None
    try:
        print '>'*100
        project_id = analyzer.analyze_static()
        argv['project_id'] = project_id
        print '#'*100
        print 'Project id: {}'.format(project_id)
        print '#'*100

        print '>'*100
        # lauch watcher
        process_watcher = Process(target=run_watcher, args=[dir_struct, argv])
        process_watcher.start()
        processes.append(process_watcher)
        sleep(0.5)
        print '>'*100

        # execute afl
        queue = Queue()
        process_afl = Process(target=run_afl, args=[dir_struct, argv, queue])
        process_afl.daemon = True
        process_afl.start()
        container = queue.get(timeout=1)
        processes.append(process_afl)
        sleep(0.5)
        print '>'*100

        # make s2e launcher as the last compenent
        process_s2e = Process(target=run_s2e, args=[dir_struct, argv])
        process_s2e.start()
        processes.append(process_s2e)
        print '>'*100

        while True:
            time.sleep(1)
    except (Exception, KeyboardInterrupt):
        print 'kill container'
        if container:
            docker.from_env().containers.get(container).kill()
        print 'kill subprocess'
        for p in processes:
            kill_process(p)
        active_children()

        traceback.print_exc()


def check_req(argv):
    ''' check the requirements of cim_fuzz'''

    # check afl docker image
    ret = check_docker_image(argv['docker_afl'], 'afl')
    (import_afl, build_afl, export_afl) = ret
    # (import_afl, build_afl, export_afl) = (False, False, False)

    # check s2e docker image
    # ret = check_docker_image(argv['docker_s2e'], 's2e')
    # (import_s2e, build_s2e, export_s2e) = ret
    (import_s2e, build_s2e, export_s2e) = (False, False, False)

    # check s2e VM images
    # get_s2e_vm = check_s2e_vm()
    get_s2e_vm = False

    # process afl docker image according to check result
    if import_afl:
        build_or_import(AFLDIR, argv['docker_afl'], True)
    if build_afl:
        build_or_import(AFLDIR, argv['docker_afl'], False)
    if export_afl:
        export_docker_image(argv['docker_afl'], 'afl')

    # process s2e docker image according to check result
    if import_s2e:
        build_or_import(S2EDIR, argv['docker_s2e'], True)
    if build_s2e:
        build_or_import(S2EDIR, argv['docker_s2e'], False)
    if export_s2e:
        export_docker_image(argv['docker_s2e'], 's2e')

    # process s2e VM images
    if get_s2e_vm:
        print_sep()
        print '[C]: NOW DOWNLOADING S2E VM IMAGE TARBALL'
        vm_path = '{}/vm'.format(S2EDIR)
        file_name = url_get_file(IMAGE_URL, vm_path)

        print_sep()
        print '[C]: EXTRACTING DOWNLOADED FILE'
        unzip(file_name, vm_path)

    # check python packages
    pip_check('psycopg2')
    pip_check('watchdog')
    pip_check('setproctitle')
    pip_check('docker')
    pip_check('psutil')
    pip_check(check='concurrent', install='futures')
    globals()['docker'] = __import__('docker')
    globals()['setproctitle'] = __import__('setproctitle')

    # check for qemu build (for dynamic basic block coverage)
    curpath = os.path.dirname(os.path.realpath(__file__))
    qemu_1 = '{}/coverage/qemu-x86_64'.format(curpath)
    qemu_2 = '{}/coverage/qemu-i386'.format(curpath)
    if not os.path.isfile(qemu_1) or not os.path.isfile(qemu_2):
        cmd = '{}/coverage/setup.sh'.format(curpath)
        run_command_noret(cmd, debug=True)

    argv['qemu'] = '{}/coverage'.format(curpath)

    print_sep()
    print '[C]: Using docker image [{}] as the afl docker for the test'\
            .format(argv['docker_afl'])
    print '[C]: Using docker image [{}] as the s2e docker for the test'\
            .format(argv['docker_s2e'])


def setup(argv):
    ''' setup '''
    print '[C]: In setup mode, will exit after setup finished'
    docker_afl = argv['docker_afl']
    docker_s2e = argv['docker_s2e']

    if argv['build_docker']:
        build_or_import(AFLDIR, docker_afl, False)
        build_or_import(S2EDIR, docker_s2e, False)

    if argv['export_docker']:
        if not check_docker_image_exist(docker_afl):
            build_or_import(AFLDIR, docker_afl, False)
        export_docker_image(docker_afl, 'afl')

        if not check_docker_image_exist(docker_s2e):
            build_or_import(S2EDIR, docker_s2e, False)
        export_docker_image(docker_s2e, 's2e')

    if argv['import_docker']:
        build_or_import(AFLDIR, docker_afl, True)
        build_or_import(S2EDIR, docker_s2e, True)


def run_fuzz(argv):
    ''' run the test '''
    # check the requirements of cim_fuzz
    check_req(argv)

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

    print "out_afl:{}/{}".format(dir_struct['out_afl'], argv['fid'])

    # save command to cimfuzz.cmd file
    argv.pop('func', None)
    with open('{}/cimfuzz.cmd'.format(dir_name), 'w') as fuzz_cmd:
        json.dump(argv, fuzz_cmd)

    # globals for flask
    if argv['afl_only']:
        execute_aflonly(dir_struct, argv)
    else:
        execute(dir_struct, argv)



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


    # command parser for setup fuzz engine
    sub_setup = subparsers.add_parser('setup')
    sub_setup.set_defaults(func=setup)
    sub_setup.add_argument('--build_docker', action='store_true')
    sub_setup.add_argument('--export_docker', action='store_true')
    sub_setup.add_argument('--import_docker', action='store_true')
    sub_setup.add_argument('--docker_s2e', type=str, default='s2e_afl')
    sub_setup.add_argument('--docker_afl', type=str, default='cim_fuzz')
    sub_setup.add_argument('--debug', action='store_true')

    args = parser.parse_args()
    kwargs = vars(args)

    if args.command == 'setup' and \
        not(args.build_docker or args.export_docker or args.import_docker):
        sub_setup.print_help()
        print '\nAt least one operation is needed in setup mode'
        exit(0)

    args.func(kwargs)


if __name__ == "__main__":
    setup_argparse()
