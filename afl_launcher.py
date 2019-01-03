#!/usr/bin/env python

# kodos  Oct. 2016

# AFL docker launcher
# ---------------------
'''
Task:
    1. for each binary in the given directory
    prepare an input and output directory
    start a AFL container to run the binary

    add the output to a watch list (for the gui)

    2. start a GUI to collect progress information
        port number is a parameter
'''
# ---------------------

import os
import argparse
import stat
import docker
from utils import check_dir, build_cmd


class AFLLauncher(object):

    """Docstring for AFLLauncher. """

    def __init__(self, argv):
        self._resume     = argv.get('resume'   , False)
        self._qemu       = argv.get('qemu'     , True)
        self._fuzz_lib   = argv.get('fuzz_lib' , False)
        self._debug      = argv.get('debug'    , False)
        self._parallel   = argv.get('parallel' , 1)
        self._timeout    = argv.get('timeout'  , 0)
        self._uid        = argv.get('uid'      , os.getuid())
        self._arch       = argv.get('arch'     , 'i386')
        self._fid        = argv.get('fid')
        self._docker_img = argv.get('docker_img')
        self._basedir    = argv.get('basedir')

        self._containers  = []
        self._mode       = '-Q' if argv.get('mode') == 'qemu' else ''
        self._masters    = argv.get('masters', self._parallel)
        self._container_name = argv.get('container_name')


    def get_node(self, launched):
        worker_id = launched + 1
        if worker_id <= self._masters:
            node = '-M master_{:03d}:{}/{}'.format(worker_id, worker_id, self._masters)
        else:
            node = '-S secondary_{:03d}'.format(worker_id - self._masters)

        return node


    def get_afl_command(self, idx):
        ''' Build command '''
        if self._resume:
            input_opt = '-i-'
        else:
            input_opt = '-i /input'

        if self._timeout != 0:
            timeout_opt = '-t {} '.format(self._timeout)
        else:
            timeout_opt = ''

        # binary command
        cmd_file = '{}/command.json'.format(self._basedir)
        bin_cmd = ' '.join(build_cmd(cmd_file, basedir='/'))

        node = self.get_node(idx)

        command = ('/afl-{_ARCH_}/afl-fuzz -o /output '
                   '{_INPUT_} {_TIMEOUT_} {_MODE_} {_NODE_} '
                   '-m none -- {_CMD_} > /dev/null 2>&1')

        return command.format(_ARCH_    = self._arch,
                              _INPUT_   = input_opt,
                              _TIMEOUT_ = timeout_opt,
                              _MODE_    = self._mode,
                              _NODE_    = node,
                              _CMD_     = bin_cmd)


    def map_volumes(self, shim):
        ''' map volumes '''
        volumes = {}
        input_path = '{}/input'.format(self._basedir)
        file_path = '{}/file'.format(self._basedir)
        binary_path = '{}/binary'.format(self._basedir)
        library_path = '{}/library'.format(self._basedir)
        output_path = '{}/output_afl/{}'.format(self._basedir, self._fid)
        check_dir(output_path)

        volumes[input_path] = {'bind': '/input', 'mode': 'ro'}
        volumes[file_path] = {'bind': '/file', 'mode': 'ro'}
        volumes[output_path] = {'bind': '/output', 'mode': 'rw'}
        volumes[binary_path] = {'bind': '/binary', 'mode': 'ro'}
        volumes[library_path] = {'bind': '/library', 'mode': 'ro'}
        volumes[shim] = {'bind': '/shim.sh', 'mode': 'ro'}

        return volumes


    def prepare_shim(self, command_list):
        if self._resume:
            fname = 'shim.resume.sh'
        else:
            fname = 'shim.sh'

        fname = '{}/output_afl/{}/{}'.format(self._basedir, self._fid, fname)
        with open(fname, 'w') as shim_sh:
            shim_sh.write('#!/bin/bash\n')
            shim_sh.write('export AFL_NO_UI=1\n')

            for cmd in command_list:
                shim_sh.write('{} &\n'.format(cmd))

            shim_sh.write('while true; do sleep 1; done;\n')

            os.fchmod(shim_sh.fileno(), stat.S_IRWXU | stat.S_IRWXG | stat.S_IROTH | stat.S_IXOTH)

        return fname



    def container_exec(self, container, command, environment):
        ''' execute command in already existing docker container '''
        # some inconsistency in docker api, can use user id when start launching
        # a container, but can't when exec a command in a existing container

        output_path = '{}/output_afl/{}'.format(self._basedir, self._fid)
        check_dir(output_path)
        container.exec_run(cmd         = command,
                           privileged  = True,
                           detach      = True,
                           # user = user,
                           environment = environment)


    def launch(self):
        """ launch afl docker container """
        client = docker.from_env()

        #########################
        ## common stuff
        environment = {}
        environment['LD_LIBRARY_PATH'] = '/library:$LD_LIBRARY_PATH'
        environment['ALF_NO_UI'] = 'true'
        if self._fuzz_lib:
            environment['AFL_INST_LIBS'] = 'true'


        command_list = []
        for idx in range(self._parallel):
            command_list.append(self.get_afl_command(idx))


        shim = self.prepare_shim(command_list)

        #########################
        ## Volume Mapping
        volumes = self.map_volumes(shim)

        #########################
        ## Ulimit
        ulimits=[{'Name': 'stack', 'Soft': -1, 'Hard': -1}]

        #########################
        ## Execute
        container = None
        try:
            container = client.containers.run(image       = self._docker_img,
                                              command     = '/shim.sh',
                                              name        = self._container_name,
                                              detach      = True,
                                              remove      = True,
                                              auto_remove = True,
                                              privileged  = True,
                                              ulimits     = ulimits,
                                              user        = self._uid,
                                              volumes     = volumes,
                                              environment = environment)
        except Exception:
            try:
                if not container:
                    container = client.containers.get(self._container_name)
                container.stop(timeout=5)
            except Exception:
                pass

        return container.id


def setup_argparse():
    ''' setup_argparse '''
    parser = argparse.ArgumentParser()

    parser.add_argument('--fid', type=str)
    parser.add_argument('--docker_img', type=str, default='cimfuzz-afl')
    parser.add_argument('--uid', type=int, default=0)
    parser.add_argument('--arch', default='x86_64')
    parser.add_argument('--parallel', type=int, default=1)
    parser.add_argument('--timeout', type=int, default=0)
    parser.add_argument('--masters', default=None)
    parser.add_argument('--fuzz_lib', action='store_true', default=False)
    parser.add_argument('--qemu', action='store_true', default=False)
    parser.add_argument('--debug', action='store_true', default=False)
    parser.add_argument('--resume', action='store_true', default=False)
    parser.add_argument('--mode', default='qemu')
    parser.add_argument('--container_name', type=str, default='cimfuzz-afl')
    parser.add_argument('--basedir', default='')
    parser.add_argument('--cmd_file', default='')

    args = parser.parse_args()
    kwargs = vars(args)

    return kwargs


if __name__ == '__main__':
    dict_args = setup_argparse()
    launcher = AFLLauncher(dict_args)
    launcher.launch()

