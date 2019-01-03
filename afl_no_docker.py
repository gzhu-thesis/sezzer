#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import stat
import multiprocessing
import subprocess
from utils import build_cmd, run_command_noret

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
            input_opt = '-i {}/input'.format(self._basedir)

        output_opt = '-o {}/output_afl/{}/'.format(self._basedir, self._fid)

        if self._timeout != 0:
            timeout_opt = '-t {} '.format(self._timeout)
        else:
            timeout_opt = ''

        # binary command
        cmd_file = '{}/command.json'.format(self._basedir)
        bin_cmd = ' '.join(build_cmd(cmd_file, basedir=self._basedir))

        node = self.get_node(idx)

        command = ('/tmp/afl-{_ARCH_}/afl-fuzz {_OUTPUT_} '
                   '{_INPUT_} {_TIMEOUT_} {_MODE_} {_NODE_} '
                   '-m none -- {_CMD_} > /dev/null 2>&1')

        return command.format(_ARCH_    = self._arch,
                              _OUTPUT_  = output_opt,
                              _INPUT_   = input_opt,
                              _TIMEOUT_ = timeout_opt,
                              _MODE_    = self._mode,
                              _NODE_    = node,
                              _CMD_     = bin_cmd)


    def prepare_shim(self, command_list):
        if self._resume:
            fname = 'shim_no_docker.resume.sh'
        else:
            fname = 'shim_no_docker.sh'

        fname = '{}/output_afl/{}/{}'.format(self._basedir, self._fid, fname)
        with open(fname, 'w') as shim_sh:
            shim_sh.write('#!/bin/bash\n')
            shim_sh.write('export AFL_NO_UI=1\n')
            shim_sh.write('export LD_LIBRARY_PATH={}/library:$LD_LIBRARY_PATH\n'.format(self._basedir))

            for cmd in command_list:
                shim_sh.write('{} &\n'.format(cmd))

            shim_sh.write('while true; do sleep 1; done;\n')

            os.fchmod(shim_sh.fileno(), stat.S_IRWXU | stat.S_IRWXG | stat.S_IROTH | stat.S_IXOTH)

        return fname


    def launch(self):
        command_list = []
        for idx in range(self._parallel):
            command_list.append(self.get_afl_command(idx))


        shim = self.prepare_shim(command_list)

        # process = multiprocessing.Process(target=run_command_noret, args=[shim])
        # process.start()

        # print shim
        return shim

