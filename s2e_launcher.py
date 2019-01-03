#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import time
import glob
import random
import traceback
from io import BytesIO
from multiprocessing import active_children, Process, Manager
from Queue import Empty, Full
import threading
import psutil
import psycopg2
from setproctitle import setproctitle

from utils import check_dir, run_command_noret, kill_process, build_cmd

from inotify import adapters
from inotify.constants import IN_CREATE, IN_CLOSE_WRITE, IN_ISDIR

class S2ELauncher(object):
    """Docstring for S2ELauncher. """
    def __init__(self, argv):
        # docker + s2e variables
        self._basedir     = argv.get('basedir')
        self._project_id  = argv.get('project_id')
        self._db_config   = argv.get('db_config')
        self._max_process = argv.get('process'   , 1)      #number of s2e instances
        self._timeout     = argv.get('timeout'   , 300)
        self._debug       = argv.get('debug'     , False)
        self._arch        = argv.get('arch'      , 'i386')
        self._interval    = argv.get('interval'  , 10)
        self._threshold   = argv.get('threshold' , 4)
        self._mem_limit   = argv.get('mem_limit' , 10 * 1024 * 1024 * 1024)
        self._command = build_cmd('{}/command.json'.format(self._basedir), basedir='./')

        needles = ['.//file/', './/binary/']
        for idx, ele in enumerate(self._command):
            for needle in needles:
                if ele.startswith(needle):
                    self._command[idx] = ele.replace(needle, '', 1)

        self._covered_count = 0
        self._S2EDIR = '{}/s2e'.format(os.path.dirname(os.path.realpath(__file__)))


    def prepare_template_symbolic(self, input_name, input_hash):
        ''' prepare the lua config for s2e as well as bootstrap shell script '''
        current_dir = os.path.dirname(os.path.realpath(__file__))

        paths = dict()
        paths['library']  = '{}/library'.format(self._basedir)
        paths['file']  = '{}/file'.format(self._basedir)
        paths['config']   = '{}/output_s2e/config/{}'.format(self._basedir, input_hash)
        paths['testcases'] = '{}/output_s2e/testcases'.format(self._basedir)
        paths['template'] = os.path.join(current_dir, 'templates')

        if self._arch == 'i386':
            paths['tools'] = '{}/build/bin/guest-tools32'.format(self._S2EDIR)
        elif self._arch == 'x86_64':
            paths['tools'] = '{}/build/bin/guest-tools64'.format(self._S2EDIR)

        check_dir(paths['config'])
        check_dir(paths['testcases'])

        with open(os.path.join(paths['template'], 'analyze.lua.template.sym')) as f_lua_temp:
            lua_temp = f_lua_temp.read()
        lua_mod = lua_temp.format(_DEBUG       = 'debug',
                                  PATH_BINARY  = '{}/binary'.format(self._basedir),
                                  PATH_INPUT   = '{}/input_s2e'.format(self._basedir),
                                  PATH_LIB     = paths['library'],
                                  PATH_FILE    = paths['file'],
                                  PATH_TOOLS   = paths['tools'],
                                  PATH_CONFIG  = paths['config'],
                                  PATH_TESTGEN = paths['testcases'])

        with open('{}/analyze.lua'.format(paths['config']), 'w') as f_lua:
            f_lua.write(lua_mod)

        # build the execute command according to
        # whether the input is from file or stdin ('@@' in command.json)
        command = self._command[:]

        # replace the first occurance of '@@' in the command from right
        # if no '@@' found, meaning that input should be piped to stdin
        if '@@' in command:
            command[command.index('@@')] = '${SYMB_FILE}'
        else:
            command.append('< ${SYMB_FILE}')

        exec_cmd = ' '.join(command)
        print exec_cmd

        files = []
        for target in glob.glob(os.path.join(paths['file'], '*')):
            files.append('{} "{}"'.format('${S2EGET}', os.path.basename(target)))

        lib_cmd = 'LD_PRELOAD="./s2e.so'
        for lib in glob.glob(os.path.join(paths['library'], '*')):
            files.append('{} "{}"'.format('${S2EGET}', os.path.basename(lib)))
            lib_cmd += ' ./{}'.format(os.path.basename(lib))
        lib_cmd += '"'

        with open(paths['template']+'/bootstrap.sh.template') as f_bootstrap_temp:
            bs_temp = f_bootstrap_temp.read()
        bs_mod = bs_temp.format(_CB    = command[0],
                                _FILES  = '\n'.join(files),
                                _INPUT = '{}_{}'.format(input_hash, input_name),
                                _LIB_CMD = lib_cmd,
                                _CMD   = exec_cmd)

        with open(os.path.join(paths['config'], 'bootstrap.sh'), 'w') as f_bs:
            f_bs.write(bs_mod)

        print os.path.join(paths['config'], 'bootstrap.sh')

        return paths['config']


    def prepare_template(self, input_name, input_hash, interested):
        ''' prepare the lua config for s2e as well as bootstrap shell script '''
        # interester -> [[ input_id, interested_id, bb_start, bb_end, uri, bb_id ]]
        current_dir = os.path.dirname(os.path.realpath(__file__))
        interested , count_bbs= interested

        paths = dict()
        paths['config']   = '{}/output_s2e/config/{}'.format(self._basedir, input_hash)
        paths['testcases'] = '{}/output_s2e/testcases'.format(self._basedir)
        paths['library']  = '{}/library'.format(self._basedir)
        paths['file']  = '{}/file'.format(self._basedir)
        paths['template'] = '{}/templates'.format(current_dir)
        paths['binary'] = '{}/binary'.format(self._basedir)
        paths['bblog']    = '{}/output_s2e/BBLog'.format(self._basedir)

        check_dir(paths['config'])
        check_dir(paths['testcases'])
        check_dir(paths['bblog'])

        entry = '''
            entry_{} = {{ {}, {}, {} , {} , {} }},'''
        entries = [entry.format(row[1], row[2], row[3], row[0], row[1], row[5]) for row in interested]

        if self._arch == 'i386':
            paths['tools'] = '{}/build/bin/guest-tools32'.format(self._S2EDIR)
        elif self._arch == 'x86_64':
            paths['tools'] = '{}/build/bin/guest-tools64'.format(self._S2EDIR)

        modules = ''
        tmp_module = ('    mod_{} = {{\n'
                      '        moduleName = "{}",\n'
                      '        kernelMode = false,\n'
                      '    }},\n')

        module_idx = 0
        for idx, cb in enumerate(glob.glob(os.path.join(paths['binary'], '*'))):
            modules = modules + tmp_module.format(idx, os.path.basename(cb))
            module_idx = idx

        for idx, lib in enumerate(glob.glob(os.path.join(paths['library'], '*'))):
            modules = modules + tmp_module.format(module_idx+idx+1, os.path.basename(lib))

        with open(paths['template']+'/analyze.lua.template') as f_lua_temp:
            lua_temp = f_lua_temp.read()

        lua_mod = lua_temp.format(_DEBUG       = 'debug',
                                  MODULES      = modules,
                                  IDX_INPUT    = interested[0][0],
                                  PATH_BINARY  = '{}/binary'.format(self._basedir),
                                  PATH_INPUT   = '{}/input_s2e'.format(self._basedir),
                                  PATH_LIB     = paths['library'],
                                  PATH_FILE    = paths['file'],
                                  PATH_TOOLS   = paths['tools'],
                                  PATH_CONFIG  = paths['config'],
                                  PATH_TESTGEN = paths['testcases'],
                                  PATH_BBLOG   = paths['bblog'],
                                  TOTAL_TBS    = count_bbs,
                                  ENTRIES      = ''.join(entries))

        with open('{}/analyze.lua'.format(paths['config']), 'w') as f_lua:
            f_lua.write(lua_mod)

        # build the execute command according to
        # whether the input is from file or stdin ('@@' in command.json)
        command = self._command[:]

        # replace the first occurance of '@@' in the command from right
        # if no '@@' found, meaning that input should be piped to stdin
        if '@@' in command:
            command[command.index('@@')] = '${SYMB_FILE}'
        else:
            command.append('< ${SYMB_FILE}')

        exec_cmd = ' '.join(command)

        files = []
        for target in glob.glob(os.path.join(paths['file'], '*')):
            files.append('{} "{}"'.format('${S2EGET}', os.path.basename(target)))

        lib_cmd = 'LD_PRELOAD="./s2e.so'
        for lib in glob.glob(os.path.join(paths['library'], '*')):
            files.append('{} "{}"'.format('${S2EGET}', os.path.basename(lib)))
            lib_cmd += ' ./{}'.format(os.path.basename(lib))
        lib_cmd += '"'

        with open(paths['template']+'/bootstrap.sh.template') as f_bootstrap_temp:
            bs_temp = f_bootstrap_temp.read()
        bs_mod = bs_temp.format(_CB    = command[0],
                                _FILES  = '\n'.join(files),
                                _INPUT = '{}_{}'.format(input_hash, input_name),
                                _LIB_CMD = lib_cmd,
                                _CMD   = exec_cmd)

        with open(paths['config']+'/bootstrap.sh', 'w') as f_bs:
            f_bs.write(bs_mod)

        return paths['config']


    @staticmethod
    def sql_insert_interested(conn, seed, proj_id):
        ''' insert the interested records into database '''
        cur = conn.cursor()
        idinput = seed[0]

        # XXX: we want random 100 out of the 150 basic blocks for extra randomness
        if len(seed[1]['bbs']) > 100:
            random_bbs = random.sample(seed[1]['bbs'], 100)
        else:
            random_bbs = seed[1]['bbs']
        gen = ('{}\t{}\t{}\t1\n'.format(proj_id, idinput, x[0]) for x in random_bbs) #pylint: disable=E1136
        bio = BytesIO(''.join(gen))
        query = (
            'CREATE temp TABLE tmp_interested AS '
            '  SELECT * '
            '    FROM interested '
            '  WHERE  FALSE ')
        cur.execute(query)

        cur.copy_from(bio,
                      'tmp_interested',
                      columns=('idproject', 'idinput', 'idbasic_block', 'status'))

        query = (
            'insert into interested '
            '       (idproject, idinput, idbasic_block, status) '
            'select tmp.idproject, '
            '       tmp.idinput, '
            '       tmp.idbasic_block, '
            '       tmp.status '
            '  from tmp_interested tmp '
            'on conflict do nothing;')

        cur.execute(query)
        conn.commit()


    @staticmethod
    def sql_select_interested_id(conn, idinput):
        ''' get the id of the inserted interested input + basic block '''
        cur = conn.cursor()
        query = ('SELECT  i.idinput, '
                 '        i.id, '
                 '        b.start_addr, '
                 '        b.end_addr, '
                 '        i.uri, '
                 '        b.id '
                 'FROM   interested i '
                 '       inner join basic_block b '
                 '                ON i.idbasic_block = b.id '
                 'WHERE  b.status = 1 '
                 'AND    i.status = 1 '
                 'AND    i.idinput = %s; ')

        cur.execute(query, (idinput, ))

        interested = cur.fetchall()

        # change status
        query = ('UPDATE interested AS i '
                 'SET    status = 2 '
                 'FROM   basic_block AS b '
                 'WHERE  i.status = 1 '
                 'AND    i.idbasic_block = b.id '
                 'AND    b.status = 1 '
                 'AND    i.idinput = %s; ')
        cur.execute(query, (idinput, ))

        if cur.rowcount != len(interested):
            print 'update interested row count not match'
            print idinput, cur.rowcount, len(interested)
            # conn.rollback()
            # conn.close()
            # return
        conn.commit()

        # get the number of basic blocks executed by this particular input
        query = ('SELECT sum(count) '
                 'FROM   coverage '
                 'WHERE  idinput = %s; ')
        cur.execute(query, (idinput, ))
        count_bbs = cur.fetchall()[0][0]

        return (interested, count_bbs)


    @staticmethod
    def sql_get_file_content(conn, idinput):
        ''' get the binary and input from database '''
        cur = conn.cursor()
        query = ('SELECT f.file, '
                 '       i.uri, '
                 '       f.hash '
                 'FROM   file f, '
                 '       input i '
                 'WHERE  f.id = i.idfile '
                 'AND    i.id = %s; ')
        cur.execute(query, (idinput, ))
        return cur.fetchone()


    def pg_conn(self):
        ''' get a connection to the postgres database with psycopg2 '''
        while True:
            try:
                conn = psycopg2.connect(database=self._db_config['database'],
                                        user=self._db_config['user'],
                                        password=self._db_config['password'],
                                        host=self._db_config['host'],
                                        port=self._db_config['port'])
                return conn
            except psycopg2.OperationalError:
                print 'S2E: Error during connect, retry now...'
                continue


    def prepare_s2e_cmd(self, config_dir):
        ''' generate S2E command and env '''
        s2e_env = dict()
        install_dir="{}/build/".format(self._S2EDIR)
        s2e_env['S2E_CONFIG']            = "{}/analyze.lua".format(config_dir)
        s2e_env['S2E_OUTPUT_DIR']        = "{}/output_s2e/expdata".format(self._basedir)
        s2e_env['S2E_SHARED_DIR']        = "{}/share/libs2e".format(install_dir)
        s2e_env['S2E_MAX_PROCESSES']     = '1'
        s2e_env['S2E_UNBUFFERED_STREAM'] = '1'
        s2e_env['LD_PRELOAD']            = "{}/share/libs2e/libs2e-{}-s2e.so".format(install_dir, self._arch)
        s2e_env['LD_LIBRARY_PATH']       = '{}/lib:{}'.format(install_dir, '$LD_LIBRARY_PATH')

        qemu_cmd = []
        qemu_cmd.append('{}/bin/qemu-system-{}'.format(install_dir, self._arch))
        qemu_cmd.append('-drive file={}/images/debian-8.7.1-{}/image.raw.s2e,format=s2e,cache=writeback'.format(self._S2EDIR, self._arch))
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


    def prepare_input(self, input_content, input_name, input_hash):
        ''' write test input for S2E '''
        # input_content, uri, input_hash = file_content
        fname = '{}/input_s2e/{}_{}'.format(self._basedir, input_hash, input_name)
        with open(fname, 'wb') as file_input:
            file_input.write(str(input_content))


    def worker(self, seed, queue):
        ''' worker '''
        setproctitle('launching S2E with input idx:[{}]'.format(seed[0]))

        # get the concolic input from database
        conn = self.pg_conn()
        self.sql_insert_interested(conn, seed, self._project_id)
        interested = self.sql_select_interested_id(conn, seed[0])
        input_content, uri, input_hash = self.sql_get_file_content(conn, seed[0])
        conn.close()
        input_name = os.path.basename(uri)

        self.prepare_input(input_content, input_name, input_hash)

        # setup config file, in/out path
        config_dir = self.prepare_template(input_name, input_hash, interested)
        # build command and env
        s2e_env, cmd = self.prepare_s2e_cmd(config_dir)

        # print debug
        node  = os.path.basename(os.path.dirname(os.path.dirname(uri)))
        print '-' * 100
        print '[S2E]: launching S2E with test input [{}:{}] as seed.'.format(node, input_name)
        for key, val in s2e_env.iteritems():
            print '{}={} '.format(key,val),
        print cmd
        print '-' * 100

        run_command_noret(cmd, caller='S2E', queue=queue, timeout=self._timeout, env=s2e_env)


    def sql_get_symbolic_input(self):
        ''' prepare symbolic input for pure symbolic S2E execution '''
        conn = self.pg_conn()
        cur = conn.cursor()
        # query =('CREATE EXTENSION IF NOT EXISTS TSM_SYSTEM_ROWS;')
        # cur.execute(query)

        # get all the possible id
        query = ('SELECT i.id FROM input i, file f '
                 'WHERE i.idproject = %s '
                 'AND   i.idfile = f.id '
                 'AND   octet_length(f.file) > 256;')
        cur.execute(query, (self._project_id, ))

        if cur.rowcount > 0:
            ids = cur.fetchall()
            idinput = random.choice(ids)
            content = self.sql_get_file_content(conn, idinput)
        else:
            content = ('A'*256, 'INPUT', 'B3EFB0EBA6FBC059ABB5A59E8E78E4FE')

        conn.close()
        return content


    def launch_symbolic(self, queue):
        ''' launch S2E with pure symbolic input '''
        # check get candidate input seed
        input_content, uri, input_hash = self.sql_get_symbolic_input()
        input_name = os.path.basename(uri)
        self.prepare_input(input_content, input_name, input_hash)

        config_dir = self.prepare_template_symbolic(input_name, input_hash)
        s2e_env, cmd = self.prepare_s2e_cmd(config_dir)

        for key, val in s2e_env.iteritems():
            print '{}={} '.format(key,val),
        print cmd

        run_command_noret(cmd, caller='S2E', queue=queue, env=s2e_env, timeout=300)


    def sql_check_increament(self):
        ''' check increament '''
        conn = self.pg_conn()
        cur = conn.cursor()

        # 1. select count of the covered bb's "as of now"
        query = ('SELECT count(distinct(c.idbasic_block)) '
                 'FROM   coverage c '
                 'WHERE  c.idproject = %s;')

        cur.execute(query, (self._project_id, ))
        new_count = cur.fetchone()[0]
        conn.close()

        print '>'*100
        print "[S2E]: BB coverage [{}] -> [{}]".format(self._covered_count, new_count)
        print '<'*100

        increament, self._covered_count = new_count-self._covered_count, new_count
        return increament


    def sql_get_seeds(self):
        ''' query the database and return the interested input and basic blocks '''
        conn = self.pg_conn()
        cur = conn.cursor()

        # create temporary table for potential basic blocks
        query = 'DROP TABLE IF EXISTS potential;'
        cur.execute(query)

        # All the predecessors of basic blocks that are
        # NOT covered by existing inputs(not in coverage table)
        query = (
            'CREATE temp TABLE potential AS '
            '  SELECT DISTINCT e.from_bb AS id '
            '  FROM   edge e '
            '         inner join basic_block b '
            '                 ON e.to_bb = b.id '
            '         inner join content c '
            '                 ON b.idcontent = c.id '
            '         left join coverage '
            '                ON b.id = coverage.idbasic_block '
            '  WHERE  c.idproject = %s '
            '     AND coverage.idbasic_block IS NULL; ')
        cur.execute(query, (self._project_id,))

        query = 'create unique index on potential (id);'
        cur.execute(query)

        # select input seeds base on potential basic blocks:
        # for each record in the potential table, find out which inputs have covered that record
        query = (
            'SELECT c.idinput, '
            '       c.idbasic_block '
            'FROM   coverage c '
            '       inner join potential p '
            '               ON c.idbasic_block = p.id '
            '       left join interested i '
            '               ON c.idinput = i.idinput '
            '              AND c.idbasic_block = i.idbasic_block '
            'WHERE  i.idinput IS NULL '
            '   AND c.idproject = %s;')

        query = (
            'SELECT c.idinput, '
            '       p.id '
            'FROM   potential p '
            '       inner join coverage c '
            '               ON c.idbasic_block = p.id '
            '       left join interested i '
            '               ON c.idinput = i.idinput '
            '              AND c.idbasic_block = i.idbasic_block '
            'WHERE  i.idinput IS NULL '
            '   AND c.idproject = %s;')
        cur.execute(query, (self._project_id,))
        ret = cur.fetchall()
        conn.close()

        return ret


    def update_rank(self, bb_covered, seeds):
        ''' bb_covered is the global basic block coverage counter
            seeds contains the potential input/bb pairs for the current loop '''

        rank = {}
        if not seeds:
            return rank

        # 1. map the execution counter to each of the basic block
        for (idinput, idbasic_block) in seeds:
            counter = bb_covered.get(idbasic_block, 1)
            if counter < 10:
                if not idinput in rank:
                    rank[idinput] = {'score': 0.0, 'bbs': []}
                rank[idinput]['bbs'].append((idbasic_block, counter))

        # 2. sort the lists and get the score of top 150
        # XXX: this could become time consuming
        for value in rank.itervalues():
            value['bbs'].sort(key=lambda x:x[1])
            value['bbs'] = value['bbs'][:150]
            value['score'] = sum( (1.0 / pair[1]) for pair in value['bbs'])

        # 3. return the rank by sorting each k,v pair with the calculated score
        return  sorted(rank.items(), key=lambda x: x[1]['score'], reverse=True)


    def memory_watcher(self, processes):
        ''' check the memory usage of S2E instance and kill if use too much memory '''
        while True:
            time.sleep(10)
            try:
                process = list(processes)
                for _, p_qemu in process:
                    pmem = psutil.Process(p_qemu.pid).memory_info()
                    if pmem.rss > self._mem_limit:
                        print 'memory watcher'
                        kill_process(p_qemu)
            except KeyboardInterrupt:
                raise
            except psutil.NoSuchProcess:
                # traceback.print_exc()
                # print 'error in memory watcher thread, psutil.NoSuchProcess, ignore for now'
                # print getattr(e, 'message', repr(e))
                pass
            except Exception as e:
                traceback.print_exc()
                print 'error in memory watcher thread'
                print getattr(e, 'message', repr(e))
                raise e


    def bblog_watcher(self, bb_exec_q):
        ''' watcher for log files that contains the covered basic blocks of each S2E execution '''
        setproctitle('S2E basic block coverage log handler')
        paths_bblog    = '{}/output_s2e/BBLog'.format(self._basedir)
        check_dir(paths_bblog)
        processed = set()

        def tail_with_pid(full_path, pid):
            ''' simple tail implementation '''
            interval = 1.0
            f_log = open(full_path)
            while True:
                try:
                    where = f_log.tell()
                    lines = f_log.readlines()
                    if not lines:
                        time.sleep(interval)
                        f_log.seek(where)
                    else:
                        yield lines

                    # break the loop if process no longer exists
                    if not psutil.pid_exists(pid):
                        break
                except IOError:
                    yield ''
                except KeyboardInterrupt:
                    raise

        def process_log(path, filename):
            ''' process the basic block coverage log from S2E execution '''
            full_path = os.path.join(path, filename)

            try:
                pid = int(filename.split('_')[0])
            except ValueError:
                print 'extract pid from ' + filename + ' failed.'
                return

            for lines in tail_with_pid(full_path, pid):
                for line in lines:
                    try:
                        bb_exec_q.put(int(line.rstrip()))
                    except ValueError:
                        print 'convert basic block id failed. {}'.format(line.rstrip())
                    except Full:
                        print 'put value into queue failed, Queue if full'
                    except Exception:
                        raise

        i = adapters.InotifyTree(paths_bblog, mask=IN_CREATE)
        for event in i.event_gen():
            active_children()
            if event is None:
                continue

            (_, _, path, filename) = event
            if filename in processed:
                continue
            processed.add(filename)

            p_event = Process(target=process_log, args=[path, filename])
            p_event.start()


    def bb_execution_counter(self, bb_exec_q, bb_covered):
        while True:
            try:
                bb = bb_exec_q.get()
                bb_covered[bb] = bb_covered.get(bb, 1) + 1
                # print 'counter -> ', bb, ' -> ', bb_covered[bb]
                time.sleep(0.01)
            except KeyboardInterrupt:
                raise


    def start(self):
        """ start the launcher """
        manager    = Manager()
        bb_covered = manager.dict()
        queue      = manager.Queue()
        bb_exec_q  = manager.Queue()
        processes  = list()
        # time.sleep(600)
        try:
            # use threading there because want to access process list in real time
            mem_watcher = threading.Thread(target=self.memory_watcher, args=[processes])
            mem_watcher.start()

            # parse the basic block coverage files generated by S2E
            # and put the covered basic block into Q for processing
            bblog_handler = Process(target=self.bblog_watcher, args=[bb_exec_q])
            bblog_handler.start()

            # handler of basic block execution counter, de-Q the basic block ID and do increament
            bb_exec_handler = Process(target=self.bb_execution_counter, args=[bb_exec_q, bb_covered])
            bb_exec_handler.start()

            # wait until AFL test cases are processed by DynamicAnalyzer
            time.sleep(self._interval)
            while True:
                # check if increament is larger than threshold
                increament = self.sql_check_increament()
                if increament > self._threshold:
                    time.sleep(self._interval)
                    continue

                seeds = self.sql_get_seeds()
                rank = self.update_rank(bb_covered, seeds)

                if not rank:
                    print 'no potential S2E seed, launching S2E with Symbolic Searcher'
                    self.launch_symbolic(queue)
                    continue

                # approximate timer
                timer = 0
                while timer < self._interval:
                    if not rank:
                        break       # to the outer loop

                    timer += 2
                    time.sleep(2)

                    if len(processes) >= self._max_process:
                        active_children()
                        processes[:] = [p for p in processes if p[0].is_alive()]
                        continue

                    seed = rank.pop(0)

                    # for each of the BB, add "select panalty" no matter what
                    for bb_count in seed[1]['bbs']:
                        bb = bb_count[0]
                        bb_covered[bb] = bb_covered.get(bb, 1) + 0.09

                    print '~'*100
                    print 'Popping top ranked seed'
                    print 'idinput -> ', seed[0]
                    print 'score -> ', seed[1]['score']
                    print '[',
                    for bb_count in seed[1]['bbs']:
                        print '({0[0]}, {0[1]:.2f})'.format(bb_count),
                    print ']'
                    print '~'*100

                    process = Process(target=self.worker, args=[seed, queue])
                    process.start()

                    try:
                        p_qemu = queue.get(timeout=10)
                        processes.append([process, p_qemu])
                    except Empty:
                        print 'get qemu process id timeout'
        except Exception:
            kill_process(bblog_handler)
            kill_process(bb_exec_handler)
            for process, p_qemu in processes:
                kill_process(p_qemu)   # terminate child qemu subprocess first
                time.sleep(0.2)
                kill_process(process)  # terminate worker multiprocessing process
            active_children()

            traceback.print_exc()
            raise


def setup_argparse():
    parser = argparse.ArgumentParser()

    # binary directory
    parser.add_argument('--cbpath', type=str, required=True,
            help='the directory that contains the test binary')

    # testcase generation path
    parser.add_argument('--output', type=str, required=False,
            help='directory for saving test cases')

    # max number of processes
    parser.add_argument('--process', type=int, default=1, required=False,
            help='the max number of s2e instances to be executed concurrently')

    # max number of processes
    parser.add_argument('--timeout', type=int, default=900, required=False,
            help='the maximum number of seconds each s2e instance can run')

    # max number of processes
    parser.add_argument('--image', type=str, required=True,
            help='the guest image and snapshot to be used by s2e')

    # path to depended shared libraries
    parser.add_argument('--library', type=str, required=False,
            help='path to the dependened shared libraries')

    # path to depended shared libraries
    parser.add_argument('--fork', type=str, required=False,
            choices=['process', 'process-code', 'process-userspace'], default='process-userspace',
            help='process               Enable forking in the current process only\n'
                 'process-userspace     Enable forking in userspace-code of the current process only\n'
                 'process-code          Enable forking in the code section of the current binary only\n')

    # architecture of the binary
    parser.add_argument('--arch', type=str, required=True,
            choices=['x86_64', 'i386'], default='i386',
            help='architecture of the binary')

    parser.add_argument('--debug', action='store_true', default=False)

    # path to depended shared libraries
    parser.add_argument('--uid', type=str, required=False,
            help='the user id used to launch the docker container')

    # script execution mode
    parser.add_argument('--docker_img', default='s2e_afl', type=str, required=False,
            help='the docker container image to be run')

    parser.add_argument('--vmdir', default='/opt/s2e/vm/', type=str, required=False,
            help='the directory that contains the s2e guest vm')

    # command used to binary (should be identical to AFL)
    parser.add_argument('Command', type=str,
            help='the command used to execute the test binary', nargs='*')

    # Parse arguments:
    args = parser.parse_args()
    kwargs = vars(args)

    if not kwargs['Command']:
        parser.error('You must specify the command used to execute the test binary')

    return kwargs

if __name__ == '__main__':
    dict_args = setup_argparse()
    launcher = S2ELauncher(dict_args)
    launcher.start()
