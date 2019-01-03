#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from os.path import basename, devnull, dirname
import time
import shutil
import traceback
from multiprocessing import Process, active_children, Queue
import psycopg2
from psycopg2.extensions import AsIs
from analyze import DynamicAnalyzer
from utils import md5sum, check_dir, kill_process
from inotify import adapters
from inotify.constants import IN_CREATE, IN_CLOSE_WRITE, IN_ISDIR
from setproctitle import setproctitle


def afl_watcher(argv):
    setproctitle('AFL test case watcher')

    def process_input(path, filename):
        setproctitle('analyzing [{}:{}]'.format(basename(dirname(path)), filename))

        db_config = argv['db_config']
        project_id = argv['project_id']
        qemu = argv['qemu']
        basedir = argv['basedir']

        analyzer = DynamicAnalyzer(db_config=db_config, qemu=qemu,
                                   basedir=basedir, project_id=project_id)
        analyzer.analyze_dynamic(os.path.join(path, filename))


    def process_stats(path, filename):
        setproctitle('Processing fuzzer_stats for node {}'.format(basename(path)))

        db_config = argv['db_config']
        project_id = argv['project_id']

        conn = psycopg2.connect(host=db_config['host'],
                                port=db_config['port'],
                                database=db_config['database'],
                                user=db_config['user'],
                                password=db_config['password'])
        cur = conn.cursor()

        with open(os.path.join(path, filename)) as f_stats:
            content = f_stats.readlines()

        stats_dict = dict(map(str.strip, line.split(':',1)) for line in content)

        stats_dict['idproject'] = project_id

        try:
            columns = stats_dict.keys()
            values = [stats_dict[column] for column in columns]
            exclude_columns = ['EXCLUDED.'+column for column in columns]

            query = ('insert into afl_stats '
                     '(%s) values %s '
                     'on conflict (idproject, afl_banner) DO UPDATE SET '
                     '(%s) = (%s) '
                     'returning id;')

            cur.execute(query, (AsIs(', '.join(columns)),
                                tuple(values),
                                AsIs(', '.join(columns)),
                                AsIs(', '.join(exclude_columns))))

            conn.commit()
            id_file = cur.fetchone()
        except psycopg2.IntegrityError as excp:
            print getattr(excp, 'message', repr(excp))
            conn.rollback()
        except Exception as excp:
            print getattr(excp, 'message', repr(excp))
            conn.rollback()

        conn.close()


    def worker(queue):
        setproctitle('AFL dynamic analyze dispatcher')
        processes = []
        MAX_PROCESSES = 20

        while True:
            try:
                # max number of child processes
                while active_children():
                    processes[:] = [p for p in processes if p.is_alive()]
                    if len(processes) < MAX_PROCESSES:
                        break
                    time.sleep(0.1)

                path, filename = queue.get()

                p_input = Process(target=process_input, args=[path, filename])
                p_input.start()
                processes.append(p_input)
            except KeyboardInterrupt:
                raise
            except Exception as excp:
                print getattr(excp, 'message', repr(excp))
                continue


    watch_dir = argv['out_afl']
    max_testcase_size = argv.get('max_testcase_size' , 1024*1024*50)
    queue = Queue()
    processed = set()
    tracker = set()

    worker = Process(target=worker, args=[queue])
    worker.start()

    i = adapters.InotifyTree(watch_dir, mask=IN_CLOSE_WRITE)
    for event in i.event_gen():
        if event is None:
            continue

        (_, _, path, filename) = event

        # filter #1, most often: the evenet is not inside queue directory
        dir_base = basename(path)
        if not dir_base == 'queue':
            # possibly its the fuzzer statistics
            if filename == 'fuzzer_stats':
                p_stats = Process(target=process_stats, args=[path, filename])
                p_stats.start()
            continue

        # filter #2, there is a subdirectory inside queue
        if not filename.startswith('id:'):
            continue

        # filter #3, do not analyze seedbox
        node = basename(dirname(path))
        if node == 'seedbox':
            continue

        # filter #4, for some reason, *MOST* of the test case AFL created,
        # IN_CLOSE_WRITE event will fire twice, workaround by only handling
        # the event every second time.
        if not (path, filename) in tracker:
            tracker.add((path, filename))
            continue
        tracker.remove((path, filename))

        current = []
        # XXX since the tracker set keeps growing, clear the set when reaches
        # 100 records by try to put them into queue for processing
        if len(tracker) > 100:
            while tracker:
                current.append(tracker.pop())

        # always put current event file if reach here
        current.append((path, filename))

        for c_path, c_filename in current:
            # filter #5, different nodes can generate test case with same hash
            md5 = md5sum(os.path.join(c_path, c_filename))
            if md5 in processed:
                continue
            processed.add(md5)

            f_size = os.stat(os.path.join(c_path, c_filename)).st_size
            if f_size > max_testcase_size:
                print 'TEST CASE FILE SIZE TOO LARGE FOR FILE: '
                print '{}:{} ({}) NOT SYNC INTO DATABASE'.format(node, c_filename, f_size)
                continue

            queue.put((c_path, c_filename))

            print '[W][AFL][{}][{: >8}]: [{}] {}'.format(len(processed),
                                                         basename(dirname(c_path)),
                                                         c_filename,
                                                         md5)
        active_children()



def s2e_concolic_testcase_watcher(argv):
    setproctitle('S2E test case watcher')

    watch_dir = '{}/testcases'.format(argv['out_s2e'])
    db_config = argv['db_config']
    seedbox = argv['seedbox']
    processed = set()
    count = 0

    def process_input(path, filename, count):
        setproctitle('S2E test case watcher: processing [{}]'.format(filename))
        # 1. update interested table with testcase info
        src = os.path.join(path, filename)
        try:
            with open(src, 'rb') as f_src:
                src_content = f_src.read()
            md5 = md5sum(src)
        except Exception as excp:
            print getattr(excp, 'message', repr(excp))
            return

        conn = psycopg2.connect(host=db_config['host'],
                                port=db_config['port'],
                                database=db_config['database'],
                                user=db_config['user'],
                                password=db_config['password'])
        cur = conn.cursor()

        id_file = 0
        try:
            query = ('insert into file (hash, file) '
                     'values (%s, %s) on conflict do nothing returning id;')
            cur.execute(query, (md5, psycopg2.Binary(src_content)))
            conn.commit()
            id_file = cur.fetchone()
        except KeyboardInterrupt:
            raise
        except psycopg2.IntegrityError as excp:
            print getattr(excp, 'message', repr(excp))
            conn.rollback()
        except Exception as excp:
            print getattr(excp, 'message', repr(excp))
            conn.rollback()

        # only update interested table if the testcase is generated by concolic mode
        if not filename.startswith('testcase'):
            # l_fn = ['s2e', 'input', idx_input, idx_interested, idx_basic_block, md5_short]
            l_fn = filename.split('_')
            if cur.description is None or id_file is None:
                query = 'select id from file where hash = %s;'
                cur.execute(query, (md5, ))
                id_file = cur.fetchone()

            if id_file is not None:
                query = ('update interested set '
                         'idfile = %s, '
                         'uri = %s, '
                         'update_time=now(), '
                         'status = 3 '
                         'where id = %s returning id;')
                cur.execute(query, (id_file[0], src, l_fn[3]))
                rowcount = cur.rowcount

                if rowcount != 1:
                    conn.rollback()
                else:
                    conn.commit()

        conn.close()

        # copy file from s2e test case output directory to AFL seedbox
        if not filename.startswith('testcase'):
            dst_file= 'id:{:06d},{},{},{},{}'.format(count, l_fn[2], l_fn[3], l_fn[4], l_fn[5])
            dst = '{}/{}'.format(seedbox, dst_file)
        else:
            dst_file= 'id:{:06d},{}'.format(count, filename)
            dst = '{}/{}'.format(seedbox, dst_file)

        # lastly copy file to seedbox
        print '[W][S2E]: [{}] -> [{}]'.format(basename(src), basename(dst))
        shutil.copyfile(src, dst)


    i = adapters.InotifyTree(watch_dir, mask=IN_CLOSE_WRITE)
    for event in i.event_gen():
        # auto join child process
        active_children()

        if event is None:
            continue

        (_, _, path, filename) = event

        md5 = md5sum(os.path.join(path, filename))
        if md5 in processed:
            continue
        processed.add(md5)


        count += 1
        p_input = Process(target=process_input, args=[path, filename, count])
        p_input.start()


def s2e_expdata_watcher(argv):
    ''' replace S2E expdata files with /dev/null symlink '''
    setproctitle('S2E expdata handler')

    watch_dir = '{}/expdata'.format(argv['out_s2e'])
    tmp_dir = argv['out_s2e']

    i = adapters.InotifyTree(watch_dir, mask=IN_CREATE)
    for event in i.event_gen():
        if event is None:
            continue

        (header, _, path, filename) = event

        if header.mask & IN_ISDIR:
            continue

        tmplink = '{}/{}_tmp'.format(tmp_dir, filename)
        os.symlink(devnull, tmplink)
        os.rename(tmplink, os.path.join(path, filename))


def launch(argv):
    s2e_testcase_dir = '{}/testcases'.format(argv['out_s2e'])
    s2e_expdata_dir = '{}/expdata'.format(argv['out_s2e'])

    check_dir(argv['seedbox'])
    check_dir(s2e_testcase_dir)
    check_dir(s2e_expdata_dir)

    afl_handler = Process(target=afl_watcher, args=[argv])
    s2e_testcase_handler = Process(target=s2e_concolic_testcase_watcher, args=[argv])
    s2e_expdata_handler = Process(target=s2e_expdata_watcher, args=[argv])

    afl_handler.start()
    s2e_testcase_handler.start()
    s2e_expdata_handler.start()

    while True:
        try:
            time.sleep(1)
        except Exception:
            print '#'*100
            traceback.print_exc()
            kill_process(afl_handler)
            kill_process(s2e_testcase_handler)
            kill_process(s2e_expdata_handler)
            active_children()
            raise


def setup_argparse():
    """parse args """
    argv = dict()
    argv['out_s2e'] = '/opt/exp-data/cb_2018-04-09-213605.814717/objdump/output_s2e/'
    argv['out_afl'] = '/opt/exp-data/cb_2018-04-09-213605.814717/objdump/output_afl/57923d8c/'
    argv['seedbox'] = '/opt/exp-data/cb_2018-04-09-213605.814717/objdump/output_afl/57923d8c/seedbox/queue'
    argv['project_id'] = 45
    argv['qemu'] = '/opt/afl/cyimmu_afl_tmp/cyimmu_afl/coverage/qemu-x86_64'
    argv['basedir'] = '/opt/exp-data/cb_2018-04-09-213605.814717/objdump/'

    db_config = dict()
    db_config['host'] = '127.0.0.1'
    db_config['port'] = 5432
    db_config['database'] = 'cyimmu'
    db_config['user'] = 'postgres'
    db_config['password'] = 'postgres'
    argv['db_config'] = db_config
    return argv


if __name__ == '__main__':
    dict_args = setup_argparse()

    launch(dict_args)
