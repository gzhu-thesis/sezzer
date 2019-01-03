#!/usr/bin/env python
# -*- coding: utf-8 -*-
''' perform static analyze on binaries and/or dynamic analyze upon binary + test input'''
import argparse
import tempfile
import shlex
import subprocess
from multiprocessing import Process
import os
import time
from collections import OrderedDict
from io import BytesIO
import json
import traceback
import psycopg2
from psycopg2 import sql
from utils import md5sum, run_command_noret, build_cmd, kill_process


class DB(object):

    """Docstring for DB. """

    def __init__(self, host, port, database, user, password):
        """TODO: to be defined1. """
        self._host = host
        self._port = port
        self._database = database
        self._user = user
        self._password = password
        self._conn = None
        self._cursor = None

    def conn(self):
        ''' connect to database '''
        while True:
            try:
                self._conn = psycopg2.connect(host=self._host,
                                              port=self._port,
                                              database=self._database,
                                              user=self._user,
                                              password=self._password)
                self._cursor = self._conn.cursor()
                return
            except psycopg2.OperationalError:
                print 'Analyze: Error when connect, retry ...'
                print self._host
                print self._port
                print self._database
                print self._user
                print self._password
                import time
                time.sleep(5)
                continue
            except Exception as excp:
                traceback.print_exc()
                print 'cannot connect to database'
                print getattr(excp, 'message', repr(excp))
                raise excp


    def commit(self):
        ''' commit '''
        self._conn.commit()


    def rollback(self):
        ''' rollback '''
        self._conn.rollback()


    def executemany(self, query, content=None):
        ''' bulk insert with exectuemany() '''

        try:
            self.conn()
            my_execute = self._cursor.executemany(query, content)
        except psycopg2.IntegrityError as excp:
            traceback.print_exc()
            print getattr(excp, 'message', repr(excp))
            print query
            self._conn.rollback()
            self._conn.close()
        except Exception as excp:
            traceback.print_exc()
            self._conn.rollback()
            self._conn.close()
            print getattr(excp, 'message', repr(excp))
            print query
        else:
            self._conn.commit()
            self._conn.close()



    def execute(self, query, content=None, fetchone=False, commit=True):
        ''' execute a sql query and return the result + number of rows affected '''

        # print query
        # print content
        # print '*'*100


        try:
            self.conn()

            if content is None:
                self._cursor.execute(query)
            else:
                self._cursor.execute(query, content)

            if self._cursor.description is None:
                ret = (None, 0)
            else:
                if not fetchone:
                    ret = (self._cursor.fetchall(), self._cursor.rowcount)
                else:
                    ret = (self._cursor.fetchone(), self._cursor.rowcount)

        except psycopg2.IntegrityError as excp:
            traceback.print_exc()
            # several places might trigger unique constraint violation:
            # 1. updateing edge -> safe to ignore
            # 2. inserting edge -> safe to ignore
            # 3. inserting input (while idfile is incorrect, cannot reproduce) -> retry
            print query
            print content
            self._conn.rollback()
            self._conn.close()
            return (None, 0)
        except Exception as excp:
            traceback.print_exc()
            print query
            print content
            self._conn.rollback()
            self._conn.close()
            return (None, 0)
        else:
            if commit:
                self._conn.commit()
            self._conn.close()

        return ret


    def insert_edge(self, bio, input_id):
        try:
            self.conn()

            tname = 'edge_{}'.format(input_id)
            query = sql.SQL(
                ('CREATE TEMP TABLE {} '
                 'as select idproject, from_bb, to_bb '
                 'from edge where false;')
            ).format(sql.Identifier(tname))
            self._cursor.execute(query)

            self._cursor.copy_from(bio,
                                   tname,
                                   columns=('idproject', 'from_bb', 'to_bb'))

            query = sql.SQL(
                ('insert into edge (idproject, from_bb, to_bb) '
                 'select a.idproject, a.from_bb, a.to_bb from {} a '
                 # 'where not exists '
                 #       '(select * from edge '
                 #       'where idproject = a.idproject '
                 #       'and from_bb = a.from_bb '
                 #       'and to_bb = a.to_bb) '
                 'on conflict do nothing;')
            ).format(sql.Identifier(tname))

            self._cursor.execute(query)
            self._conn.commit()
        except Exception as excp:
            traceback.print_exc()
            print getattr(excp, 'message', repr(excp))
            self._conn.rollback()
            self._conn.close()
            # raise excp
        finally:
            self._conn.close()


    def insert_coverage(self, bio, input_id, project_id):
        try:
            self.conn()

            tname = 'coverage_{}'.format(input_id)
            query = sql.SQL(
                ('CREATE TEMP TABLE {} '
                 'as select idbasic_block, count '
                 'from coverage where false;')
            ).format(sql.Identifier(tname))
            self._cursor.execute(query)

            self._cursor.copy_from(bio,
                                   tname,
                                   columns=('idbasic_block', 'count'))

            query = sql.SQL(
                ('insert into coverage (idproject, idinput, idbasic_block, count) '
                 'select %s, %s, a.idbasic_block, a.count from {} a '
                 # 'where not exists '
                 #       '(select * from coverage '
                 #       'where idproject = %(p)s '
                 #       'and idinput = %(i)s '
                 #       'and idbasic_block = a.idbasic_block) '
                 'on conflict do nothing; ')
                 # 'on conflict (idproject, idinput, idbasic_block) do update '
                 # 'set count = excluded.count ;')
            ).format(sql.Identifier(tname))

            self._cursor.execute(query, (project_id, input_id))
            self._conn.commit()
        except Exception as excp:
            traceback.print_exc()
            print getattr(excp, 'message', repr(excp))
            self._conn.rollback()
            self._conn.close()
            # raise excp
        finally:
            self._conn.close()


    def bulk_insert(self, bio, table, columns):
        """ insert into databse with copy_from """
        try:
            self.conn()
            self._cursor.copy_from(bio, table, columns=columns)
            self._conn.commit()
        except Exception as excp:
            traceback.print_exc()
            print getattr(excp, 'message', repr(excp))
            self._conn.rollback()
            self._conn.close()
            # raise excp
        self._conn.close()


class StaticAnalyzer(object):

    """Docstring for StaticAnalyzer. """

    def __init__(self, db_config, cfg, basedir, tar, arch):
        """ init """
        self._debug      = False
        self.basedir = basedir
        self._tar        = tar
        self._arch       = arch
        self._project_id  = None
        self._dict = dict()

        self._db = DB(host=db_config['host'],
                      port=db_config['port'],
                      database=db_config['database'],
                      user=db_config['user'],
                      password=db_config['password'])

        # temp workaround
        with open(cfg, 'r') as f_cfg:
            self._cfg = json.load(f_cfg)


    def get_dict(self):
        """ get the dictionary from database """
        query = ('select dt.table, dt.column, d.description, d.value '
                 'from dict d, dict_type dt '
                 'where d.iddict_type = dt.id;')

        rows, _ = self._db.execute(query, commit=False)
        for row in rows:
            if not row[0] in self._dict:
                self._dict[row[0]] = dict()
            if not row[1] in self._dict[row[0]]:
                self._dict[row[0]][row[1]] = dict()
            self._dict[row[0]][row[1]].update({row[2]:row[3]})


    def process_project(self):
        """ insert project entry """
        ###### project entry
        # insert project tgz into file table

        ins_project = ('insert into project (name, idfile, uri, arch) '
                       'values (%s, %s, %s, %s) on conflict do nothing returning id;')

        # insert into file table first
        file_id = self.process_file(self._tar)

        arch = self._dict['project']['arch'][self._arch]
        # insert project entry
        p_name = os.path.basename(self._tar)
        content = (p_name, file_id, self.basedir, arch)
        project_id, _ = self._db.execute(ins_project, content, fetchone=True)
        self._project_id = project_id[0]


    def process_file(self, filename):
        """ insert binary entry into table content """
        ins_file = ('insert into file (hash, file) '
                    'values (%s, %s) on conflict do nothing returning id;')

        # calculate md5
        md5 = md5sum(filename)

        with open(filename, 'rb') as f_src:
            src_content = f_src.read()

        content = (md5, psycopg2.Binary(src_content))
        (file_id), rowcount = self._db.execute(ins_file, content, fetchone=True)
        if rowcount == 0:
            query = 'select id from file where hash = %s;'
            file_id, _ = self._db.execute(query, (md5,), fetchone=True, commit=False)

        return file_id[0]


    def process_binary(self):
        """ insert library entry into table content """
        binary_path = '{}/binary'.format(self.basedir)
        ins_content = ('insert into content (idproject, type, idfile, uri) '
                       'values (%s, %s, %s, %s) on conflict do nothing returning id;')

        for root, _, files in os.walk(binary_path):
            for binary_file in files:
                filename = '{}/{}'.format(root, binary_file)
                file_id = self.process_file(filename)

                content = (self._project_id, 1, file_id, filename)
                content_id, _ = self._db.execute(ins_content, content, fetchone=True)

                ###### basic block entries
                self.process_basic_block(content_id[0])

            break


    def process_library(self):
        """ insert library entry into table content """
        library_path = '{}/library'.format(self.basedir)
        ins_content = ('insert into content (idproject, type, idfile, uri) '
                       'values (%s, %s, %s, %s) on conflict do nothing returning id;')

        for root, _, files in os.walk(library_path):
            for library_file in files:
                filename = '{}/{}'.format(root, library_file)
                file_id = self.process_file(filename)

                content = (self._project_id, 2, file_id, filename)
                self._db.execute(ins_content, content, fetchone=True)
            break


    def process_basic_block(self, content_id):
        """ insert basic block entries """
        nodes = list()

        for bb in self._cfg.iterkeys():
            nodes.append([int(x, 16) for x in bb.split(',')])

        # print 'number of basic blocks: {}'.format(len(nodes))

        gen = ('{}\t{}\t{}\n'.format(content_id, x[0], x[1]) for x in nodes)
        bio = BytesIO(''.join(gen))

        self._db.bulk_insert(bio, 'basic_block', ('idcontent', 'start_addr', 'end_addr'))


    def process_edge(self):
        """ insert edge entries """
        # First we need to map each of the edge with the corresponding basic block index
        select_bb = ('select b.id, b.start_addr, b.end_addr '
                     'from basic_block b, content c '
                     'where b.idcontent = c.id '
                     'and b.status = 1 '
                     'and c.idproject = %s;')

        rows, _ = self._db.execute(select_bb, (self._project_id,), commit=False)

        dict_bb = dict()
        for row in rows:
            dict_bb[(int(row[1]), int(row[2]))] = row[0]

        rows = None

        nodes = list()
        # map basic blocks with their database index
        for bb, successors in self._cfg.iteritems():
            tup_bb = tuple([int(x, 16) for x in bb.split(',')])
            for successor in successors:
                tup_successor = tuple([int(x, 16) for x in successor.split(',')])
                nodes.append((dict_bb[tup_bb], dict_bb[tup_successor]))

        # print 'number of edges: {}'.format(len(nodes))

        gen = ('{}\t{}\t{}\n'.format(self._project_id, x[0], x[1]) for x in nodes)
        bio = BytesIO(''.join(gen))


        # import shutil
        # with open('/tmp/edge_write.txt', 'w') as f_write:
        #     shutil.copyfileobj(bio, f_write, length=131072)


        self._db.bulk_insert(bio, 'edge', ('idproject', 'from_bb', 'to_bb'))


    def analyze_static(self):
        """ analyze the static translation block coverage with the tool of choice """

        self.get_dict()
        ###### project entry
        self.process_project()

        ###### binary entry
        self.process_binary()

        ###### library entries
        self.process_library()

        ###### edge entries
        self.process_edge()

        return self._project_id



class DynamicAnalyzer(object):

    """Docstring for DynamicAnalyzer. """

    def __init__(self, db_config, qemu, basedir, project_id):
        """ init """
        self._qemu       = qemu
        self.basedir = basedir
        self._project_id = project_id
        self._fifo_name  = ''
        self._tmpdir     = ''
        self._mmap_tb    = dict()
        self._debug      = False
        self._mmap_edges = dict()
        self._command    = build_cmd('{}/command.json'.format(self.basedir))

        self._db = DB(host=db_config['host'],
                      port=db_config['port'],
                      database=db_config['database'],
                      user=db_config['user'],
                      password=db_config['password'])


    def parse_trace(self):
        """ read from fifo and parse into dictionary """
        #trace_tbs = OrderedSet()
        trace_tbs = dict()
        trace_edges = set()
        do_mmap = False
        mmap = dict()               # map of loaded processes memory map
        current = None              # current basic block being parsed
        previous = None             # previous basic block beding parsed
        # tmp = open('/tmp/test.log', 'w')
        count = 0
        with open(self._fifo_name, 'r') as fifo:
            for line in fifo:
                count += 1
                if count % 10000 ==0:
                    print count
                # tmp.write(line)
                # the trace file consists of two parts, mmap and exec trace
                # they are seperated by a line of "-"(end) and "+"(start)
                # the markers should always come in pair ...
                if line[0] == '-':
                    do_mmap = False
                    continue
                if line[0] == '+':
                    do_mmap = True
                    continue
                if do_mmap:
                    res = [x.strip(' ') for x in line[:-1].split(':')]
                    # ignore if the third element (filename) is empty
                    if len(res) == 2 or res[2] == '':
                        continue
                    if not res[2] in mmap:
                        mmap[res[2]] = set()
                    mmap[res[2]].add((int(res[0], 16), int(res[1], 16)))
                    continue
                # process traceed tbs
                current = tuple([int(x, 16) for x in line[:-1].split(':')])

                # executed tbs with statistic
                current_count = trace_tbs.get(current)
                if current_count is None:
                    current_count = 1
                else:
                    current_count += 1
                trace_tbs[current] = current_count

                edge = (previous, current)
                if not edge in trace_edges:
                    trace_edges.add(edge)
                previous = current

        # tmp.close()
        return (trace_tbs, trace_edges, mmap)


    def map_edges(self, trace_edges, mmap):
        """ map edge traces to filename in memory map """
        # print 'Total (unique) edges: ', len(trace_edges)

        for filename, m_ranges in mmap.iteritems():
            # skip if the memory mapped object is not a file. eg, "stack"
            if not os.path.isfile(filename):
                continue
            self._mmap_edges[filename] = set()
            for m_range in m_ranges:
                mapped_edges = set()
                for edge in trace_edges:
                    if edge[0] is None or edge[1] is None:
                        continue
                    if edge[0][0] > m_range[0] and edge[0][0] < m_range[1]:
                        self._mmap_edges[filename].add(edge)
                        mapped_edges.add(edge)
                # reduce set during each of the loops
                trace_edges = trace_edges.difference(mapped_edges)

        # for k, v in self._mmap_edges.iteritems():
        #     print k, ':', len(v)
        # print 'leftover: ', len(trace_edges)


    def map_tbs(self, trace_tbs, mmap):
        """ map basic block traces to filename in memory map """
        # print 'Total (unique) Tbls: ', len(trace_tbs)

        for filename, m_ranges in mmap.iteritems():
            # skip if the memory mapped object is not a file. eg, "stack"
            if not os.path.isfile(filename):
                continue
            self._mmap_tb[filename] = dict()
            for m_range in m_ranges:
                mapped_bbs = set()
                for tb, value in trace_tbs.iteritems():
                    if tb[0] > m_range[0] and tb[0] < m_range[1]:
                        self._mmap_tb[filename][tb] = value
                        mapped_bbs.add(tb)
                # reduce set during each of the loops
                for tb in mapped_bbs:
                    trace_tbs.pop(tb, None)

        # for k, v in self._mmap_tb.iteritems():
        #     print k, ':', len(v)
        # print 'leftover: ', len(trace_tbs)


    def mkfile(self, fifo=None):
        self._fifo_name = tempfile.mkstemp('.fifo', 'tmp', '/opt/tmpfiles')[1]
        # """ create FIFO """
        # if fifo is None:
        #     fifo = 'fifo'
        # # self._tmpdir = tempfile.mkdtemp()
        # self._tmpdir = '/opt/tmp/'
        # self._fifo_name = os.path.join(self._tmpdir, fifo)
        # try:
        #     open(self._fifo_name, 'r')
        # except IOError:
        #     open(self._fifo_name, 'w')


    def mkfifo(self, fifo=None):
        """ create FIFO """
        if fifo is None:
            fifo = 'fifo'
        self._tmpdir = tempfile.mkdtemp()
        self._fifo_name = os.path.join(self._tmpdir, fifo)
        try:
            os.mkfifo(self._fifo_name)
        except OSError as excp:
            traceback.print_exc()
            os.rmdir(self._tmpdir)
            print "Failed to create FIFO"
            print getattr(excp, 'message', repr(excp))
            raise excp


    @staticmethod
    def get_tb_status(tb, bb_dict):
        """ return the matching result of a translation block(tb)
        return: 1 - no match
                2 - tb spans across multiple bbs
                3 - inside, end does not match
                4 - inside, end does match
                other - db index of matched bb
        """
        if tb in bb_dict:
            return (0, tb)
        if tb[0] == tb[1]:
            return (1, None)
        for bb in bb_dict:
            if tb[0] >= bb[1] or tb[1] <= bb[0]:
                continue
            if tb[1] < bb[1]:
                return (3, bb)
            if tb[1] == bb[1]:
                return (4, bb)
            if tb[1] > bb[1]:
                return (2, None)
        return (1, None)



    def process_basic_block(self, contents):
        """ update basic_block table according to dynamic analyze results """
        ###### tb -> tranlation block which is colected from qemu's dynamic trace
        ###### bb -> basic block information recorded in database

        hashes = [x[3] for x in contents]

        for filename, tbs in self._mmap_tb.iteritems():
            # skip if the hash does not exist in database, else get the database index
            try:
                content_id = contents[hashes.index(md5sum(filename))][0]
            except ValueError:
                continue

            query = ('select b.id, b.start_addr, b.end_addr '
                     'from basic_block b '
                     'where b.idcontent = %s '
                     'and b.status = 1 '
                     'order by b.start_addr asc;')
            rows, _ = self._db.execute(query, (content_id,), commit=False)

            # since the full match should be the majority of the case
            bb_dict = OrderedDict()
            for row in rows:
                bb_dict[(int(row[1]), int(row[2]))] = row[0]

            rows = None

            # loop through tbs and rows
            for tb in tbs.iterkeys():
                (status_code, bb) = self.get_tb_status(tb, bb_dict)

                if status_code == 1:
                    # insert new record into basic_block table
                    query = ('insert into basic_block '
                             '(idcontent, start_addr, end_addr) '
                             'values (%s, %s, %s) on conflict do nothing returning id;')
                    self._db.execute(query, (content_id, tb[0], tb[1]))
                if status_code == 2:
                    # XXX: do nothing for now
                    pass
                if status_code == 3:
                    # split the original into 3 parts, update edge accordingly
                    # new_block_1 = (bb[0], tb[0])
                    # new_block_2 = (tb[0], tb[1])
                    # new_block_3 = (tb[1], bb[1])
                    bb_idx = bb_dict.get(bb)
                    query = ('insert into basic_block '
                             '(idcontent, start_addr, end_addr) '
                             'values (%s, %s, %s) on conflict do nothing returning id;')
                    idx_1, _ = self._db.execute(query, (content_id, bb[0], tb[0]), fetchone=True)
                    idx_2, _ = self._db.execute(query, (content_id, tb[0], tb[1]), fetchone=True)
                    idx_3, _ = self._db.execute(query, (content_id, tb[1], bb[1]), fetchone=True)

                    # update original edges, to_bb change to idx_1, from_bb change to idx_3
                    # also insert new edges: new_block_1->new_block_2 and new_block_2 -> new_block_3
                    query = ('insert into edge '
                             '(idproject, from_bb, to_bb) '
                             'values (%s, %s, %s) '
                             'on conflict do nothing returning id;')

                    self._db.execute(query, (self._project_id, idx_1, idx_2))
                    self._db.execute(query, (self._project_id, idx_2, idx_3))

                    query = ('update edge set from_bb = %s where from_bb = %s returning id;')
                    self._db.execute(query, (idx_3[0], bb_idx))

                    query = ('update edge set to_bb = %s where to_bb = %s returning id;')
                    self._db.execute(query, (idx_1[0], bb_idx))

                    # update the original basic block's status to inactive
                    query = ('update basic_block set status = 2 where id = %s returning id;')
                    self._db.execute(query, (bb_idx, ))
                if status_code == 4:
                    # split the original into 2 parts, update edge accordingly
                    # new_block_1 = (bb[0], tb[0])
                    # new_block_2 = (tb[0], tb[1])
                    bb_idx = bb_dict.get(bb)
                    query = ('insert into basic_block '
                             '(idcontent, start_addr, end_addr) '
                             'values (%s, %s, %s) on conflict do nothing returning id;')
                    idx_1, _ = self._db.execute(query, (content_id, bb[0], tb[0]), fetchone=True)
                    idx_2, _ = self._db.execute(query, (content_id, tb[0], tb[1]), fetchone=True)

                    # update original edges, to_bb change to idx_1, from_bb change to idx_2
                    query = ('update edge set from_bb = %s where from_bb = %s returning id;')
                    self._db.execute(query, (idx_2[0], bb_idx))

                    query = ('update edge set to_bb = %s where to_bb = %s returning id;')
                    self._db.execute(query, (idx_1[0], bb_idx))

                    # update the original basic block's status to inactive
                    query = ('update basic_block set status = 2 where id = %s returning id;')
                    self._db.execute(query, (bb_idx, ))


    def process_edge(self, contents, edge_set, bb_dict, input_id):
        """ update edge table according to dynamic analyze results """

        nodes = list()

        hashes = [x[3] for x in contents]

        for filename, edges in self._mmap_edges.iteritems():
            # skip if the hash does not exist in database, else get the database index
            try:
                content_id = contents[hashes.index(md5sum(filename))][0]
            except ValueError:
                continue

            for edge in edges:
                # map basic blocks with their database index
                from_bb = edge[0]
                to_bb = edge[1]

                # first node and last node, not insert into edge table
                if from_bb is None or to_bb is None:
                    continue

                idx_from_bb = bb_dict.get(from_bb)
                idx_to_bb = bb_dict.get(to_bb)

                # # if no full match found for idx_from_bb, try to match bb's end address
                # # this is because bb condition 2 is not handled (dynamic tb spans multiple bbs)
                # # this should be rare, so looping through the dict for now
                # if idx_from_bb is None:
                #     for bb in bb_dict.iterkeys():
                #         if from_bb[1] <= bb[1] and from_bb[1] > bb[0]:
                #             idx_from_bb = bb_dict[bb]
                #             break

                # # same with to_bb, try to match bb's start address
                # if idx_to_bb is None:
                #     for bb in bb_dict.iterkeys():
                #         if to_bb[0] >= bb[0] and to_bb[0] < bb[1]:
                #             idx_to_bb = bb_dict[bb]
                #             break

                # still can't find, it might be because the basic block does not
                # belong to any of the memory mapped file in the project content table
                # ignore for now...
                if idx_from_bb is None or idx_to_bb is None:
                    continue

                edge_with_idx = (idx_from_bb, idx_to_bb)
                if edge_with_idx not in edge_set:
                    # insert new edge
                    nodes.append(edge_with_idx)

            # print 'number of edges inserted: {}'.format(len(nodes))
            gen = ('{}\t{}\t{}\n'.format(self._project_id, x[0], x[1]) for x in nodes)
            bio = BytesIO(''.join(gen))
            self._db.insert_edge(bio, input_id)


    def process_file(self, filename):
        """ insert binary entry into table content """
        ins_file = ('insert into file (hash, file) '
                    'values (%s, %s) on conflict do nothing returning id;')

        # calculate md5
        md5 = md5sum(filename)

        with open(filename, 'rb') as f_src:
            src_content = f_src.read()

        content = (md5, psycopg2.Binary(src_content))
        file_id, rowcount = self._db.execute(ins_file, content, fetchone=True)
        if rowcount == 0:
            query = 'select id from file where hash = %s;'
            file_id, _ = self._db.execute(query, (md5,), fetchone=True, commit=False)

        return file_id[0]


    def process_coverage(self, contents, input_id, bb_dict):
        """ insert into coverage table """
        nodes = list()
        hashes = [x[3] for x in contents]
        for filename, tbs in self._mmap_tb.iteritems():
            # skip if the hash does not exist in database, else get the database index
            if not md5sum(filename) in hashes:
                continue

            for tb, value in tbs.iteritems():                   # iterate through tbs
                bb_idx = bb_dict.get(tb)
                if bb_idx:
                    nodes.append([bb_idx, value])
                else:
                    # if no full match found , try to match both bb's end address and start address
                    # this is because bb condition 2 is not handled (dynamic tb spans multiple bbs)
                    # this should be rare, so looping through the dict for now
                    for bb in bb_dict.iterkeys():
                        if tb[0] >= bb[0] and tb[0] < bb[1]:
                            nodes.append([bb_dict[bb], value])
                        if tb[1] > bb[0] and tb[1] <= bb[1]:
                            nodes.append([bb_dict[bb], value])

        # print 'number of coverage inserted: {}'.format(len(nodes))
        gen = ('{}\t{}\n'.format(x[0], x[1]) for x in nodes)
        bio = BytesIO(''.join(gen))
        self._db.insert_coverage(bio, input_id, self._project_id)

        # gen = ('{}\t{}\t{}\t{}\n'.format(self._project_id, input_id, x[0], x[1]) for x in nodes)
        # bio = BytesIO(''.join(gen))

        # self._db.bulk_insert(bio,
        #                      'coverage',
        #                      ('idproject', 'idinput', 'idbasic_block', 'count'))


    def process_input(self, test_input):
        """ insert input table """
        query = ('insert into input (idproject, idfile, uri, status)'
                 'values (%s, %s, %s, %s) on conflict do nothing returning id;')
        input_id = None
        while input_id is None:
            file_id = self.process_file(test_input)
            content = (self._project_id, file_id, test_input, 1)

            input_id, _ = self._db.execute(query, content, fetchone=True)
        return input_id[0]


    def update_database(self, test_input):
        """ update database according to trace result """
        ###################
        ## input
        ###################
        input_id = self.process_input(test_input)

        ###################
        ## basic blocks
        ###################
        # select all the files related to the current project from database
        query = ('select c.id, c.uri, c.type, f.hash '
                 'from content c, file f '
                 'where c.idfile = f.id '
                 'and c.idproject = %s;')
        contents, _ = self._db.execute(query, (self._project_id,), commit=False)

        # for this file name appeared in memory map, update basic block table
        self.process_basic_block(contents)

        ###################
        ## edges
        ###################
        query = ('select from_bb, to_bb '
                 'from edge '
                 'where status = 1 '
                 'and idproject = %s;')
        edges, _ = self._db.execute(query, (self._project_id,), commit=False)

        edge_set = set()
        for edge in edges:
            edge_set.add((edge[0], edge[1]))

        edges = None
        # cannot reuse the query results in bb updates because the table might have changed
        query = ('select b.id, b.start_addr, b.end_addr '
                 'from basic_block b, content c '
                 'where b.idcontent = c.id '
                 'and b.status = 1 '
                 'and c.idproject = %s;')
        rows, _ = self._db.execute(query, (self._project_id,), commit=False)

        bb_dict = dict()
        for row in rows:
            bb_dict[(int(row[1]), int(row[2]))] = row[0]

        rows = None
        self.process_edge(contents, edge_set, bb_dict, input_id)

        ###################
        ## coverage
        ###################
        self.process_coverage(contents, input_id, bb_dict)


    def build_qemu_cmd(self, test_input):
        """ build qemu command """
        library_path = '-E LD_LIBRARY_PATH={}/library'.format(self.basedir)
        binary_path = '{}/binary'.format(self.basedir)

        command = self._command[:]

        # replace the first occurance of '@@' in the command from right
        # if no '@@' found, meaning that input should be piped to stdin
        if '@@' in command:
            command[command.index('@@')] = test_input
        else:
            command.append('< {}'.format(test_input))
        exec_cmd = ' '.join(command)

        return '''
               {QEMU} {LIBRARY} -d nochain,tb -D {TRACE} {COMMAND}
               '''.format(QEMU    = self._qemu,
                          LIBRARY = library_path,
                          TRACE   = self._fifo_name,
                          BINARY  = binary_path,
                          COMMAND = exec_cmd)


    def analyze_dynamic(self, test_input):
        """ analyze the dynamic translation block coverage with qemu """
        # Execute binary with qemu user mode while taking care of libraries
        # collect dynamic translation block execution information

        # 1. create a named pipe for qemu to write to
        # self.mkfile()
        self.mkfifo()

        # 2. build command and launch QEMU
        cmd = self.build_qemu_cmd(test_input)
        process = Process(target=run_command_noret, args=[cmd, 40, 'ANALYZER'])
        process.start()

        # 3. read from fifo after QEMU finished executing
        try:
            trace_tbs, trace_edges, mmap = self.parse_trace()
        except Exception as e:
            traceback.print_exc()
            print 'error when parsing qemu trace'
            print getattr(e, 'message', repr(e))
            raise e
        finally:
            os.remove(self._fifo_name)
            os.rmdir(self._tmpdir)
            process.join()

        if not mmap:
            mmap[os.path.join(self.basedir, 'binary', 'cb')] = set()
            mmap[os.path.join(self.basedir, 'binary', 'cb')].add((0, 0x7fffffff))


        # map traced TBs to files in memory map
        self.map_tbs(trace_tbs, mmap)

        self.map_edges(trace_edges, mmap)

        # 5. Start working ...
        self.update_database(test_input)


def analyze_dynamic(argv):
    """ wrapper function of dynamic analyzer for direct call """
    db_config = {}
    db_config['host']=argv['host']
    db_config['port']=argv['port']
    db_config['database']=argv['database']
    db_config['user']=argv['user']
    db_config['password']=argv['password']

    analyzer = DynamicAnalyzer(db_config=db_config, qemu=argv['qemu'],
                               basedir=argv['basedir'], project_id=argv['projectid'])
    analyzer.analyze_dynamic(argv['input'])


def analyze_static(argv):
    """ wrapper function of static analyzer for direct call """
    db_config = {}
    db_config['host']=argv['host']
    db_config['port']=argv['port']
    db_config['database']=argv['database']
    db_config['user']=argv['user']
    db_config['password']=argv['password']

    analyzer = StaticAnalyzer(db_config=db_config, cfg=argv['cfg'],
                              basedir=argv['basedir'], tar=argv['tar'],
                              arch=argv['arch'])
    analyzer.analyze_static()


def setup_argparse():
    """ argparse """
    parser = argparse.ArgumentParser()

    ############################################################################
    # general options

    ############################################################################
    # subparsers
    subparsers = parser.add_subparsers(dest='command')

    # ------ static ------ #
    sub_static = subparsers.add_parser('static')
    sub_static.set_defaults(func=analyze_static)
    sub_static.add_argument('--engine', type=str, default='angr',
            help='Default static analyze engine')
    sub_static.add_argument('--cfg', type=str, default='',
            help='Path to the control flow graph Will try to generate a new one if left empty')
    sub_static.add_argument('--tar', type=str, default='',
            help='the tar file of the project')
    sub_static.add_argument('--arch', type=str, default='',
            help='the archtechture of the project')
    sub_static.add_argument('--host', type=str, default='127.0.0.1')
    sub_static.add_argument('--port', type=int, default=5432)
    sub_static.add_argument('--database', type=str, default='cyimmu')
    sub_static.add_argument('--user', type=str, default='postgres')
    sub_static.add_argument('--password', type=str, default='postgres')
    sub_static.add_argument('--basedir', type=str, default='', help='Path to the project')


    # ------ dynamic ------ #
    sub_dynamic = subparsers.add_parser('dynamic')
    sub_dynamic.set_defaults(func=analyze_dynamic)
    sub_dynamic.add_argument('--input', type=str, default='',
            help='Path to the input file to be dynamically analyzed')
    sub_dynamic.add_argument('--qemu', type=str, default='',
            help='Path to the QEMU that performs dynamic analyze')
    sub_dynamic.add_argument('--projectid', type=int,
            help='the database index of the project to be analyzed, used for updateing basic block and edge info')
    sub_dynamic.add_argument('--host', type=str, default='127.0.0.1')
    sub_dynamic.add_argument('--port', type=int, default=5432)
    sub_dynamic.add_argument('--databse', type=str, default='cyimmu')
    sub_dynamic.add_argument('--dbuser', type=str, default='postgres')
    sub_dynamic.add_argument('--password', type=str, default='postgres')
    sub_dynamic.add_argument('--basedir', type=str, default='', help='Path to the project')

    args = parser.parse_args()
    kwargs = vars(args)
    args.func(kwargs)


if __name__ == '__main__':
    setup_argparse()
