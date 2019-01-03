--
-- PostgreSQL database dump
--

-- Dumped from database version 10.0
-- Dumped by pg_dump version 10.0

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;




CREATE TABLE afl_stats
(
    id bigint NOT NULL,
    idproject bigint NOT NULL,
    afl_banner character varying(32) COLLATE pg_catalog."default" NOT NULL,
    afl_version character varying(10) COLLATE pg_catalog."default" NOT NULL,
    bitmap_cvg character varying(10) COLLATE pg_catalog."default" NOT NULL,
    command_line character varying(512) COLLATE pg_catalog."default" NOT NULL,
    target_mode character varying(32) COLLATE pg_catalog."default" NOT NULL,
    execs_per_sec character varying(10) COLLATE pg_catalog."default" NOT NULL,
    cur_path bigint NOT NULL,
    cycles_done bigint NOT NULL,
    exec_timeout bigint NOT NULL,
    execs_done bigint NOT NULL,
    execs_since_crash bigint NOT NULL,
    fuzzer_pid bigint NOT NULL,
    last_crash bigint NOT NULL,
    last_hang bigint NOT NULL,
    last_path bigint NOT NULL,
    last_update bigint NOT NULL,
    max_depth bigint NOT NULL,
    paths_favored bigint NOT NULL,
    paths_found bigint NOT NULL,
    paths_imported bigint NOT NULL,
    paths_total bigint NOT NULL,
    pending_favs bigint NOT NULL,
    pending_total bigint NOT NULL,
    stability character varying(10) COLLATE pg_catalog."default" NOT NULL,
    start_time bigint NOT NULL,
    unique_crashes bigint NOT NULL,
    unique_hangs bigint NOT NULL,
    variable_paths bigint NOT NULL,
    CONSTRAINT "PK_AFL_ID" PRIMARY KEY (id),
    CONSTRAINT "UNIQ_AFL_BANNER_PROJECT" UNIQUE (idproject, afl_banner)
);


CREATE SEQUENCE afl_stats_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: afl_stats_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE afl_stats_id_seq OWNED BY afl_stats.id;
ALTER TABLE ONLY afl_stats ALTER COLUMN id SET DEFAULT nextval('afl_stats_id_seq'::regclass);




--
-- Name: basic_block; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE basic_block (
    id bigint NOT NULL,
    idcontent bigint NOT NULL,
    start_addr numeric NOT NULL,
    end_addr numeric NOT NULL,
    status bigint DEFAULT '1'::bigint NOT NULL,
    create_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    update_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: COLUMN basic_block.status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN basic_block.status IS 'Where does this BB comes from:
1. Active
2. Archived';


--
-- Name: basic_block_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE basic_block_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: basic_block_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE basic_block_id_seq OWNED BY basic_block.id;


--
-- Name: content; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE content (
    id bigint NOT NULL,
    idproject bigint NOT NULL,
    type bigint NOT NULL,
    idfile bigint DEFAULT '1'::bigint NOT NULL,
    uri character varying(1024) NOT NULL,
    create_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    update_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: COLUMN content.type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN content.type IS '1 - executable
2 - library
3 - config';


--
-- Name: content_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE content_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: content_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE content_id_seq OWNED BY content.id;


--
-- Name: coverage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE coverage (
    id bigint NOT NULL,
    idproject bigint NOT NULL,
    idinput bigint NOT NULL,
    idbasic_block bigint NOT NULL,
    count bigint NOT NULL
);


--
-- Name: coverage_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE coverage_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: coverage_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE coverage_id_seq OWNED BY coverage.id;


--
-- Name: dict; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE dict (
    id bigint NOT NULL,
    iddict_type bigint NOT NULL,
    value bigint NOT NULL,
    description character varying(128) NOT NULL,
    comments character varying(128)
);


--
-- Name: dict_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE dict_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dict_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE dict_id_seq OWNED BY dict.id;


--
-- Name: dict_type; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE dict_type (
    id bigint NOT NULL,
    "table" character varying(64) NOT NULL,
    "column" character varying(64) NOT NULL,
    comments character varying(128)
);


--
-- Name: dict_type_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE dict_type_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dict_type_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE dict_type_id_seq OWNED BY dict_type.id;


--
-- Name: edge; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE edge (
    id bigint NOT NULL,
    idproject bigint NOT NULL,
    from_bb bigint NOT NULL,
    to_bb bigint NOT NULL,
    instruction bigint DEFAULT '1'::bigint NOT NULL,
    condition bigint DEFAULT '1'::bigint NOT NULL,
    status bigint DEFAULT '1'::bigint NOT NULL,
    create_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    update_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: COLUMN edge.instruction; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN edge.instruction IS '1 - conditional jump
2 - direct jump
3 - call
4 - others';


--
-- Name: COLUMN edge.condition; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN edge.condition IS 'which branch it takes for the instruction
1 - True
2 - False
3 - None';


--
-- Name: COLUMN edge.status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN edge.status IS 'Where does this BB comes from:
1. Active
2. Archived';


--
-- Name: edge_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE edge_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: edge_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE edge_id_seq OWNED BY edge.id;


--
-- Name: file; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE file (
    id bigint NOT NULL,
    hash character(32) NOT NULL,
    file bytea NOT NULL
);


--
-- Name: file_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE file_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: file_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE file_id_seq OWNED BY file.id;


--
-- Name: input; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE input (
    id bigint NOT NULL,
    idproject bigint NOT NULL,
    idfile bigint NOT NULL,
    uri character varying(1024) NOT NULL,
    status bigint DEFAULT '0'::bigint NOT NULL,
    create_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    update_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: COLUMN input.status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN input.status IS '
1 - normal
2 - archived
0 - inserting';


--
-- Name: input_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE input_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: input_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE input_id_seq OWNED BY input.id;


--
-- Name: interested; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE interested (
    id bigint NOT NULL,
    idproject bigint NOT NULL,
    idinput bigint NOT NULL,
    idbasic_block bigint NOT NULL,
    idfile bigint,
    uri character varying(1024),
    status bigint DEFAULT '1'::bigint NOT NULL,
    create_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    update_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: COLUMN interested.idfile; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN interested.idfile IS 'The possible generated test case file';


--
-- Name: COLUMN interested.status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN interested.status IS '1 - new
2 - solving
3 - success
4 - fail
5 - timeout';


--
-- Name: interested_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE interested_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: interested_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE interested_id_seq OWNED BY interested.id;


--
-- Name: path; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE path (
    id bigint NOT NULL,
    idinput bigint NOT NULL,
    idbasic_block bigint NOT NULL,
    idedge bigint NOT NULL,
    prev bigint DEFAULT '1'::bigint NOT NULL,
    next bigint DEFAULT '1'::bigint NOT NULL,
    create_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: path_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE path_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: path_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE path_id_seq OWNED BY path.id;


--
-- Name: project; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE project (
    id bigint NOT NULL,
    name character varying(256) NOT NULL,
    idfile bigint DEFAULT '1'::bigint NOT NULL,
    uri character varying(1024) NOT NULL,
    arch bigint NOT NULL,
    status bigint DEFAULT '1'::bigint NOT NULL,
    create_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    update_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: COLUMN project.name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN project.name IS 'Project name';


--
-- Name: COLUMN project.idfile; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN project.idfile IS 'Each project should have a self contained archive, including the executable, (possible) libraries, configuration and so on.
This file FK should link to the archive tar ball of the project.';


--
-- Name: COLUMN project.arch; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN project.arch IS 'Architecture of the project
1 - i386
2 - x86_64
3 - armel';


--
-- Name: COLUMN project.status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN project.status IS '1 - normal
2 - archived';


--
-- Name: project_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE project_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: project_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE project_id_seq OWNED BY project.id;


--
-- Name: basic_block id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY basic_block ALTER COLUMN id SET DEFAULT nextval('basic_block_id_seq'::regclass);


--
-- Name: content id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY content ALTER COLUMN id SET DEFAULT nextval('content_id_seq'::regclass);


--
-- Name: coverage id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage ALTER COLUMN id SET DEFAULT nextval('coverage_id_seq'::regclass);


--
-- Name: dict id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY dict ALTER COLUMN id SET DEFAULT nextval('dict_id_seq'::regclass);


--
-- Name: dict_type id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY dict_type ALTER COLUMN id SET DEFAULT nextval('dict_type_id_seq'::regclass);


--
-- Name: edge id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY edge ALTER COLUMN id SET DEFAULT nextval('edge_id_seq'::regclass);


--
-- Name: file id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY file ALTER COLUMN id SET DEFAULT nextval('file_id_seq'::regclass);


--
-- Name: input id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY input ALTER COLUMN id SET DEFAULT nextval('input_id_seq'::regclass);


--
-- Name: interested id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY interested ALTER COLUMN id SET DEFAULT nextval('interested_id_seq'::regclass);


--
-- Name: path id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY path ALTER COLUMN id SET DEFAULT nextval('path_id_seq'::regclass);


--
-- Name: project id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY project ALTER COLUMN id SET DEFAULT nextval('project_id_seq'::regclass);


--
-- Name: basic_block idx_21382_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY basic_block
    ADD CONSTRAINT idx_21382_primary PRIMARY KEY (id);


--
-- Name: content idx_21394_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY content
    ADD CONSTRAINT idx_21394_primary PRIMARY KEY (id);


--
-- Name: coverage idx_21406_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage
    ADD CONSTRAINT idx_21406_primary PRIMARY KEY (id);


--
-- Name: dict idx_21412_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY dict
    ADD CONSTRAINT idx_21412_primary PRIMARY KEY (id);


--
-- Name: dict_type idx_21418_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY dict_type
    ADD CONSTRAINT idx_21418_primary PRIMARY KEY (id);


--
-- Name: edge idx_21424_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY edge
    ADD CONSTRAINT idx_21424_primary PRIMARY KEY (id);


--
-- Name: file idx_21435_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY file
    ADD CONSTRAINT idx_21435_primary PRIMARY KEY (id);


--
-- Name: input idx_21444_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY input
    ADD CONSTRAINT idx_21444_primary PRIMARY KEY (id);


--
-- Name: interested idx_21456_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY interested
    ADD CONSTRAINT idx_21456_primary PRIMARY KEY (id);


--
-- Name: path idx_21468_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY path
    ADD CONSTRAINT idx_21468_primary PRIMARY KEY (id);


--
-- Name: project idx_21477_primary; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY project
    ADD CONSTRAINT idx_21477_primary PRIMARY KEY (id);


--
-- Name: idx_21382_fk_bb_content_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21382_fk_bb_content_idx ON basic_block USING btree (idcontent);


--
-- Name: idx_21382_idx_bb_end_addr; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21382_idx_bb_end_addr ON basic_block USING btree (end_addr);


--
-- Name: idx_21382_idx_bb_start_addr; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21382_idx_bb_start_addr ON basic_block USING btree (start_addr);


--
-- Name: idx_21394_fk_content_file_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21394_fk_content_file_idx ON content USING btree (idfile);


--
-- Name: idx_21394_fk_content_project_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21394_fk_content_project_idx ON content USING btree (idproject);


--
-- Name: idx_21406_fk_coverage_bb_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21406_fk_coverage_bb_idx ON coverage USING btree (idbasic_block);


--
-- Name: idx_21406_fk_coverage_input_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21406_fk_coverage_input_idx ON coverage USING btree (idinput);


--
-- Name: idx_21406_fk_coverage_project_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21406_fk_coverage_project_idx ON coverage USING btree (idproject);


--
-- Name: idx_21406_uniq_project_input_bb; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_21406_uniq_project_input_bb ON coverage USING btree (idproject, idinput, idbasic_block);


--
-- Name: idx_21412_fk_type_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21412_fk_type_idx ON dict USING btree (iddict_type);


--
-- Name: idx_21412_uniq_type_value; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_21412_uniq_type_value ON dict USING btree (iddict_type, value);


--
-- Name: idx_21424_fk_edge_content_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21424_fk_edge_content_idx ON edge USING btree (idproject);


--
-- Name: idx_21424_fk_from_bb_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21424_fk_from_bb_idx ON edge USING btree (from_bb);


--
-- Name: idx_21424_fk_to_bb_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21424_fk_to_bb_idx ON edge USING btree (to_bb);


--
-- Name: idx_21424_uniq_from_bb_to_bb; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_21424_uniq_from_bb_to_bb ON edge USING btree (from_bb, to_bb, idproject);


--
-- Name: idx_21435_file_uniq_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_21435_file_uniq_hash ON file USING btree (hash);


--
-- Name: idx_21444_fk_input_file_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21444_fk_input_file_idx ON input USING btree (idfile);


--
-- Name: idx_21444_fk_input_project_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21444_fk_input_project_idx ON input USING btree (idproject);


--
-- Name: idx_21456_fk_interested_bb_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21456_fk_interested_bb_idx ON interested USING btree (idbasic_block);


--
-- Name: idx_21456_fk_interested_file_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21456_fk_interested_file_idx ON interested USING btree (idfile);


--
-- Name: idx_21456_fk_interested_input_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21456_fk_interested_input_idx ON interested USING btree (idinput);


--
-- Name: idx_21456_fk_interested_project_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21456_fk_interested_project_idx ON interested USING btree (idproject);


--
-- Name: idx_21456_uniq_interested_project_input_bb; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_21456_uniq_interested_project_input_bb ON interested USING btree (idproject, idinput, idbasic_block);


--
-- Name: idx_21468_fk_bb_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21468_fk_bb_idx ON path USING btree (idbasic_block);


--
-- Name: idx_21468_fk_edge_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21468_fk_edge_idx ON path USING btree (idedge);


--
-- Name: idx_21468_fk_input_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21468_fk_input_idx ON path USING btree (idinput);


--
-- Name: idx_21468_fk_next_path_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21468_fk_next_path_idx ON path USING btree (next);


--
-- Name: idx_21468_fk_prev_path_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21468_fk_prev_path_idx ON path USING btree (prev);


--
-- Name: idx_21477_fk_project_file_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_21477_fk_project_file_idx ON project USING btree (idfile);


--
-- Name: basic_block fk_bb_content; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY basic_block
    ADD CONSTRAINT fk_bb_content FOREIGN KEY (idcontent) REFERENCES content(id);


--
-- Name: content fk_content_file; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY content
    ADD CONSTRAINT fk_content_file FOREIGN KEY (idfile) REFERENCES file(id);


--
-- Name: content fk_content_project; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY content
    ADD CONSTRAINT fk_content_project FOREIGN KEY (idproject) REFERENCES project(id);


--
-- Name: coverage fk_coverage_bb; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage
    ADD CONSTRAINT fk_coverage_bb FOREIGN KEY (idbasic_block) REFERENCES basic_block(id);


--
-- Name: coverage fk_coverage_input; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage
    ADD CONSTRAINT fk_coverage_input FOREIGN KEY (idinput) REFERENCES input(id);


--
-- Name: coverage fk_coverage_project; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage
    ADD CONSTRAINT fk_coverage_project FOREIGN KEY (idproject) REFERENCES project(id);


--
-- Name: edge fk_edge_from_bb; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY edge
    ADD CONSTRAINT fk_edge_from_bb FOREIGN KEY (from_bb) REFERENCES basic_block(id);


--
-- Name: edge fk_edge_project; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY edge
    ADD CONSTRAINT fk_edge_project FOREIGN KEY (idproject) REFERENCES project(id);


--
-- Name: edge fk_edge_to_bb; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY edge
    ADD CONSTRAINT fk_edge_to_bb FOREIGN KEY (to_bb) REFERENCES basic_block(id);


--
-- Name: input fk_input_file; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY input
    ADD CONSTRAINT fk_input_file FOREIGN KEY (idfile) REFERENCES file(id);


--
-- Name: input fk_input_project; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY input
    ADD CONSTRAINT fk_input_project FOREIGN KEY (idproject) REFERENCES project(id);


--
-- Name: interested fk_interested_bb; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY interested
    ADD CONSTRAINT fk_interested_bb FOREIGN KEY (idbasic_block) REFERENCES basic_block(id);


--
-- Name: interested fk_interested_file; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY interested
    ADD CONSTRAINT fk_interested_file FOREIGN KEY (idfile) REFERENCES file(id);


--
-- Name: interested fk_interested_input; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY interested
    ADD CONSTRAINT fk_interested_input FOREIGN KEY (idinput) REFERENCES input(id);


--
-- Name: interested fk_interested_project; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY interested
    ADD CONSTRAINT fk_interested_project FOREIGN KEY (idproject) REFERENCES project(id);


--
-- Name: path fk_path_bb; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY path
    ADD CONSTRAINT fk_path_bb FOREIGN KEY (idbasic_block) REFERENCES basic_block(id);


--
-- Name: path fk_path_edge; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY path
    ADD CONSTRAINT fk_path_edge FOREIGN KEY (idedge) REFERENCES edge(id);


--
-- Name: path fk_path_input; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY path
    ADD CONSTRAINT fk_path_input FOREIGN KEY (idinput) REFERENCES input(id);


--
-- Name: path fk_path_next_path; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY path
    ADD CONSTRAINT fk_path_next_path FOREIGN KEY (next) REFERENCES path(id);


--
-- Name: path fk_path_prev_path; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY path
    ADD CONSTRAINT fk_path_prev_path FOREIGN KEY (prev) REFERENCES path(id);


--
-- Name: project fk_project_file; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY project
    ADD CONSTRAINT fk_project_file FOREIGN KEY (idfile) REFERENCES file(id);


--
-- Name: dict fk_type; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY dict
    ADD CONSTRAINT fk_type FOREIGN KEY (iddict_type) REFERENCES dict_type(id);


--
-- PostgreSQL database dump complete
--

