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

SET search_path = public, pg_catalog;

--
-- Data for Name: dict_type; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY dict_type (id, "table", "column", comments) FROM stdin;
1	project	arch	NULL
2	project	status	NULL
3	content	type	NULL
4	basic_block	status	NULL
5	edge	instruction	NULL
6	edge	condition	NULL
7	edge	status	NULL
8	input	status	NULL
9	interested	status	NULL
\.


--
-- Data for Name: dict; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY dict (id, iddict_type, value, description, comments) FROM stdin;
1	1	1	i386	NULL
2	1	2	x86_64	NULL
3	1	3	armel	NULL
4	2	1	normal	NULL
5	2	2	achived	NULL
6	3	1	executable	NULL
7	3	2	library	NULL
8	3	3	config	NULL
9	4	1	active	NULL
10	4	2	archived	NULL
11	5	1	jump	NULL
12	5	2	fall-thru	NULL
13	5	3	exception handling	NULL
14	5	4	sibling calls	NULL
15	5	5	computed jumps	NULL
16	5	6	nonlocal goto handlers\n	NULL
17	5	7	function entry points	NULL
18	5	8	function exits	NULL
19	6	1	true	NULL
20	6	2	false	NULL
21	6	3	none	NULL
22	7	1	active	NULL
23	7	2	archive	NULL
24	8	0	new	NULL
25	8	1	normal	NULL
26	8	2	achived	NULL
27	9	1	new	NULL
28	9	2	solving	NULL
29	9	3	success	NULL
30	9	4	fail	NULL
31	9	5	timeout	NULL
\.


--
-- Name: dict_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('dict_id_seq', 31, true);


--
-- Name: dict_type_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('dict_type_id_seq', 9, true);


--
-- PostgreSQL database dump complete
--

