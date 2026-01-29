CREATE DATABASE network_policy;
\c network_policy;

--
-- PostgreSQL database dump
--

-- Dumped from database version 17.6
-- Dumped by pg_dump version 17.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: destinations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.destinations (
    id integer NOT NULL,
    group_id integer,
    port integer,
    protocol text,
    start_port integer,
    end_port integer
);


--
-- Name: destinations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.destinations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: destinations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.destinations_id_seq OWNED BY public.destinations.id;


--
-- Name: gorp_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.gorp_migrations (
    id text NOT NULL,
    applied_at timestamp with time zone
);


--
-- Name: groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.groups (
    id integer NOT NULL,
    guid text,
    type text DEFAULT 'app'::text
);


--
-- Name: groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.groups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.groups_id_seq OWNED BY public.groups.id;


--
-- Name: policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.policies (
    id integer NOT NULL,
    group_id integer,
    destination_id integer
);


--
-- Name: policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.policies_id_seq OWNED BY public.policies.id;


--
-- Name: policies_info; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.policies_info (
    id integer NOT NULL,
    last_updated timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: policies_info_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.policies_info_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: policies_info_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.policies_info_id_seq OWNED BY public.policies_info.id;


--
-- Name: running_security_groups_spaces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.running_security_groups_spaces (
    space_guid character varying(36) NOT NULL,
    security_group_guid character varying(36) NOT NULL
);


--
-- Name: security_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.security_groups (
    id bigint NOT NULL,
    guid character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    rules text,
    staging_default boolean DEFAULT false,
    running_default boolean DEFAULT false,
    staging_spaces jsonb,
    running_spaces jsonb,
    hash character varying(255) DEFAULT ''::character varying
);


--
-- Name: security_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.security_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: security_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.security_groups_id_seq OWNED BY public.security_groups.id;


--
-- Name: security_groups_info; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.security_groups_info (
    id integer NOT NULL,
    last_updated timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: security_groups_info_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.security_groups_info_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: security_groups_info_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.security_groups_info_id_seq OWNED BY public.security_groups_info.id;


--
-- Name: staging_security_groups_spaces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.staging_security_groups_spaces (
    space_guid character varying(36) NOT NULL,
    security_group_guid character varying(36) NOT NULL
);


--
-- Name: destinations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.destinations ALTER COLUMN id SET DEFAULT nextval('public.destinations_id_seq'::regclass);


--
-- Name: groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups ALTER COLUMN id SET DEFAULT nextval('public.groups_id_seq'::regclass);


--
-- Name: policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policies ALTER COLUMN id SET DEFAULT nextval('public.policies_id_seq'::regclass);


--
-- Name: policies_info id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policies_info ALTER COLUMN id SET DEFAULT nextval('public.policies_info_id_seq'::regclass);


--
-- Name: security_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_groups ALTER COLUMN id SET DEFAULT nextval('public.security_groups_id_seq'::regclass);


--
-- Name: security_groups_info id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_groups_info ALTER COLUMN id SET DEFAULT nextval('public.security_groups_info_id_seq'::regclass);


--
-- Name: destinations destinations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.destinations
    ADD CONSTRAINT destinations_pkey PRIMARY KEY (id);


--
-- Name: gorp_migrations gorp_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gorp_migrations
    ADD CONSTRAINT gorp_migrations_pkey PRIMARY KEY (id);


--
-- Name: groups groups_guid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_guid_key UNIQUE (guid);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: policies policies_group_id_destination_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_group_id_destination_id_key UNIQUE (group_id, destination_id);


--
-- Name: policies_info policies_info_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policies_info
    ADD CONSTRAINT policies_info_pkey PRIMARY KEY (id);


--
-- Name: policies policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_pkey PRIMARY KEY (id);


--
-- Name: running_security_groups_spaces running_sg_spaces_pk; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.running_security_groups_spaces
    ADD CONSTRAINT running_sg_spaces_pk PRIMARY KEY (space_guid, security_group_guid);


--
-- Name: security_groups security_groups_guid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_groups
    ADD CONSTRAINT security_groups_guid_key UNIQUE (guid);


--
-- Name: security_groups_info security_groups_info_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_groups_info
    ADD CONSTRAINT security_groups_info_pkey PRIMARY KEY (id);


--
-- Name: security_groups security_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_groups
    ADD CONSTRAINT security_groups_pkey PRIMARY KEY (id);


--
-- Name: staging_security_groups_spaces staging_sg_spaces_pk; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.staging_security_groups_spaces
    ADD CONSTRAINT staging_sg_spaces_pk PRIMARY KEY (space_guid, security_group_guid);


--
-- Name: destinations unique_destination; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.destinations
    ADD CONSTRAINT unique_destination UNIQUE (group_id, start_port, end_port, protocol);


--
-- Name: idx_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_type ON public.groups USING btree (type);


--
-- Name: destinations destinations_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.destinations
    ADD CONSTRAINT destinations_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id);


--
-- Name: policies policies_destination_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_destination_id_fkey FOREIGN KEY (destination_id) REFERENCES public.destinations(id);


--
-- Name: policies policies_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id);


--
-- Name: running_security_groups_spaces running_sg_spaces_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.running_security_groups_spaces
    ADD CONSTRAINT running_sg_spaces_fk FOREIGN KEY (security_group_guid) REFERENCES public.security_groups(guid) ON DELETE CASCADE;


--
-- Name: staging_security_groups_spaces staging_sg_spaces_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.staging_security_groups_spaces
    ADD CONSTRAINT staging_sg_spaces_fk FOREIGN KEY (security_group_guid) REFERENCES public.security_groups(guid) ON DELETE CASCADE;

--
-- PostgreSQL database dump complete
--
