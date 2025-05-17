-- DDL for table: logs
CREATE TABLE logs (
     id SERIAL PRIMARY KEY NOT NULL,
     timestamp timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
     action character varying NOT NULL,
     details character varying NOT NULL,
     private_level character varying NOT NULL,
     ip_address character varying
);

-- DDL for table: logs_archive
CREATE TABLE logs_archive (
     id SERIAL PRIMARY KEY NOT NULL,
     timestamp timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
     action character varying NOT NULL,
     details character varying NOT NULL,
     private_level character varying NOT NULL,
     ip_address character varying
);

-- DDL for table: requests
CREATE TABLE requests (
     id SERIAL PRIMARY KEY NOT NULL ,
     timestamp timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
     ticket_uuid character varying NOT NULL,
     wallet_name character varying NOT NULL,
     ip_address character varying,
     category character varying,
     status character varying DEFAULT 'Pending'::character varying,
     reason character varying,
     request_type character varying NOT NULL
);

-- DDL for table: settings
CREATE TABLE settings (
     id SERIAL PRIMARY KEY NOT NULL ,
     maximum_currency double precision DEFAULT 1000000.0,
     allow_debts boolean DEFAULT false,
     allow_self_review boolean DEFAULT false,
     allow_leaderboard boolean DEFAULT true,
     allow_public_logs boolean DEFAULT true,
     bank_name character varying NOT NULL,
     currency_name character varying NOT NULL,
);

-- DDL for table: users
CREATE TABLE users (
     id SERIAL PRIMARY KEY NOT NULL ,
     current_currency double precision DEFAULT 0.0,
     created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
     last_login timestamp with time zone,
     is_frozen boolean DEFAULT false,
     wallet_name character varying NOT NULL,
     password character varying NOT NULL
);
