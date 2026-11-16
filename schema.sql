-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.profiles (
  id uuid NOT NULL,
  display_name text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT profiles_pkey PRIMARY KEY (id),
  CONSTRAINT profiles_id_fkey FOREIGN KEY (id) REFERENCES auth.users(id)
);
CREATE TABLE public.user_settings (
  user_id uuid NOT NULL,
  monthly_budget numeric NOT NULL DEFAULT 0 CHECK (monthly_budget >= 0::numeric),
  currency text NOT NULL DEFAULT 'COP'::text,
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT user_settings_pkey PRIMARY KEY (user_id),
  CONSTRAINT user_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.tasks (
  id bigint NOT NULL,
  user_id uuid NOT NULL,
  title text NOT NULL,
  priority text NOT NULL DEFAULT 'medium'::text CHECK (priority = ANY (ARRAY['high'::text, 'medium'::text, 'low'::text])),
  due_date date,
  completed boolean NOT NULL DEFAULT false,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT tasks_pkey PRIMARY KEY (user_id, id),
  CONSTRAINT tasks_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.transactions (
  id bigint NOT NULL,
  user_id uuid NOT NULL,
  description text NOT NULL,
  amount numeric NOT NULL CHECK (amount > 0::numeric),
  type text NOT NULL CHECK (type = ANY (ARRAY['income'::text, 'expense'::text])),
  category text NOT NULL DEFAULT 'General'::text,
  transaction_date date NOT NULL DEFAULT CURRENT_DATE,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT transactions_pkey PRIMARY KEY (user_id, id),
  CONSTRAINT transactions_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.goals (
  id bigint NOT NULL,
  user_id uuid NOT NULL,
  name text NOT NULL,
  target numeric NOT NULL CHECK (target > 0::numeric),
  current_amount numeric NOT NULL DEFAULT 0 CHECK (current_amount >= 0::numeric),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT goals_pkey PRIMARY KEY (user_id, id),
  CONSTRAINT goals_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.appointments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  title text NOT NULL,
  description text,
  location text,
  start_at timestamp with time zone NOT NULL,
  end_at timestamp with time zone NOT NULL,
  timezone text NOT NULL DEFAULT 'America/Bogota'::text,
  calendar_event_id text,
  sync_status text NOT NULL DEFAULT 'pending'::text CHECK (sync_status = ANY (ARRAY['pending'::text, 'synced'::text, 'error'::text])),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  origin text NOT NULL DEFAULT 'balance'::text CHECK (origin = ANY (ARRAY['balance'::text, 'google'::text])),
  google_etag text,
  google_updated_at timestamp with time zone,
  all_day boolean NOT NULL DEFAULT false,
  deleted_at timestamp with time zone,
  CONSTRAINT appointments_pkey PRIMARY KEY (id),
  CONSTRAINT appointments_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.calendar_connections (
  user_id uuid NOT NULL,
  google_email text,
  calendar_id text DEFAULT 'primary'::text,
  access_token_encrypted text,
  refresh_token_encrypted text,
  token_expires_at timestamp with time zone,
  granted_scopes ARRAY,
  sync_token text,
  channel_id text,
  channel_resource_id text,
  channel_expires_at timestamp with time zone,
  connected_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  last_synced_at timestamp with time zone,
  sync_error text,
  CONSTRAINT calendar_connections_pkey PRIMARY KEY (user_id),
  CONSTRAINT calendar_connections_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
