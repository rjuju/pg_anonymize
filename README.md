pg_anonymize
============

pg_anonymize is a PostgreSQL extension that allows to perform data
anonymization transparently on the database.

![Tests](https://github.com/rjuju/pg_anonymize/actions/workflows/tests.yml/badge.svg?branch=main)

Requirements
------------

pg_anonymize is compatible with PostgreSQL 10 and above.

Installation
------------

You need the PostgreSQL header files for the major version(s) you want to build
the extension.  You have to make sure that `pg_config` is available and points
to the correct major version.  For instance, for PostgreSQL 14, `pg_config`
returns at the time this document was written:

```
$ pg_config --version
PostgreSQL 14.5
```

Decompress the tarball or clone the git repository.  In the pg_anonymize source
directory, run:

```
make
sudo make install
```

NOTE: you have to make sure that `sudo pg_config` sees the correct version.  If
you want to install the extension on multiple major versions, or used to wrong
`pg_config`, you have to first clean the compiled files using:

```
make clean
```

Configuration
-------------

pg_anonymize provides the following configuration options:

- **pg_anonymize.enabled** (bool): allows to globally enable or disable
  pg_anonymize.  The default value is **on**.

- **pg_anonymize.check_labels** (bool): perform sanity checks (expression
  validity, read-only, returned type and lack of SQL injection) on the defined
  expression when declaring security labels.  The default value is **on**.

- **pg_anonymize.inherit_labels** (bool): inherit security labels from relation
  ancestors (partitioned tables and inheritance tables) if any.  The default
  value is **on**.

NOTE: even if **pg_anonymize.check_labels** is disabled, pg_anonymize will
still check that the defined expression doesn't contain any SQL injection.

Usage
-----

pg_anonymize must be loaded before being able to use use.  There are multiple
ways to do it.  Usually, only a few roles should require data anonymization, so
the recommended way is to only load the extension for such roles.  For
instance, assuming the role **alice** should be used:

```
ALTER ROLE alice SET session_preload_libraries = 'pg_anonymize';
```

NOTE: only sessions opened by alice **after** this command has been
successfully run will load pg_anonymize.

You can alternatively load it explicitly, for instance:

```
LOAD 'pg_anonymize';
```

NOTE: LOAD requires superuser privileges.

You then need to declare the wanted role(s) as needing anonymized data.  This
is done adding a SECURITY LABEL **anonymize** on the target role(s).  For
instance:

```
-- pg_anonymize need to be loaded before declaring SECURITY LABEL
LOAD 'pg_anonymize';
SECURITY LABEL FOR pg_anonymize ON ROLE alice IS 'anonymize';
```

NOTE: declaring a SECURITY LABEL on a role requires CREATEROLE privilege.

You can then declare how to anonymize each column with SECURITY LABELS,
defining an expression to replace the actual content.

For instance, assuming a simplistic customer table:

```
CREATE TABLE public.customer(id integer,
    first_name text,
    last_name text,
    birthday date,
    phone_number text);

INSERT INTO public.customer VALUES (1, 'Nice', 'Customer', '1970-03-04', '+886 1234 5678');

GRANT SELECT ON TABLE public.customer TO alice;
```

Let's anonymize the last name, birthday and phone number:

```
SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.last_name
    IS $$substr(last_name, 1, 1) || '*****'$$;
SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.birthday
    IS $$date_trunc('year', birthday)::date$$;
SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.phone_number
    IS $$regexp_replace(phone_number, '\d', 'X', 'g')$$;
```

NOTE: declaring a SECURITY LABEL on a column requires to be owner of the
underlying relation.

The **alice** role will now automatically see anonymized data.  For instance:

```
-- current role sees the normal data
=# SELECT * FROM public.customer;
 id | first_name | last_name |  birthday  |  phone_number
----+------------+-----------+------------+----------------
  1 | Nice       | Customer  | 1970-03-04 | +886 1234 5678
(1 row)

-- but alice will see anonymized data
=# \c - alice
You are now connected to database "rjuju" as user "alice".

=> SELECT * FROM public.customer;
 id | first_name | last_name |  birthday  |  phone_number
----+------------+-----------+------------+----------------
  1 | Nice       | C*****    | 1970-01-01 | +XXX XXXX XXXX
(1 row)

-- pg_dump will also see anonymized data
$ pg_dump -U alice -t public.customer -a rjuju | grep "COPY" -A2
COPY public.customer (id, first_name, last_name, birthday, phone_number) FROM stdin;
1	Nice	C*****	1970-01-01	+XXX XXXX XXXX
\.
```
