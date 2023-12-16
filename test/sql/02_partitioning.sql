LOAD 'pg_anonymize';
-- mask our own user
SELECT current_user \gset
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS 'anonymize';

--------------------
-- list partitioning
--------------------
CREATE TABLE t_part_list(id integer, val text) PARTITION BY LIST (id);
CREATE TABLE t_part_list_1(val text, id integer);
ALTER TABLE t_part_list ATTACH PARTITION t_part_list_1 FOR VALUES IN (1);
CREATE TABLE t_part_list_2(val text, id integer);
ALTER TABLE t_part_list ATTACH PARTITION t_part_list_2 FOR VALUES IN (2);
INSERT INTO t_part_list SELECT i, 'line ' || i FROM generate_series(1, 2) i;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_part_list.val IS $$'root hidden'::text$$;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_part_list_2.val IS $$'part hidden'::text$$;

SET pg_anonymize.enabled = 'off';

-- should see original data
SELECT * FROM t_part_list ORDER BY id;
COPY t_part_list TO STDOUT;
SELECT * FROM t_part_list_1 ORDER BY id;
COPY t_part_list_1 TO STDOUT;
SELECT * FROM t_part_list_2 ORDER BY id;
COPY t_part_list_2 TO STDOUT;

SET pg_anonymize.enabled = 'on';
SET pg_anonymize.inherit_labels = false;

--should see anonymized data when selecting from root partition
SELECT * FROM t_part_list ORDER BY id;
COPY t_part_list TO STDOUT;
-- but original data from any leaf partition when label inheritance is disabled
SELECT * FROM t_part_list_1 ORDER BY id;
COPY t_part_list_1 TO STDOUT;
-- unless there's an explicit anonymization rule on it
SELECT * FROM t_part_list_2 ORDER BY id;
COPY t_part_list_2 TO STDOUT;

SET pg_anonymize.inherit_labels = true;
-- should see anonymized data from inherited security labels
SELECT * FROM t_part_list_1 ORDER BY id;
COPY t_part_list_1 TO STDOUT;
-- and still see same anonymized data
SELECT * FROM t_part_list_2 ORDER BY id;
COPY t_part_list_2 TO STDOUT;

---------------------
-- range partitioning
---------------------
CREATE TABLE t_part_range(id integer, val text) PARTITION BY RANGE (id);
CREATE TABLE t_part_range_1_3(val text, id integer);
ALTER TABLE t_part_range ATTACH PARTITION t_part_range_1_3 FOR VALUES FROM (1) TO (3);
CREATE TABLE t_part_range_3_5(val text, id integer);
ALTER TABLE t_part_range ATTACH PARTITION t_part_range_3_5 FOR VALUES FROM (3) TO (5);
INSERT INTO t_part_range SELECT i, 'line ' || i FROM generate_series(1, 4) i;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_part_range.val IS $$'root hidden'::text$$;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_part_range_3_5.val IS $$'part hidden'::text$$;

SET pg_anonymize.enabled = 'off';

-- should see original data
SELECT * FROM t_part_range ORDER BY id;
COPY t_part_range TO STDOUT;
SELECT * FROM t_part_range_1_3 ORDER BY id;
COPY t_part_range_1_3 TO STDOUT;
SELECT * FROM t_part_range_3_5 ORDER BY id;
COPY t_part_range_3_5 TO STDOUT;

SET pg_anonymize.enabled = 'on';
SET pg_anonymize.inherit_labels = false;

--should see anonymized data when selecting from root partition
SELECT * FROM t_part_range ORDER BY id;
COPY t_part_range TO STDOUT;
-- but original data from any leaf partition when label inheritance is disabled
SELECT * FROM t_part_range_1_3 ORDER BY id;
COPY t_part_range_1_3 TO STDOUT;
-- unless there's an explicit anonymization rule on it
SELECT * FROM t_part_range_3_5 ORDER BY id;
COPY t_part_range_3_5 TO STDOUT;

SET pg_anonymize.inherit_labels = true;
-- should see anonymized data from inherited security labels
SELECT * FROM t_part_range_1_3 ORDER BY id;
COPY t_part_range_1_3 TO STDOUT;
-- and still see same anonymized data
SELECT * FROM t_part_range_3_5 ORDER BY id;
COPY t_part_range_3_5 TO STDOUT;

----------------------
-- nested partitioning
----------------------
-- root level
CREATE TABLE t_part_nest(id integer, id2 integer, val text)
    PARTITION BY RANGE (id);
-- level 1
CREATE TABLE t_part_nest_1(id2 integer, id integer, val text);
ALTER TABLE t_part_nest ATTACH PARTITION t_part_nest_1 FOR VALUES FROM (1) TO (2);
CREATE TABLE t_part_nest_23(val text, id2 integer, id integer) PARTITION BY LIST (id);
ALTER TABLE t_part_nest ATTACH PARTITION t_part_nest_23 FOR VALUES FROM (2) TO (4);
-- level 2
CREATE TABLE t_part_nest_23_2(val text, id integer, id2 integer);
ALTER TABLE t_part_nest_23 ATTACH PARTITION t_part_nest_23_2 FOR VALUES IN (2);
CREATE TABLE t_part_nest_23_3(val text, id integer, id2 integer);
ALTER TABLE t_part_nest_23 ATTACH PARTITION t_part_nest_23_3 FOR VALUES IN (3);

INSERT INTO t_part_nest SELECT i, i, 'line ' || i FROM generate_series(1, 3) i;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN t_part_nest.val IS $$'root hidden'::text$$;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN t_part_nest_23.val IS $$'nested hidden'::text$$;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN t_part_nest_23_3.id2 IS $$42$$;

SET pg_anonymize.enabled = 'off';

-- should see original data
SELECT * FROM t_part_nest ORDER BY id;
COPY t_part_nest TO STDOUT;
SELECT * FROM t_part_nest_1 ORDER BY id;
COPY t_part_nest_1 TO STDOUT;
SELECT * FROM t_part_nest_23 ORDER BY id;
COPY t_part_nest_23 TO STDOUT;
SELECT * FROM t_part_nest_23_2 ORDER BY id;
COPY t_part_nest_23_2 TO STDOUT;
SELECT * FROM t_part_nest_23_3 ORDER BY id;
COPY t_part_nest_23_3 TO STDOUT;

SET pg_anonymize.enabled = 'on';
SET pg_anonymize.inherit_labels = false;

-- should see anonymized data when selecting from root partition
SELECT * FROM t_part_nest ORDER BY id;
COPY t_part_nest TO STDOUT;
-- but original data from any leaf / subpartition when label inheritance is
-- disabled
SELECT * FROM t_part_nest_1 ORDER BY id;
COPY t_part_nest_1 TO STDOUT;
SELECT * FROM t_part_nest_23_2 ORDER BY id;
COPY t_part_nest_23_2 TO STDOUT;
-- unless there's an explicit anonymization rule for it
SELECT * FROM t_part_nest_23 ORDER BY id;
COPY t_part_nest_23 TO STDOUT;
SELECT * FROM t_part_nest_23_3 ORDER BY id;
COPY t_part_nest_23_3 TO STDOUT;

SET pg_anonymize.inherit_labels = true;
-- should see anonymized data from inherited security labels
SELECT * FROM t_part_nest_1 ORDER BY id;
COPY t_part_nest_1 TO STDOUT;
SELECT * FROM t_part_nest_23_2 ORDER BY id;
COPY t_part_nest_23_2 TO STDOUT;
-- and still see same anonymized data for some table
SELECT * FROM t_part_nest_23 ORDER BY id;
COPY t_part_nest_23 TO STDOUT;
-- and a mix of inherited and non inherited anonymized data
SELECT * FROM t_part_nest_23_3 ORDER BY id;
COPY t_part_nest_23_3 TO STDOUT;

-- cleanup
SET pg_anonymize.enabled = 'on';
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS NULL;
