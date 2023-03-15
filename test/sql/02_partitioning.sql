LOAD 'pg_anonymize';
-- mask our own user
SELECT current_user \gset
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS 'anonymize';

--------------------
-- list partitioning
--------------------
CREATE TABLE t_part_list(id integer, val text) PARTITION BY LIST (id);
CREATE TABLE t_part_list_1 PARTITION OF t_part_list FOR VALUES IN (1);
CREATE TABLE t_part_list_2 PARTITION OF t_part_list FOR VALUES IN (2);
INSERT INTO t_part_list SELECT i, 'line ' || i FROM generate_series(1, 2) i;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_part_list.val IS $$'root hidden'::text$$;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_part_list_2.val IS $$'part hidden'::text$$;

SET pg_anonymize.enabled = 'off';

-- should see original data
SELECT * FROM t_part_list ORDER BY id;
SELECT * FROM t_part_list_1 ORDER BY id;
SELECT * FROM t_part_list_2 ORDER BY id;

SET pg_anonymize.enabled = 'on';

--should see anonymized data when selecting from root partition
SELECT * FROM t_part_list ORDER BY id;
COPY t_part_list TO stdout;
-- but original data from any leaf partition
SELECT * FROM t_part_list_1 ORDER BY id;
COPY t_part_list_1 TO stdout;
-- unless there's an explicit anonymization rule on it
SELECT * FROM t_part_list_2 ORDER BY id;
COPY t_part_list_2 TO stdout;

---------------------
-- range partitioning
---------------------
CREATE TABLE t_part_range(id integer, val text) PARTITION BY RANGE (id);
CREATE TABLE t_part_range_1_3 PARTITION OF t_part_range FOR VALUES FROM (1) TO (3);
CREATE TABLE t_part_range_3_5 PARTITION OF t_part_range FOR VALUES FROM (3) TO (5);
INSERT INTO t_part_range SELECT i, 'line ' || i FROM generate_series(1, 4) i;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_part_range.val IS $$'root hidden'::text$$;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_part_range_3_5.val IS $$'part hidden'::text$$;

SET pg_anonymize.enabled = 'off';

-- should see original data
SELECT * FROM t_part_range ORDER BY id;
SELECT * FROM t_part_range_1_3 ORDER BY id;
SELECT * FROM t_part_range_3_5 ORDER BY id;

SET pg_anonymize.enabled = 'on';

--should see anonymized data when selecting from root partition
SELECT * FROM t_part_range ORDER BY id;
COPY t_part_range TO stdout;
-- but original data from any leaf partition
SELECT * FROM t_part_range_1_3 ORDER BY id;
COPY t_part_range_1_3 TO stdout;
-- unless there's an explicit anonymization rule on it
SELECT * FROM t_part_range_3_5 ORDER BY id;
COPY t_part_range_3_5 TO stdout;
