LOAD 'pg_anonymize';
-- mask our own user
SELECT current_user \gset
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS 'anonymize';

--------------------
-- hash partitioning
--------------------
CREATE TABLE t_part_hash(id integer, val text) PARTITION BY HASH (id);
CREATE TABLE t_part_hash_0 PARTITION OF t_part_hash FOR VALUES WITH (MODULUS 2, REMAINDER 0);
CREATE TABLE t_part_hash_1 PARTITION OF t_part_hash FOR VALUES WITH (MODULUS 2, REMAINDER 1);
INSERT INTO t_part_hash SELECT i, 'line ' || i FROM generate_series(1, 4) i;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_part_hash.val IS $$'root hidden'::text$$;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_part_hash_1.val IS $$'part hidden'::text$$;

SET pg_anonymize.enabled = 'off';

-- should see original data
SELECT * FROM t_part_hash ORDER BY id;
COPY t_part_hash TO STDOUT;
SELECT * FROM t_part_hash_0 ORDER BY id;
COPY t_part_hash_0 TO STDOUT;
SELECT * FROM t_part_hash_1 ORDER BY id;
COPY t_part_hash_1 TO STDOUT;

SET pg_anonymize.enabled = 'on';

--should see anonymized data when selecting from root partition
SELECT * FROM t_part_hash ORDER BY id;
COPY t_part_hash TO STDOUT;
-- but original data from any leaf partition
SELECT * FROM t_part_hash_0 ORDER BY id;
COPY t_part_hash_0 TO STDOUT;
-- unless there's an explicit anonymization rule on it
SELECT * FROM t_part_hash_1 ORDER BY id;
COPY t_part_hash_1 TO STDOUT;
