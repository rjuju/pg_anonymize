LOAD 'pg_anonymize';
-- mask our own user
SELECT current_user \gset
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS 'anonymize';

CREATE TABLE t_inh(id integer, val text);
CREATE TABLE t_inh_a (val_a text) INHERITS (t_inh);
CREATE TABLE t_inh_b (val_b text) INHERITS (t_inh);

INSERT INTO t_inh SELECT 1, 't_inh';
INSERT INTO t_inh_a SELECT 2, 't_inh_a', 'a';
INSERT INTO t_inh_b SELECT 3, 't_inh_b', 'b';

SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_inh.val IS $$'root hidden'::text$$;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_inh_b.val IS $$'part hidden'::text$$;

SET pg_anonymize.enabled = 'off';

-- should see original data
SELECT * FROM t_part_list ORDER BY id;

SET pg_anonymize.enabled = 'on';

--should see anonymized data when selecting from parent table
SELECT * FROM t_inh ORDER BY id;
COPY t_inh TO stdout;
-- but original data from any leaf table
SELECT * FROM t_inh_a ORDER BY id;
COPY t_inh_a TO stdout;
-- unless there's an explicit anonymization rule on it
SELECT * FROM t_inh_b ORDER BY id;
COPY t_inh_b TO stdout;