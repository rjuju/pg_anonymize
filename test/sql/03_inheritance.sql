LOAD 'pg_anonymize';
-- mask our own user
SELECT current_user \gset
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS 'anonymize';

CREATE TABLE t_inh(id integer, val text);
CREATE TABLE t_inh_a (val_a text, id integer) INHERITS (t_inh);
CREATE TABLE t_inh_b (val_b text) INHERITS (t_inh);
-- multi inheritance
CREATE TABLE t_inh_ab_c (id integer, val_a text, val_c text)
    INHERITS (t_inh_a, t_inh_b);

INSERT INTO t_inh SELECT 1, 't_inh';
INSERT INTO t_inh_a SELECT 2, 't_inh_a', 'a';
INSERT INTO t_inh_b SELECT 3, 't_inh_b', 'b';
INSERT INTO t_inh_ab_c SELECT 4, 't_inh_c', 't_inh_c', 't_inh_c', 'c';

SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_inh.val IS $$'root hidden'::text$$;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_inh_b.val IS $$'part hidden'::text$$;
SECURITY LABEL FOR pg_anonymize
    ON COLUMN public.t_inh_ab_c.val_c IS $$'part c hidden'::text$$;

SET pg_anonymize.enabled = 'off';

-- should see original data
SELECT * FROM t_inh ORDER BY id;
COPY t_inh TO STDOUT;
SELECT * FROM t_inh_a ORDER BY id;
COPY t_inh_a TO STDOUT;
SELECT * FROM t_inh_b ORDER BY id;
COPY t_inh_b TO STDOUT;
SELECT * FROM t_inh_ab_c ORDER BY id;
COPY t_inh_ab_c TO STDOUT;

SET pg_anonymize.enabled = 'on';

--should see anonymized data when selecting from parent table
SELECT * FROM t_inh ORDER BY id;
COPY t_inh TO STDOUT;
-- but original data from any leaf table
SELECT * FROM t_inh_a ORDER BY id;
COPY t_inh_a TO STDOUT;
-- unless there's an explicit anonymization rule on it
SELECT * FROM t_inh_b ORDER BY id;
COPY t_inh_b TO STDOUT;
SELECT * FROM t_inh_ab_c ORDER BY id;
COPY t_inh_ab_c TO STDOUT;
