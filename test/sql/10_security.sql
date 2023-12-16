--setup
LOAD 'pg_anonymize';

CREATE TABLE customer_security(
    id integer,
    name text,
    country text
);

INSERT INTO customer_security VALUES (1, 'Secret Name', 'Taiwan');

SECURITY LABEL ON COLUMN customer_security.name IS $$'XXX'::text$$;

-- mask our own user
SELECT current_user \gset
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS 'anonymize';

SELECT * FROM customer_security;

-- It shouldn't be possible to access the original fooling the planner
CREATE FUNCTION leak_info(name text, country text) RETURNS BOOL AS
$_$
BEGIN
    RAISE NOTICE 'saw % - %', name, country;

    RETURN true;
END;
$_$ LANGUAGE plpgsql COST 0.0000000000000000000001;

SELECT * FROM customer_security WHERE leak_info(name, country);

-- cleanup
SET pg_anonymize.enabled = 'on';
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS NULL;
