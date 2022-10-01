CREATE TABLE public.customer(id integer,
    first_name text,
    last_name text,
    birthday date,
    phone_number text);
INSERT INTO public.customer VALUES (1, 'Nice', 'Customer', '1970-03-04', '+886 1234 5678');
GRANT SELECT ON TABLE public.customer TO alice;

CREATE FUNCTION write_and_return(val text) RETURNS text AS
$$
BEGIN
    INSERT INTO public.customer(id) VALUES (0);
    RETURN 'hoho';
END;
$$ LANGUAGE plpgsql;

LOAD 'pg_anonymize';

-- test check_labels option
SET pg_anonymize.check_labels = 'on';

-- invalid expression
SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.first_name
    IS 'error';
-- wrong type
SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.first_name
    IS '1';
-- underlying write
SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.first_name
    IS $$write_and_return(first_name)$$;
-- SQL injection
SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.first_name
    IS $$'some value'; INSERT INTO public.customer SELECT 1; --$$;
-- unknown to non-text
SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.birthday
    IS $$'1970-01-01'$$;
-- unknown to text is ok with a notice
SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.last_name
    IS $$'some text'$$;

-- Test various anonymization
SET pg_anonymize.enabled = 'on';

SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.last_name
    IS $$substr(last_name, 1, 1) || '*****'$$;
SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.birthday
    IS $$date_trunc('year', birthday)::date$$;
SECURITY LABEL FOR pg_anonymize ON COLUMN public.customer.phone_number
    IS $$regexp_replace(phone_number, '\d', 'X', 'g')$$;

-- current role should see the data
SELECT * FROM public.customer;

-- mask our own user
SELECT current_user \gset
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS 'anonymize';

-- current role should see anonymized data
SELECT * FROM public.customer;
COPY public.customer TO stdout;
COPY public.customer(first_name, phone_number) TO stdout;

-- current role should see normal data when pg_anonymize isn't enabled
SET pg_anonymize.enabled = 'off';
SELECT * FROM public.customer;
COPY public.customer TO stdout;
COPY public.customer(first_name, phone_number) TO stdout;

-- cleanup
SET pg_anonymize.enabled = 'on';
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS NULL;

-- current role should see normal data
SELECT * FROM public.customer;
