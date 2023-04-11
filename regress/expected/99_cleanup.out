LOAD 'pg_anonymize';
-- unmask our own user
SELECT current_user \gset
SECURITY LABEL FOR pg_anonymize ON ROLE :current_user IS NULL;
