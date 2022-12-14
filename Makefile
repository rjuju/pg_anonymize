EXTVERSION   = 0.0.1
TESTS        = $(wildcard test/sql/*.sql)
REGRESS      = $(patsubst test/sql/%.sql,%,$(TESTS))
REGRESS_OPTS = --inputdir=test

PG_CONFIG = pg_config

MODULE_big = pg_anonymize
OBJS = pg_anonymize.o

all:

release-zip: all
	git archive --format zip --prefix=pg_anonymize-${EXTVERSION}/ --output ./pg_anonymize-${EXTVERSION}.zip HEAD
	unzip ./pg_anonymize-$(EXTVERSION).zip
	rm ./pg_anonymize-$(EXTVERSION).zip
	rm ./pg_anonymize-$(EXTVERSION)/.gitignore
	sed -i -e "s/__VERSION__/$(EXTVERSION)/g"  ./pg_anonymize-$(EXTVERSION)/META.json
	zip -r ./pg_anonymize-$(EXTVERSION).zip ./pg_anonymize-$(EXTVERSION)/
	rm ./pg_anonymize-$(EXTVERSION) -rf


DATA = $(wildcard *--*.sql)
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
