EXTVERSION   = 0.0.1
REGRESS      = 01_general 02_partitioning
REGRESS_OPTS = --inputdir=test

PG_CONFIG ?= pg_config

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


PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

ifneq ($(MAJORVERSION), 10)
	REGRESS += 02_partitioning_hash
endif

REGRESS += 03_inheritance 99_cleanup
