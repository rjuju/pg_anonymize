EXTVERSION   = 0.0.1
PGFILEDESC   = "pg_anonymize - perform data anonymization transparently on the database"

MODULE_big   = pg_anonymize
OBJS         = pg_anonymize.o

REGRESS      = 01_general \
               02_partitioning
ifneq ($(MAJORVERSION), 10)
	REGRESS += 02_partitioning_hash
endif
REGRESS     += 03_inheritance \
               99_cleanup

REGRESS_DIR  = "$(CURDIR)/regress"
EXTRA_REGRESS_OPTS = --inputdir=$(REGRESS_DIR) \
                     --outputdir=$(REGRESS_DIR)

EXTRA_CLEAN  = $(REGRESS_DIR)/results \
               $(REGRESS_DIR)/regression.diffs \
               $(REGRESS_DIR)/regression.out

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

release-zip: all
	git archive --format zip --prefix=pg_anonymize-${EXTVERSION}/ --output ./pg_anonymize-${EXTVERSION}.zip HEAD
	unzip ./pg_anonymize-$(EXTVERSION).zip
	rm ./pg_anonymize-$(EXTVERSION).zip
	rm ./pg_anonymize-$(EXTVERSION)/.gitignore
	sed -i -e "s/__VERSION__/$(EXTVERSION)/g"  ./pg_anonymize-$(EXTVERSION)/META.json
	zip -r ./pg_anonymize-$(EXTVERSION).zip ./pg_anonymize-$(EXTVERSION)/
	rm ./pg_anonymize-$(EXTVERSION) -rf
