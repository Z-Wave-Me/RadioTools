DESTDIR := /opt/zme_radiotools

.PHONY: install dist clean clean-all

dist:
	tar -c --exclude=zme_radiotools.txz --exclude='.git*' . | xz > zme_radiotools.txz

clean-all: clean
	rm -f zme_radiotools.txz

clean:
	rm -f *~

install: dist
	mkdir -p $(DESTDIR) /var/cache/zme_radiotools
	unxz -c zme_radiotools.txz | ( cd $(DESTDIR); tar -x --exclude="zme_radiotools.crontab.in" --exclude="zme_radiotools.initd.in" --no-same-owner )
	sed -re 's/@ZME_DESTDIR@/$(subst /,\/,$(DESTDIR))/' zme_radiotools.crontab.in > /etc/cron.d/zme_radiotools
	sed -re 's/@ZME_DESTDIR@/$(subst /,\/,$(DESTDIR))/' zme_radiotools.initd.in > /etc/init.d/zme_radiotools
	chmod a+rx /etc/init.d/zme_radiotools
