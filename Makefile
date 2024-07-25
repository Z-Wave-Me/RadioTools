DESTDIR := /opt/zme_radiotools

.PHONY: install dist clean clean-all

dist:
	tar -c --exclude=zme_radiotools.txz --exclude='.git*' . | xz > zme_radiotools.txz

clean-all: clean
	rm -f zme_radiotools.txz

clean:
	rm -f *~

install: dist
	mkdir -p $(DESTDIR)
	unxz -c zme_radiotools.txz | ( cd $(DESTDIR); tar -x --exclude="zme_radiotools.crontab.in" --no-same-owner )
