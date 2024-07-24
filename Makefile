.PHONY: dist clean clean-all

dist:
	tar -c --exclude=zme_radiotools.txz --exclude='.git*' . | xz > zme_radiotools.txz

clean-all: clean
	rm -f zme_radiotools.txz

clean:
	rm -f *~
