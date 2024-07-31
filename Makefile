ZME_RTHOME := /opt/zme_radiotools

.PHONY: all install install-autostart dist clean clean-all

all: install-autostart

dist:
	tar -c --exclude=zme_radiotools.txz --exclude='.git*' . | xz > zme_radiotools.txz

clean-all: clean
	rm -f zme_radiotools.txz

clean:
	rm -f *~

install: dist
	mkdir -p $(ZME_RTHOME) /var/cache/zme_radiotools
	unxz -c zme_radiotools.txz | ( cd $(ZME_RTHOME); tar -x --exclude="zme_radiotools.crontab.in" --exclude="zme_radiotools.initd.in" --no-same-owner )
	sed -re 's/@ZME_RTHOME@/$(subst /,\/,$(ZME_RTHOME))/' zme_radiotools.crontab.in > /etc/cron.d/zme_radiotools
	sed -re 's/@ZME_RTHOME@/$(subst /,\/,$(ZME_RTHOME))/' zme_radiotools.initd.in > /etc/init.d/zme_radiotools
	chmod a+rx /etc/init.d/zme_radiotools

install-autostart: install
	if which systemctl >/dev/null 2>&1; then\
		systemctl enable zme_radiotools\
	elif which rc-update >/dev/null 2>&1; then\
		rc-update add zme_radiotools defaults\
	elif which update-rc.d >/dev/null 2>&1; then\
		update-rc.d zme_radiotools defaults\
	else\
		echo "INFO! Now you can add /etc/init.d/zme_radiotools to autostart."\
	fi
