#!/bin/bash
# Usage: $0 [FILES_MAX_CNT]

set -u

cd `dirname $0`
. zme_radiotools.conf

if [[ "${1:-}" ]]; then
	cnt_max=$1
else
	cnt_max=$ZME_LOGSCNT
fi
fnamepref_cur=""
cnt=0
ls -1 "$ZME_LOGPATH/" | sort -r | while read fname; do
	fnamepref=${fname%%-*}
	if [[ "$fnamepref_cur" != "$fnamepref" ]]; then
		fnamepref_cur=$fnamepref
		cnt=$cnt_max
	fi
	if [[ $cnt -eq 0 ]]; then
		echo rm $fname
	else
		((cnt--))
	fi
done
