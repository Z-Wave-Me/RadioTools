#!/usr/bin/python3
# This script is for tests only!
# TODO: remove unneeded lines

from zme_modemhost import ZMEModemListener
from common.zme_aux import *
from common.zme_sapi import *
from common.zme_serialport import Port
from zwave.zme_zwave_protocol import ZWaveDataEncoder
import os
import time
import signal
import argparse
import logging
import colorama
from zme_threads import GracefulTerminator
from zme_web_sevices import ZMELicenseService
from threading import Lock

signum = 0
running = 1

def sig_hdlr(_signum, frame):
	global running, signum
	signum = _signum
	running = 0

if __name__ == "__main__":
	def Main():
		zmeSetupLogging("ZMEDUMMY", True, True)
		logging.debug("\nStarting on %s.\nARGS:%s" % (
		  platform.system(), ' '.join(sys.argv)))
		print("args: %s" % (' '.join(sys.argv)))
		signal.signal(signal.SIGTERM, sig_hdlr)
		signal.signal(signal.SIGINT, sig_hdlr)
		signal.signal(signal.SIGHUP, sig_hdlr)
		signal.signal(signal.SIGQUIT, sig_hdlr)
		while running:
			logging.info("keep alive %f" %(time.time()))
			print(".", end='', flush=True)
			time.sleep(5)
		logging.info("terminating (%d)" % (signum))
	Main()