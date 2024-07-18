#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import os
import re
import platform
import logging
import errno
import time
import glob
import traceback
from time import gmtime, strftime
from random import randint
import traceback
import subprocess
import json
from common.zme_aux import *
from threading import Thread, Lock
import signal

MY_VERSION = "0.1b1"

class TaskThread(Thread):
    STATE_INITED = 0
    STATE_RUNNING = 1
    STATE_TERMINATED = 2
    
    
    def __init__(self, taskfunc):
        self._lock = Lock()
        self._output_queue = []
        self._func = taskfunc
        self._result = None
        self._term_request = False
        self._state = TaskThread.STATE_INITED
        Thread.__init__(self)
        
    def popOutput(self):
        d = None
        self._lock.acquire()
        if len(self._output_queue) > 0:
            d = self._output_queue[0]
            del self._output_queue[0]
        self._lock.release()
        return d
    def pushOutput(self, d):
        print("OUTPUT:%s"%(d))
        self._lock.acquire()
        self._output_queue += [d]
        self._lock.release()
    def terminate(self):
        self._lock.acquire()
        self._term_request = True
        self._lock.release()
        self.join()
    def has_to_term(self):
        r = False
        self._lock.acquire()
        r = self._term_request
        self._lock.release()
        return r
    def run(self):
        try:
            res = None
            self.setResult(res)
            self._state = TaskThread.STATE_RUNNING
            res = self._func(self)
            self.setResult(res)
            self._state = TaskThread.STATE_TERMINATED
        except:
            zmeProcessException("TaskThread.run")
            self._state = TaskThread.STATE_TERMINATED
            return
    def setResult(self, res):
        self._lock.acquire()
        self._result = res
        self._lock.release()
        return res
    def getResult(self):
        res = None
        self._lock.acquire()
        res = self._result
        self._lock.release()
        return res
    def isStopped(self):
        return (self._state == TaskThread.STATE_TERMINATED)
        
    

class LoopingThread(Thread):
    ACTIVE_DELAY_PERIOD = 0.0005
    def __init__(self, loopfunc):
        self._func = loopfunc
        self._lock = Lock()
        self._b_loop = True
        self._delay = 0.01
        Thread.__init__(self)

    def stopLoop(self):
        self._lock.acquire()
        self._b_loop = False
        self._lock.release()

    def isLooping(self):
        res = False
        self._lock.acquire()
        res = self._b_loop
        self._lock.release()
        return res

    def poll(self):
        if self.isLooping():
            self._func()
        self.on_stop()
    def setLatency(self, l):
        self._delay = l

    def on_stop(self):
        pass
    def active_delay(self, t):
        n_cycles = int(t / LoopingThread.ACTIVE_DELAY_PERIOD)
        if n_cycles == 0:
           n_cycles += 1 
        while n_cycles:
            if not self.isLooping():
                break
            time.sleep(LoopingThread.ACTIVE_DELAY_PERIOD)
            n_cycles -= 1
            
        
    def run(self):
        while self.isLooping():
            self._func()
            if self._delay != 0:
                self.active_delay(self._delay)
        self.on_stop()

    def __del__(self):
        self.stopLoop()
        self.join()


class GracefulTerminator:
  b_stop = False
  tread_list = []
  func_list = []

  def __init__(self):
      signal.signal(signal.SIGINT, self.exit_gracefully)
      signal.signal(signal.SIGTERM, self.exit_gracefully)

  def addThread(self, thread):
      self.tread_list += [thread]

  def addFunc(self, func):
      self.func_list += [func]

  def exit(self):
      self.exit_gracefully(0, [])

  def exit_gracefully(self, signum, frame):
      self.b_stop = True
      for t in self.tread_list:
          t.stopLoop()
          t.join()
      self.tread_list = []
      for f in self.func_list:
          f()
      self.func_list = []

  def __del__(self):
    self.exit()

  def wasStopped(self):
    return self.b_stop
