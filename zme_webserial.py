#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import platform
import logging
import time
import argparse
import traceback
from time import gmtime, strftime
from random import randint
import traceback 
import json
import threading
from common.zme_aux import * 
from zme_threads import *
#from threading import Thread, current_thread
from common.zme_serialport import Port
from serial.tools.list_ports import comports
import asyncio
import websockets

MY_VERSION = "0.1b1"


class WebSerialService:
    LOGGING_MODE_VERBOSE = 0
    LOGGING_MODE_SHORT = 1
    LOGGING_MODE_OFF = 2

    POLICY_MODE_ALL = 0
    POLICY_MODE_WHITELIST = 1
    POLICY_MODE_BLACKLIST = 2
    
    def __init__(self, ip_addr="127.0.0.1", ip_port="8998", policy = POLICY_MODE_ALL, policy_list = None, logging_mode=LOGGING_MODE_VERBOSE):
        self._ip_addr = ip_addr
        self._ip_port = int(ip_port)
        self._policy = policy
        self._policy_list = policy_list
        self._logging_mode = logging_mode
        self._poll_interval = 0.01
        self._scan_interval = 0.01
        #WebSerialHandler.setData(self)
        #self._my_lock = threading.Lock()
        self._port_metadata = {}
        self._port_data = {}
        self._uuids_table = {}
        self._http_loop = None
        self._http_thread = threading.Thread(target = self._http_run, args = (0,))
        self._serial_context = {}
        self._web_clients = {}
        self._futures = None
        self._stop_requested = False

    async def _addClientListener(self, dev, ws):
        if not (dev in self._web_clients):
            self._web_clients[dev] = set()
        if not (ws in self._web_clients[dev]):
            logging.info("Add ws:%s for:%s"%(ws, dev))
            self._web_clients[dev].add(ws)
    async def __removeWS(self, dev, ws):
        if not dev in self._web_clients:
            return
        logging.info("Remove ws%s for:%s count:%d"%(ws, dev, len(self._web_clients[dev])))
        if ws in self._web_clients[dev]:
            self._web_clients[dev].remove(ws)
            logging.info("*** Removed ws%s for:%s count:%d"%(ws, dev, len(self._web_clients[dev])))
            if len(self._web_clients[dev]) == 0:
                if dev in self._serial_context:
                    port = self._serial_context[dev]["serial"]
                    if port.isOpened():
                        port.Close()
    async def _remClientListener(self, ws, dev = None):
        if dev == None:
            for d in self._web_clients:
                await self.__removeWS(d, ws)                
        else:
            await self.__removeWS(dev, ws)   
    async def _notifyIncomingData(self):
        while True:
            try:
                i1 = 0
                while i1 < len(self._serial_context):
                    name_lst = list(self._serial_context)
                    p = name_lst[i1]
                    port = self._serial_context[p]["serial"]
                    if port.isOpened():
                        n_waiting = port.inWaiting()
                        if n_waiting > 0:
                            logging.info("Port %s opened. Incoming:%d"%(p, n_waiting))
                            data = port.Read(n_waiting)
                            message = json.dumps({"action":"incoming_stream", "params":{"buff":data}})
                            port_clients = self._web_clients[p]
                            self._log_info("--- Notify Port:%s Incoming data:%s client_list:%s"%(p, splitHexBuff(data), len(port_clients)))
                            if len(port_clients) > 0:
                                await asyncio.wait([user.send(message) for user in port_clients])
                    else:
                        await asyncio.sleep(0.05)
                    i1 += 1
                if self._stopFlag():
                    logging.info(" (!) Stopping port read task")
                    break
                await asyncio.sleep(0.01)
            except:
                zmeProcessException("_notifyIncomingData")
    def _log_info(self, text):
        if self._logging_mode != WebSerialService.LOGGING_MODE_VERBOSE:
            return
        logging.info(text)
    def _stopFlag(self):
        return self._stop_requested
    async def _scanPorts(self):
        index = 0
        while True:
            try:
                #self._log_info("--- _scanPorts poll:%s"%(index))
                for c in comports():
                    name = c.device
                    if (self._policy == WebSerialService.POLICY_MODE_WHITELIST) and (not (name in self._policy_list)):
                        continue
                    if (self._policy == WebSerialService.POLICY_MODE_BLACKLIST) and (name in self._policy_list):
                        continue
                    if not self._isPortAvaliable(name):
                        uuid = 0
                        pid = 0 
                        vid = 0
                        if c.vid != None:
                            vid = c.vid
                            pid = c.pid
                            uuid = c.serial_number
                        port_md = {"name":name, "uuid":uuid, "vid":vid, "pid":pid, "opened":False, "baud":0}
                        self._log_info("--- Serial was added:%s"%(port_md))
                        self._updatePortInfo(port_md)
                if self._stopFlag():
                    break
                await asyncio.sleep(1.0)
                index += 1
            except:
                err_text = "_scanPorts:%s"%(traceback.format_exc())
                print(err_text)
                logging.error(err_text)
    async def _serve_ws(self, websocket, path):
        try:
            logging.info("Starting socket:%s"%(websocket))
            async for message in websocket:
                logging.info("received message:%s"%(message))
                data = json.loads(message)
                if data["action"] == "info":
                    await websocket.send(json.dumps({"response":"info","info":self.info(), "done":True}))
                elif data["action"] == "open":
                    dev = None
                    if "device" in data["params"]:
                        dev = data["params"]["device"]
                    baud =  data["params"]["baudrate"]
                    bForce = False
                    b9b = False
                    if "b_force" in data["params"]:
                        bForce = data["params"]["b_force"]
                    if "b_9bit" in data["params"]:
                        b9b = data["params"]["b_9bit"]
                    res = self._openPort(dev, baud, bForce, b9b)
                    if res:
                        await self._addClientListener(dev, websocket)
                    await websocket.send(json.dumps({"response":"open", "done":res}))
                elif data["action"] == "close":
                    dev = None
                    if "device" in data["params"]:
                        dev = data["params"]["device"]
                    # Если еще кто-то слушает этот же порт - нельзя его закрывать
                    res = True
                    if (len(self._web_clients[dev])) == 1 and (websocket in self._web_clients[dev]):
                        res  = self._closePort(dev)
                    await self._remClientListener(websocket, dev)
                    await websocket.send(json.dumps({"response":"close", "done":res}))
                    break
                elif data["action"] == "write":
                    dev = None
                    if "device" in data["params"]:
                        dev = data["params"]["device"]
                    res = self._send(dev, data["params"]["buff"])
                    await websocket.send(json.dumps({"response":"write", "done":res}))
                else:
                    logging.error("unsupported action: %s", data)
            logging.info("OUT of loop socket:%s"%(websocket))
        except:
            err_text = "_serve_ws: %s"%(traceback.format_exc())
            #print(err_text)
            logging.error(err_text)
        finally:
            logging.info("Finally of socket:%s"%(websocket))
            await self._remClientListener(websocket)
    async def _run_async_tasks(self):
        async with self._ws_server:
            self._futures = [asyncio.ensure_future(self._scanPorts()), asyncio.ensure_future(self._notifyIncomingData())]
            done, pending = await asyncio.wait(self._futures, return_when=asyncio.FIRST_COMPLETED)
            for f in pending:
                f.cancel()
    def portList(self):
        l = []
        #self._my_lock.acquire()
        for p in self._port_metadata:
            l += [p]
        #self._my_lock.release()
        return l
    def _isPortAvaliable(self, name):
        res = False
        #self._my_lock.acquire()
        if name in self._port_metadata:
           res = True
        #self._my_lock.release()
        return res
    def _getPortInfoByName(self, name):
        port_data = None
        #self._my_lock.acquire()
        if name in self._port_metadata:
            port_data = dict(self._port_metadata[name])
        #self._my_lock.release()
        return port_data
    def _getPortInfoByUUID(self, uuid):
        port_name = self._getPortNameByUUID(uuid)
        if port_name == None:
            return None
        return self._getPortInfoByName(port_name)
    def _getPortNameByUUID(self, uuid):
        port_name = None
        #self._my_lock.acquire()
        if uuid in self._uuids_table:
            port_name = self._uuids_table[uuid]
        #self._my_lock.release()
        return port_name
    def _updatePortInfo(self, port_data):
        name = port_data["name"]
        #self._my_lock.acquire()
        if not (name in self._port_metadata):
            self._port_metadata[name] = dict(port_data)
            self._uuids_table[port_data["uuid"]] = name
        else:
            self._port_metadata[name] = dict(port_data)
        #self._my_lock.release()
    def _openPort(self, portname, baudrate, bForce, b9b):
        if not self._isPortAvaliable(portname):
            return False
        md = self._getPortInfoByName(portname)
        md["baud"] = baudrate
        if not (portname in self._serial_context):
            self._serial_context[portname] = {"input_buff":[], "serial":Port(portname, baudrate)}
        port = self._serial_context[portname]["serial"]
        res = False
        try:
            if port.isOpened():
                if bForce:
                    port.Close()
                else:
                    self._log_info("--- Port:%s was opened already! bForce=False"%(portname))
                    return True
            port.setBaudrate(baudrate)
            port.set9bMode(b9b)
            port.Open()
            res = port.isOpened()
            self._log_info("--- Port:%s open:%s"%(portname, res))
            
        except:
            logging.error("_openPort exception:%s"%(traceback.format_exc()))
        return res
    def _closePort(self, portname):
        if not self._isPortAvaliable(portname):
            return False
        if not (portname in self._serial_context):
            return False
        port = self._serial_context[portname]["serial"]
        res = False
        try:
            if port.isOpened():
                port.Close()
                res = port.isOpened()
                self._log_info("--- Port:%s close:%s"%(portname, res))
            else:
                self._log_info("--- (!) Tried to close port:%s that is closed already"%(portname))
        except:
            logging.error("_closePort (%s) exception:%s"%(portname, traceback.format_exc()))
        return res
    def _send(self, portname, d):
        if not self._isPortAvaliable(portname):
            return False
        if not (portname in self._serial_context):
            return False
        try:
            self._log_info("--- Write Port:%s data:%s"%(portname, splitHexBuff(d)))        
            self._serial_context[portname]["serial"].Write(d)
        except:
            logging.error("_send exception:%s"%(traceback.format_exc()))
        
        return True
    def _http_run(self, args):
        self._http_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._http_loop)
        self._ws_server = websockets.serve(self._serve_ws, self._ip_addr, self._ip_port)
        self._http_loop.run_until_complete(self._run_async_tasks())
        #self._http_loop.run_forever()
    def start(self):
        self._stop_requested = False
        self._http_thread.start()
        #self._logic_thread.start()
    def stop(self):
        #self._httpd.shutdown()
        print("Stop called")
        self._stop_requested = True
        if self._http_loop != None:
            self._http_thread.join()
    def isRunning(self):
        if self._http_loop == None:
            return False
        return self._http_loop.is_running()
    def info(self):
        ret = []
        lst = self.portList()
        for l in lst:
            ret += [self._getPortInfoByName(l)]
        return ret
    def __del__(self):
        self.stop()
if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)-8s [%(asctime)s]  %(message)s', level=logging.DEBUG,
                    filename='%s/ZMEWebSerial-%s.log' % (getScriptPath(), strftime("%Y-%m-%d", gmtime())))
    def dummyFunc(args):
        print("*** Platform: %s Version: %s ***"%(platform.system(), MY_VERSION))
    def serviceFunc(args):
        POLICYSTR = {"ALL":WebSerialService.POLICY_MODE_ALL, "WHITE_LIST":WebSerialService.POLICY_MODE_WHITELIST, "BLACK_LIST":WebSerialService.POLICY_MODE_BLACKLIST}
        policy = WebSerialService.POLICY_MODE_ALL
        lst = []
        ip_addr = "0.0.0.0"
        port = 8998
        if args.policy != None:
            if args.policy in POLICYSTR:
                policy = POLICYSTR[args.policy]
        if args.list != None:
            lst = args.list.split()
        if args.ip_address != None:
            ip_addr = args.ip_address
        if args.port != None:
            port = int(args.port, 0)
        print("Starting service...")
        svc = WebSerialService(ip_addr, port, policy, lst)
        svc.start()
        terminator = GracefulTerminator()
        terminator.addFunc(svc.stop)
        print("[OK]")
        time.sleep(1.0)
        while svc.isRunning():
            time.sleep(1.0)
    def Main():
        logging.debug("\nStarting on %s.\nARGS:%s\nVERSION:%s MD5:%s" % (platform.system(), ' '.join(sys.argv), MY_VERSION, "-"))
        parser = argparse.ArgumentParser(description='ZWave>ME WebSocket based Serial port service. \n Welcome :)')

        parser.set_defaults(func=dummyFunc)
        subparsers = parser.add_subparsers()
        
        parserSVC = subparsers.add_parser('svc', help="Starts service")
        parserSVC.add_argument('-p', '--policy', choices=["ALL", "WHITE_LIST", "BLACK_LIST"], default="ALL", help="Defines service policy. 'ALL' binds to all avaliable serial ports.")
        parserSVC.add_argument('-l', '--list', help="Set the list on filtered devices. Functionality depends on the policy selected.", default=None)
        parserSVC.add_argument('-ip', '--ip_address', help="The IP-address to which the service binds.", default="0.0.0.0")
        parserSVC.add_argument('-P', '--port', help="Port", default="8998")
        parserSVC.set_defaults(func=serviceFunc)
        args = parser.parse_args()
        args.func(args)

    Main()

    


    
