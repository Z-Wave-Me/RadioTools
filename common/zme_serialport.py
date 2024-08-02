#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import logging
import time
import serial
import traceback
import json
from common.zme_aux import * 
from serial.tools.list_ports import comports
from threading import Thread, current_thread

import asyncio
import websockets

class ZMESerialPortException(ZMEIOException):
    pass

class Port:
    read_block_size = 0x100
    port_opened = False
    @staticmethod 
    def portListByUUID(uuid, host = None):
        rl = []
        if uuid.startswith("0x"):
            uuid = uuid[2:]
        uuid = uuid.lower()
        lst = Port.portList(host)
        for l in lst:
            u = l["uuid"]
            if isinstance(u,int):
                u = "%x"%(u)
            if u.lower() == uuid:
                rl += [l["name"]]
        rl.sort() 
        return rl
    @staticmethod 
    def _portNameByUUID(pn_or_uuid, host = None):
        if pn_or_uuid.startswith("0x"):
            lst = Port.portListByUUID(pn_or_uuid[2:].lower(), host)
            if len(lst) < 1:
                return None
            return lst[0]
        return pn_or_uuid
    @staticmethod
    def portNameFromAlias(alias, host=None):
        ni = 0
        index = alias.find("#")
        if index != -1:
            ni = int(alias[index+1:],0)
            alias = alias[:index]   
        if alias.startswith("vidpid:"):
            vp = int(alias[7:], 0)
            l = Port.portList(host, vp)
            name_lst = []
            for e in l:
                name_lst += [e["name"]]
            name_lst.sort()
            if len(name_lst) <= ni:
                return None
            return name_lst[ni]
        if alias.startswith("uuid:"):
            l = Port.portListByUUID(alias[5:].lower(), host)
            if len(l) <= ni:
                return None
            return l[ni]
        return alias


    @staticmethod
    def _extractWebSerialAddr(portname):
        parts = portname.split("@")
        if len(parts) < 2:
            return Port.portNameFromAlias(portname), None
        return Port.portNameFromAlias(parts[0], parts[1]),parts[1]
     
    def __init__(self, portname, baudrate = 115200, bEmulate9b = False, bRaiseEx = False, dtr = True):
        device_name, host =  Port._extractWebSerialAddr(portname)
        logging.debug("Port: Init serial:%s baud:%d"%(device_name, baudrate))
        self._dev_name  = device_name
        self._host = host
        self._baudrate = baudrate
        self._next_read_pos = 0
        self._resp_timeout = 2.0
        self._raise_exception = bRaiseEx
        self._b9b = bEmulate9b
        self._ws_thread = None
        if self._host == None:
            self._ser = serial.Serial()
            self._ser.dtr = dtr
            self._ser.port = self._dev_name
            self._ser.baudrate = baudrate
            self._ser.parity = serial.PARITY_NONE
            if bEmulate9b:
                self._ser.parity = serial.PARITY_EVEN
            self._ser.rtscts = False
            self._ser.xonxoff = False
            self._ser.timeout = 1  # required so that the reader thread can exit
        else:
            self._stop_flag = False
            self._soc = None
            self._ser = None
            zmeSyncEventLoop()
            self._input_buff = []
            self._request_buff = []
            self._resp_buff = []
            self._input_lock = asyncio.Lock()
            self._request_lock = asyncio.Lock()
            self._reponse_lock = asyncio.Lock()

        self._timeout = 3.0 
        self._slow_serial = False#(platform.system() == "Darwin")
        self._forced_fast = False
        self._port_opened = False
    def setNetworkResponseTimeout(self, resp_timeout):
        self._resp_timeout = resp_timeout
    def set9bMode(self, mode):
        self._b9b = mode
        self._ser.parity = serial.PARITY_NONE
        if self._b9b:
            self._ser.parity = serial.PARITY_EVEN
    def setBaudrate(self, baud):
        self._baudrate = baud
        if self._host == None:
            self._ser.baudrate = baud
    async def _translateRequests(self):
        while True:
            try:
                if self._soc != None:
                    req = await zmeAsyncPopFromBuff(self._request_lock, self._request_buff)
                    if req != None:
                        logging.info("SOCK.SEND(%s, %s):%s"%(self._dev_name, self._host, req))
                        await self._soc.send(req)
                    if self._stop_flag:
                        logging.info("SOCK.CLOSE(%s, %s)"%(self._dev_name, self._host))
                        await self._soc.close()
                        self._soc = None
                        break
                else:
                    if self._stop_flag:
                        break     
                await asyncio.sleep(0.01)
            except:
                logging.error("_translateRequests (%s, %s):%s"%(self._dev_name, self._host, traceback.format_exc()))
                break
        logging.info("Translate requests stopped!")
    async def _process_async_tasks(self):
        self._futures = [asyncio.ensure_future(self._process_websock()), asyncio.ensure_future(self._translateRequests())]
        done, pending = await asyncio.wait(self._futures, return_when=asyncio.ALL_COMPLETED)
        #print("--- OUT OF WAIT. pending:%d"%(len(pending)))
        '''
        for f in pending:
            print("---Cancel:%s"%(f))
            f.cancel()
            time.sleep(0.1)
            print("---WAIT")
        '''        
    async def _process_websock(self):
        uri = "ws://"+self._host
        logging.info("connecting to service:%s"%(uri))
        try:
            async with websockets.connect(uri) as websocket:
                self._soc = websocket
                logging.info("connected to websocket service:%s"%(self._soc))
                async for message in websocket:
                    #logging.info("SOCK.RECV(%s, %s):%s"%(self._dev_name, self._host, message))
                    data = json.loads(message)
                    if "response" in data:
                        await zmeAsyncPushToBuff(self._reponse_lock, self._resp_buff, [data])
                    if "action" in data:
                        await zmeAsyncPushToBuff(self._input_lock, self._input_buff, data["params"]["buff"])
                #print("STOP _process_websock")
                #return
                #await self._soc.close()
                self._soc = None
        except:
            logging.error("_process_websock (%s, %s):%s"%(self._dev_name, self._host, traceback.format_exc()))
            return
        
    def __send_ws_request(self, type, params):
        timeout = time.time() + 3.0
        while time.time() < timeout:
            if self._soc != None:
                break
            #print("Waiting for SOC")
            time.sleep(0.1)
        if self._soc != None:
            try:
                zmeSyncClearBuff(self._reponse_lock, self._resp_buff)
                req_text =  json.dumps({"action":type, "params":params})
                logging.info("sending request:%s"%(req_text))
                zmeSyncPushToBuff(self._request_lock, self._request_buff, [req_text])
                resp  = zmeSyncPopFromBuff(self._reponse_lock, self._resp_buff, 1, self._resp_timeout)
                if resp == None:
                    logging.error("NO response for request:%s (Timeout:%3.2f)"%(req_text, self._resp_timeout))
                    return False, None
                resp = resp[0]
                return resp["done"], resp
            except:
                logging.error("Port.__send_ws_request (%s, %s)  exception:%s"%(self._dev_name, self._host, traceback.format_exc()))
        return False, None

    def _createWSThread(self):
        if self._ws_thread == None:
            self._stop_flag = False
            self._event_loop  = asyncio.new_event_loop()
            self._ws_thread = Thread(target = self._ws_loop)
            self._ws_thread.start()
            logging.info("Started thread for (%s %s)"%(self._dev_name, self._host))
    def _stopWSThread(self):
        if self._ws_thread != None:
            self._stop_flag = True
            self._ws_thread.join()
            self._ws_thread = None
    def _ws_loop(self):
        asyncio.set_event_loop(self._event_loop)
        self._event_loop.run_until_complete(self._process_async_tasks())
        self._event_loop.stop()
        #print("---LOOP COMPLETE!")
        logging.info("loop completed (%s, %s)"%(self._dev_name, self._host))
        #self._ws_thread = None
    def setReadTimeout(self, val):
        if self._ser != None:
            self._ser.timeout = val
        self._timeout = val
    def getReadTimeout(self):
        return self._timeout
    def NOS(self):
        self._forced_fast = True
    
    def Open(self, bForce=False):
        self._port_opened = False
        if self._dev_name == None:
            #if self._raise_exception:
            #    raise ZMESerialPortException("Port is not open")
            return False
        try:
            if self._host == None:
                self._ser.open()
                self._port_opened = True
                #logging.
            else:
                self._createWSThread()
                #print("*** OPEN REQUEST:%s"%(self._dev_name))
                ok, data = self.__send_ws_request("open",{"device":self._dev_name, "baudrate":self._baudrate, "b_force":bForce, "b_9bit":self._b9b})
                #print("*** PORT OPEN:%s"%(ok))
                self._port_opened = ok
                if not ok:
                    self.Close(True, True)
        except Exception:
            self._port_opened = False
            zmeProcessException("Port.Open")
            self._stopWSThread()
            if self._raise_exception:
                raise ZMESerialPortException("Can't open port") from None
        return self._port_opened
    def isOpened(self):
        if self._host == None:
            return self._port_opened
        else:
            if self._soc == None:
                return False
            return self._port_opened
    def Write(self, buf):
        exception_rised = False
        if not self.isOpened():
            if self._raise_exception:
                raise ZMESerialPortException("Port is not open") from None
            return False
        try:
            logging.info("SerialPort.Write(%s):%s"%(self._dev_name, splitHexBuff(buf)))
            if self._host == None:
                self._ser.write(buf)
                return True
            else:
                buf = list(buf)
                ok, data = self.__send_ws_request("write",{"device":self._dev_name, "buff":buf})
                self._checkSockStatus()
                return ok
        except:
            zmeProcessException("Port.Write")
            #logging.error("Could not write to serial port %s: Unknown error: %s. Trace:%s" % (self._dev_name, e1, traceback.format_exc()))
            if self._raise_exception:
                raise ZMESerialPortException("Write") from None
    def Flush(self):
        if(self._ser != None):
            self._ser.flush()      
    def _checkSockStatus(self):
        if self._soc == None:
            if self._raise_exception:
                raise ZMESerialPortException("Sock closed")
    def Read(self, size, timeout = 3.0):
        if size == 0:
            return []
        exception_rised = False
        if not self.isOpened():
            if self._raise_exception:
                raise ZMESerialPortException("Port is not open")
            return []
        try:
            readed_data = []
            if self._host == None: 
                sub_data = self._ser.read(size)
                for c in sub_data:
                    readed_data += [c]
            else:
                tm = self._timeout
                #if tm < self._resp_timeout:
                #    tm = self._resp_timeout
                #print("REQ:%d Input buff:%s"%(size, splitHexBuff(self._input_buff)))
                d = zmeSyncPopFromBuff(self._input_lock, self._input_buff, size, tm)
                #print("Returned:%s"%(splitHexBuff(d)))
                self._checkSockStatus()
                if d != None:
                    readed_data = d
                else:
                    logging.info("timeout read from port:%s"%(self._dev_name))
            logging.info("SerialPort.Read(%s):%s"%(self._dev_name, splitHexBuff(readed_data)))
            return  readed_data
        except:
            zmeProcessException("Port.Read")
            #logging.error("Could not read from serial port %s: Unknown error: %s. Trace:%s" % (self._dev_name, e1, traceback.format_exc()))
            if self._raise_exception:
                raise ZMESerialPortException("Read") from None
       
        return []

    def inWaiting(self):
        exception_rised = False
        if not self.isOpened():
            if self._raise_exception:
                raise ZMESerialPortException("Port is not open")
            return 0
        try:
            if self._host == None:
                return self._ser.inWaiting()
            else:
                res  = zmeSyncBuffSize(self._input_lock, self._input_buff)
                self._checkSockStatus()
                if res == None:
                    return 0
                return res
        except:
            zmeProcessException("Port.inWaiting")
            if self._raise_exception:
                raise ZMESerialPortException("inWaiting") from None
        return 0    

    def Close(self, b_silent = False, b_close_conn = True):
        exception_rised = False
        try:
            if self._host == None:
                self._ser.close()
                self._port_opened = False
            else:
                if self._ws_thread == None:
                    return
                if self._port_opened and (self._soc != None):
                   ok, data = self.__send_ws_request("close",{"device":self._dev_name})
                   if ok:
                       self._port_opened = False
                #if not self._stop_flag:
                self._stopWSThread()
            if not b_silent:
                logging.info("Port %s has been closed!"%(self._dev_name))
        except Exception as e1:
            if not b_silent:
                zmeProcessException("Port.inWaiting")
            if self._raise_exception:
                raise ZMESerialPortException("Close") from None
                #logging.error("Port.Close:: port %s: Unknown error: %s. Trace:%s" % (self._dev_name, e1, traceback.format_exc()))

    @staticmethod
    def __extractSerialMD(c):
        vid = 0
        pid = 0
        ser = "-"
        descr = ""
        if c.vid != None:
            vid = c.vid
            pid = c.pid
            ser = c.serial_number
            descr = c.description
        #print("**SR:%s"%(ser))
        return {"vid":vid, "pid":pid, "uuid":ser, "name":c.device, "description":descr}

    @staticmethod
    async def __async_extractHostInfo(host):
        uri = "ws://"+host
        info = None
        try:
            async with websockets.connect(uri) as websocket:
                await websocket.send(json.dumps({"action":"info"}))
                resp = await websocket.recv()
                if resp == None:
                    return None
                data = json.loads(resp)
                if not "info" in data:
                    return None
                await websocket.close()
                logging.info("Port metadata for host:%s MD:%s"%(host, data))
                return data["info"]
        except:
            logging.error("WS Connection Error:%s"%(traceback.format_exc()))
            return None
    @staticmethod
    def __extractHostInfo(host):
        loop = zmeSyncEventLoop()
        return loop.run_until_complete(Port.__async_extractHostInfo(host))
    @staticmethod
    def portMetadata(porturl):
        if len(porturl.strip()) == 0:
            return None
        try:
            name,host = Port._extractWebSerialAddr(porturl)
            #print("name:%s host:%s"%(name,host))
            if host == None:
                for c in comports():
                    if c.device == name:
                        return Port.__extractSerialMD(c)
            else:
                md = Port.__extractHostInfo(host)
                if md != None:
                    for p in md:
                        if p["name"] == name:
                            return p
            return None
        except:
            logging.error("Port.portMetadata exception for port:%s Trace:%s"%(porturl, traceback.format_exc()))
    @staticmethod
    def portList(host=None, vidpid_filter = None):
        md = []
        if host == None:
            for c in comports():
                p = Port.__extractSerialMD(c)
                if vidpid_filter != None:
                    vid_pid = (p["vid"] << 16) | (p["pid"])
                    if vid_pid != vidpid_filter:
                        continue
                md += [p]
        else:
            md_ext = Port.__extractHostInfo(host)
            #print("MD_EX:%s"%(md_ext))
            if md_ext == None:
                md_ext = []
            if vidpid_filter == None:
                md  = md_ext
            else:
                for p in md_ext:
                    vid_pid = (p["vid"] << 16) | (p["pid"])
                    if vid_pid != vidpid_filter:
                        continue
                    md += [p]
        return md
    @staticmethod 
    def portByUUID(uuid, host=None):
        if not uuid.startswith("0x"):
            uuid = "0x"+uuid
        return Port._portNameByUUID(uuid, host)

    def __del__(self):
        #print("DESTRUCTOR")
        self._raise_exception = False
        self.Close(True, True)
if __name__ == "__main__":
    
    host = None
    if len(sys.argv) > 1:
        host = sys.argv[1]
    print("%s [PORTS HOST:%s] %s"%("-"*40, host, "-"*40))
    lst = Port.portList(host)
    print("%-38s %-8s %-8s %-50s"%("UUID", "VID", "PID", "NAME"))
    for l in lst:
        print("%-38s %-8s %-8s %-50s"%(l["uuid"], l["vid"], l["pid"], l["name"]))