from pickle import NONE
import time
from common.zme_aux import *
from common.zme_serialport import Port
from common.zme_serialport import ZMESerialPortException
from zme_threads import *
from common.zme_sapi import *

from zwave.zme_zwave_protocol import *
from zme_razberryapi import *

class ZMEModemListener(LoopingThread):
    MODE_START = 0
    MODE_INITED = 1
    MODE_NOT_CONNECTED = 3
    MODE_DISCONNECT = 4
    MODE_CHECK = 5
    MODE_APPLY_LICENSE = 5
    MODE_NOT_SUPPORTED = 11
    MODE_STOPPED = 10
    MODE_WAIT_TEST = 12
    MODE_NOT_OPEN_PORT = 13
    MODE_NOT_SUPPORTED_LICENSE = 14
    MODE_IDLED = 15

    REGION_MAP = {
                    0x00:["EU", [100000, 40000, 9600], 0],
                    0x01:["US", [100000, 40000, 9600], 3],
                    0x02:["ANZ", [100000, 40000, 9600], 4],
                    0x03:["HK", [100000, 40000, 9600], 5],
                    0x04:["MY", [100000, 40000, 9600], 10],
                    0x05:["IN", [100000, 40000, 9600], 2],
                    0x06:["IL", [100000, 40000, 9600], 9],
                    0x07:["RU", [100000, 40000, 9600], 1],
                    0x08:["CN", [100000, 40000, 9600], 6],
                    0x09:["US_LR1", [100000, 40000, 9600, 100000], 17],
                    0x0A:["US_LR2", [100000, 40000, 9600, 100000], 18],
                    0x20:["JP", [100000, 100000, 100000], 7],
                    0x21:["KR", [100000, 100000, 100000], 8]
                }
    

    def __init__(self, port_name, payload_encoder, rx_handler = None, baud_rate = 230400, state_handler = None, dev_type = None):
        self._port_name = port_name
        self._dev_type = dev_type
        self._baud = baud_rate
        self._start_baud = baud_rate
        self._is_zuno = False
        self._payload_parse_enabled = True
        
        self._stat_lock = Lock()
        self._rx_pkg_lock = Lock()
        self._rx_pkg_list = []
        self._tx_pkg_lock = Lock()
        self._tx_pkg_list = []
        self._rx_handler = rx_handler
        self._state_handler = state_handler
        self._mode = ZMEModemListener.MODE_STOPPED
        self._sapi = None
        self._user_data = None
        self._board_info = None
        self._board_supported = False
        self._region = 0
        self._power  = 10
        self._new_lic = 0
        self._state_timeout = 0
        self._current_region = 0
        self._zw_parser = None
        if payload_encoder != None:
            self._zw_parser = ZWaveTransportEncoder(payload_encoder)
        self._index = 0
        self._retry_count = 100
        self._tx_loop_back = True
        LoopingThread.__init__(self, self._receiverFunc)
    def setPayloadParseFlag(self, bEnabled):
        self._payload_parse_enabled = bEnabled
    def setTxLoopBack(self, enable=True):
        self._tx_loop_back = enable
    def setPayloadEncoder(self, encoder):
        self._zw_parser = ZWaveTransportEncoder(encoder)
    def setUserData(self, d):
        self._user_data = d
    def sendMessage(self, p):
        self._tx_pkg_lock.acquire()
        self._tx_pkg_list += [[0, p]]
        self._tx_pkg_lock.release()
    def setHomeIdFilters(self, homeids = None):
        filter_set = [0x00]*4*4
        if homeids != None:
            filter_set = []
            for h in  homeids:
                filter_set += zme_int_toarr(h, 4, bInv=True)
            if len(filter_set) < 16:
                filter_set += [0x00]*(16-len(filter_set))
        self._tx_pkg_lock.acquire()
        self._tx_pkg_list += [[1, filter_set]]
        self._tx_pkg_lock.release()

    def popRxMessage(self):
        p = None
        self._rx_pkg_lock.acquire()
        if len(self._rx_pkg_list) > 0:
            p = self._rx_pkg_list[0]
            del self._rx_pkg_list[0]
        self._rx_pkg_lock.release()
        return p
    def connect(self, region, power, test_mode = None, test_mode_channel =0 , test_mode_timeout = 1000):
        if isinstance(region, str):
            self._region = 0
            if region in FREQ_TABLE_U7:
                self._region = FREQ_TABLE_U7[region]
        else:
            self._region = region
        self._power  = power
        self._retry_count = 0
        self._test_mode = test_mode
        self._test_mode_timeout = test_mode_timeout
        self._test_channel = test_mode_channel
        self._setState(ZMEModemListener.MODE_START)
    def disconnect(self):
        if self.getState() == ZMEModemListener.MODE_INITED:
            self._setState(ZMEModemListener.MODE_DISCONNECT)
    def check(self):
        if self.getState() == ZMEModemListener.MODE_STOPPED:
            self._setState(ZMEModemListener.MODE_CHECK)
            return True
        return False
    def setupLicense(self, lic_packet):
        self._new_lic = lic_packet
        self._setState(ZMEModemListener.MODE_APPLY_LICENSE)
    def getBoardInfo(self):
        brdi = None
        self._stat_lock.acquire()
        if self._board_info != None:
            brdi = dict(self._board_info)
        self._stat_lock.release()
        return brdi
    # ----------------------------------------------------------
    def getState(self):
        c = 0
        self._stat_lock.acquire()
        c = self._mode
        self._stat_lock.release()
        return c
    def _setState(self, v):
        prev_state = self._mode
        self._stat_lock.acquire()
        self._mode = v
        self._stat_lock.release()
        if (prev_state != v) and (self._state_handler != None):
            handler = self._state_handler
            handler(self._user_data, v, self._board_info)
    def _popTxMessage(self):
        p = None
        self._tx_pkg_lock.acquire()
        if len(self._tx_pkg_list) > 0:
            p = self._tx_pkg_list[0]
            del self._tx_pkg_list[0]
        self._tx_pkg_lock.release()
        return p
    def _addRxPckg(self, p):
        self._rx_pkg_lock.acquire()
        self._rx_pkg_list += [p]
        self._rx_pkg_lock.release()
    def _pushRxPckg(self, p):
        if self._rx_handler != None:
            self._rx_handler(self._user_data, p)
        else:
            self._addRxPckg(p)

    def _setTimeout(self, value):
        self._stat_lock.acquire()
        self._state_timeout = time.time() + value
        logging.debug("State timeout:%f"%(self._state_timeout))
        self._stat_lock.release()
    def _getRemainTimeout(self):
        val = 0
        self._stat_lock.acquire()
        val = self._state_timeout
        self._stat_lock.release()
        remains = val - time.time()
        logging.debug("Remains:%f"%(remains))
        return (remains)

    def _tryBoard(self, license_check = False):
        self._stat_lock.acquire()
        self._board_info = None
        md = None
        self._stat_lock.release()
        self._sapi = SerialAPIUtilities(self._port_name, self._baud)
        self._sapi.setPortExPolicy(True)
        mode = self._dev_type
        if mode == None:
            mode = SerialAPIUtilities.DETECT_MODE_AUTO
        res,prod_md = self._sapi.extractProductInfo(mode, self._baud)
        if (res == 0):
            #self._baud = prod_md["uart_baudrate"]
            if (prod_md["product_type"] == "Z-Uno"):
                self._is_zuno = True
                self._dev_type = SerialAPIUtilities.DETECT_MODE_ZUNO
                result, md = self._sapi.readBoardInfo(bSync=False,bClose=False, custom_baud=self._baud)
                if result != 0:
                    self._sapi.closePort(True)
                    return False
                md["uart_baudrate"] = self._baud
                if license_check:
                    md["supported"] = False
                    logging.debug("MD:%s"%(md))
                    if "lic_flags" in md:
                        # Поддерживается ли режим модема
                        if md["lic_flags"] & (1 << ZUNO_LIC_FLAGS_NAMES["MODEM"]["bit"]):
                            md["supported"] = True
                        # Можно ли извлечь ключи сети
                        if md["lic_flags"] & (1 << ZUNO_LIC_FLAGS_NAMES["KEY_DUMP"]["bit"]):
                            keys_data = self._sapi.cmdinterface.readNVM(0xFFCCC0, 0x40)
                            keys_data = keys_data[4:]
                            md["s2_keys"] = {"S2UnAuth":keys_data[:0x10], "S2Auth":keys_data[0x10:0x20], "S2Access":keys_data[0x20:0x30], "S0":keys_data[0x30:0x40]}
                else:
                    md["supported"] = True
            elif  (prod_md["product_type"] == "SAPI"):
                self._dev_type = SerialAPIUtilities.DETECT_MODE_SAPI
                #self._sapi.closePort(True)
                zsapi = RazberrySAPICmd(self._port_name)
                zsapi.bindToExistedInterface(self._sapi.cmdinterface)
                if 1: #zsapi.port.Open():
                    #sync = zsapi.syncWithController(10.0)
                    #if not sync:
                    #    return False
                    md = zsapi.getBoardInfo()
                    md["uart_baudrate"] = self._baud
                    logging.debug("MD:%s"%(md))
                    if license_check:
                        lic = zsapi.getLicense()
                        if lic["status"] == RazberrySAPICmd.ZME_LIC_STATUS_OK:
                            parsed_lic = RazberryLicense(lic["license"][2:2+32])
                            md["license"] = parsed_lic.getMetadata()
                            md["supported"] = False
                            if "MODEM" in md["license"]["flags"]:
                                md["supported"] = True
                    else:
                        md["supported"] = True
                    #zsapi.port.Close()
                    #self._sapi.openPort(True)
        else:
            return False
        if md == None:
            return False
        md.update(prod_md)
        self._stat_lock.acquire()
        self._board_info = md
        self._stat_lock.release()
        return md["supported"]
    def getDevType(self):
        return self._dev_type
    @staticmethod
    def _convert1ByteFloat(b, coef):
        if b > 127:
            b -= 256
        b *= coef
        return b
    def makeTXProtocolMD(self, d):
        md = {}
        md["ts"] = time.time()
        md["index"] = self._index
        md["channeli"] = d[0]
        md["rssi"] = 0
        md["freqi"] = self._region
        md["freq"] = "UNKN"
        md["speed"] = 0
        md["dir"] = 2
        if md["freqi"] in ZMEModemListener.REGION_MAP:
            fi = md["freqi"]
            freq = ZMEModemListener.REGION_MAP[fi]
            md["freq"] = freq[0]
            if(len(freq[1]) > md["channeli"]):
                md["speed"] = freq[1][md["channeli"]]
            else:
                md["speed"] = 0
        pkg = None
        if self._zw_parser != None:
            pkg = self._zw_parser.decode(d[1:], b_fullspeed=(md["speed"]==100000))
        if pkg == None:
            md["raw"] = d[1:]
            return md
        md.update(pkg)
        self._index += 1
        return md
    def decodeModemProtocol(self, d):
        md = {}
        if len(d) < 8:
            return None
        #print("RAW:%s"%(d))
        md["ts"] = time.time()
        md["index"] = self._index
        md["channeli"] = d[0]
        md["rssi"] = ZMEModemListener._convert1ByteFloat(d[1], 1.0)
        md["freqi"] = self._region
        md["freq"] = "UNKN"
        md["dir"] = 1
        md["speed"] = 0
        if md["freqi"] in ZMEModemListener.REGION_MAP:
            fi = md["freqi"]
            freq = ZMEModemListener.REGION_MAP[fi]
            md["freq"] = freq[0]
            if(len(freq[1]) > md["channeli"]):
                md["speed"] = freq[1][md["channeli"]]
            else:
                md["speed"] = 0
        payload = d[2:]
        if md["speed"] == 100000:
            crc = calcSigmaCRC16(0x1D0F, payload, 0, len(payload))
            d += bytearray([crc >> 8, crc & 0xFF])
        else:
            crc= Checksum(payload)
            d += bytearray([crc])
        pkg = {}
        if self._zw_parser != None:
            md["freq"] = self._zw_parser.decodeFreq(md["freq"], md["channeli"])
            #print("Parsing PKG:%s"%(splitHexBuff(d[2:])))
            pkg = self._zw_parser.decode_new_version(d[2:], md["speed"], md["ts"], md["freq"], md["channeli"], False, self._payload_parse_enabled)
            if pkg == None:
                print("--NO PKG--")
                md["raw"] = d
                return md
        else:
            md["raw"] = d
        pkg.update(md)
        self._index += 1
        return pkg
    def on_stop(self):
        self.disconnect()
        self._receiverFunc()

    def _receiverFunc_disconnect(self):
            try:
                logging.info("ZMEModemListener.Disconnect")
                self._sapi.cmdinterface.softReset()
                self._sapi.closePort(True)
                self._sapi = None
            except:
                logging.error("ZMEModemListener.Disconnect exception:%s"%(traceback.format_exc()))
            self._setState(ZMEModemListener.MODE_STOPPED)

    def _sendWaitingTxMessage(self):
        p = self._popTxMessage()
        if p != None:
            if p[0] == 0:
                self._sapi.cmdinterface.writeNVM(0xABCD00, p[1])
                if self._tx_loop_back:
                    pkg = self.makeTXProtocolMD(p[1])
                    self._pushRxPckg(pkg)
            elif p[0] == 1:
                self._sapi.cmdinterface.writeNVM(0xABCF01, p[1])
    def _receiverFunc(self):
        state = self.getState()
        if state == ZMEModemListener.MODE_START:
            try:
                if self._sapi != None:
                    self._sapi.cmdinterface.softReset()
                    self._sapi.closePort(True)
                    self._sapi.setLastStatusOpened(False)
                if self._tryBoard(True):
                    uubaud = 0
                    if self._is_zuno:
                        uubaud = self._start_baud
                    if self._test_mode != None:
                        if self._sapi.startRailTest(self._test_mode, self._region, self._test_channel, self._power, self._test_mode_timeout, False):
                            self._setState(ZMEModemListener.MODE_WAIT_TEST)
                            self._setTimeout(self._test_mode_timeout/1000.0)
                    elif self._sapi.startRailTest(SerialAPIUtilities.RAIL_MODE_MODEM, self._region, 0, self._power, 10000, False, uubaud):
                        self._setState(ZMEModemListener.MODE_INITED)
                    else:
                        self._setState(ZMEModemListener.MODE_NOT_CONNECTED)
                        self._setTimeout(10.0)
                else:
                    if self._sapi == None:
                        self._setState(ZMEModemListener.MODE_NOT_OPEN_PORT)
                    else:
                        if self._sapi.getLastStatusOpened() == True:
                            if self._board_info != None:
                                self._setState(ZMEModemListener.MODE_NOT_SUPPORTED_LICENSE)
                            else:
                                self._setState(ZMEModemListener.MODE_NOT_SUPPORTED)
                        else:
                            self._setState(ZMEModemListener.MODE_NOT_OPEN_PORT)
            except Exception as e:
                zmeProcessException("ModemHost start")
                self._setState(ZMEModemListener.MODE_DISCONNECT)
                #self._setTimeout(10.0)
        elif state == ZMEModemListener.MODE_INITED:
            try:
                #logging.info("MODEMHOST>LOOP")
                n_waiting = self._sapi.cmdinterface.port.inWaiting()
                if n_waiting == 0:
                    #logging.info("MODEMHOST>CANSEND")
                    self._sendWaitingTxMessage()
                    if (self._state_handler != None):
                        self._state_handler(self._user_data, ZMEModemListener.MODE_IDLED, None)
                else:
                    self._sapi.cmdinterface.setRcvSofTimeout(0.0005)
                    logging.info("RCV PKG RMS:%d"%(n_waiting))
                    incoming = self._sapi.cmdinterface.recvIncomingRequest()
                    #print("MODEM Incoming :%s"%(splitHexBuff(incoming)))
                    if incoming[0] == self._sapi.cmdinterface.RECV_OK:
                        if (incoming[3] == 0x2A) and (incoming[4] == 0x0):
                            pkg = self.decodeModemProtocol(incoming[5:])
                            if pkg != None:
                                self._pushRxPckg(pkg)
                        #self._sendWaitingTxMessage()
            except ZMESerialPortException:
                zmeProcessException("ModemHost.PortException")
                self._setState(ZMEModemListener.MODE_DISCONNECT)
            except Exception as e:
                zmeProcessException("ModemHost.AnotherException")
                logging.error("ZMEModemListener exception:%s"%(traceback.format_exc()))
                #self._setState(ZMEModemListener.MODE_DISCONNECT)
        elif state == ZMEModemListener.MODE_WAIT_TEST:
            if self._getRemainTimeout() < 0:
                self._sapi.closePort(True)
                self._sapi = None
                self._setState(ZMEModemListener.MODE_STOPPED)
        elif state == ZMEModemListener.MODE_NOT_CONNECTED:
            if self._retry_count < 1:
                self._setState(ZMEModemListener.MODE_STOPPED)
            elif self._getRemainTimeout() < 0:
                self._retry_count -= 1
                self._setState(ZMEModemListener.MODE_START)
        elif state == ZMEModemListener.MODE_DISCONNECT:
           self._receiverFunc_disconnect()
        elif state == ZMEModemListener.MODE_NOT_SUPPORTED:
            logging.info("ZMEModemListener.This device is not supported!")
            self._receiverFunc_disconnect()
            self._setState(ZMEModemListener.MODE_STOPPED)
        elif state == ZMEModemListener.MODE_NOT_OPEN_PORT:
            logging.info("ZMEModemListener.Failed to open port!")
            self._receiverFunc_disconnect()
        elif state == ZMEModemListener.MODE_NOT_SUPPORTED_LICENSE:
            logging.info("ZMEModemListener.This device is not licensed for MODEM!")
            self._receiverFunc_disconnect()

if __name__ == "__main__":
    MY_VERSION = "01b1"
    import zme_pticlient
    import zme_razberryapi
    logging.basicConfig(format='%(levelname)-8s [%(asctime)s]  %(message)s', level=logging.DEBUG,
                    filename='%s/ZMEModemClient-%s.log' % (getScriptPath(), strftime("%Y-%m-%d", gmtime())))

    def dummyFunc(args):
        print("*** Platform: %s Version: %s ***"%(platform.system(), MY_VERSION))
    def modemRXHandler(param, pkg):
        
        logging.info("*** PKG%s"%(pkg))
        txt = zme_pticlient.ZWPKGParser.formatPackage(pkg)
        logging.info("*** TEXT%s"%(txt))
        print(txt)
    def modemFunc(args):
        print("*** Modem Client ****")
        profile = args.profile
        sc_path =  baseDirectoryPath(os.path.abspath(__file__))
        if (args.profile == None) or (len(args.profile) == 0):
            profile = sc_path + os.sep + "zme_zwave_profile.json"
        print("Z-Wave profile:%s"%(profile))
        modem = ZMEModemListener(args.device, ZWaveDataEncoder(profile), modemRXHandler)
        terminator = GracefulTerminator()
        terminator.addThread(modem)
        modem.start()
        modem.connect(args.freq, int(args.power,0))
        print("waiting for modem...")
        time.sleep(10.0)
        brd_info = modem.getBoardInfo()
        if brd_info == None:
            print("Error:Can't connect to modem!")
            terminator.exit()
            return
        print(" --- DEVICE BOARD INFORMATION ---")
        print(" BOARD TYPE: %s"%(brd_info["product_type"]))
        if brd_info["product_type"] == "Z-Uno":
            printBoardInfo(brd_info)
        elif brd_info["product_type"] == "SAPI":
            zme_razberryapi.printRazberryBoardInfo(brd_info)
        if not brd_info["supported"]:
                print("Error:Your device doesn't support modem mode! Please purchase the license! ")
                terminator.exit()
                return
        if args.send_data != None:
            for i in range(10):
                modem.sendMessage(formatHexInput(args.send_data))
        lc = 0
        while not terminator.wasStopped():
            lc += 1
            time.sleep(0.1)


    def Main():
        logging.debug("\nStarting on %s.\nARGS:%s\nVERSION:%s MD5:%s" % (platform.system(), ' '.join(sys.argv), MY_VERSION, "-"))
        parser = argparse.ArgumentParser(description='ZWave>ME PTI Tracer tool for 7th generation. \n Welcome :)')

        parser.set_defaults(func=dummyFunc)
        subparsers = parser.add_subparsers()

        parserModem = subparsers.add_parser('modem', help="Starts simplified client for Z-Uno modem interface")
        parserModem.add_argument('-d', '--device', help="Device file (UNIX) or COM-port (WINDOWS)")
        parserModem.add_argument('-b', '--baudrate', help="Device's baudrate.", default="230400")
        parserModem.add_argument('-p', '--profile', default="", help="JSON file with Z-Wave protocol descriptions.")
        parserModem.add_argument('-s', '--send_data', help="Sends data using Z-Uno")
        parserModem.add_argument('-fr', '--freq', choices=['EU', 'RU', 'US', 'IN', 'HK', 'CN', 'JP', 'IL', 'MY', 'ANZ'], default="RU", help="Frequency")
        parserModem.add_argument('-pow', '--power', default="10", help="Power of AMP in 10th of dBms")
        
        parserModem.set_defaults(func=modemFunc)

        args = parser.parse_args()
        args.func(args)

    Main()


