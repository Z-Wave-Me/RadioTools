import time
from zme_threads import *
from common.zme_aux import *
from common.zme_serialport import ZMESerialPortException, Port
import argparse
import colorama
from colorama import Fore, Back, Style




class ZWPKGParser:
    RSSI_SHIFT = -50
    
    TYPE_MAP = {0x01:"SINGL", 0x02:"MULTI", 0x03:"ACK", 0x04:"FLOOD", 0x05:"EXPLR"}
    REGION_MAP = {
                    0x00:["DEF", [100000, 40000, 9600], -1],
                    0x01:["EU", [100000, 40000, 9600], -1],
                    0x02:["US", [100000, 40000, 9600], -1],
                    0x03:["ANZ", [100000, 40000, 9600], -1],
                    0x04:["HK", [100000, 40000, 9600], -1],
                    0x05:["MY", [100000, 40000, 9600], -1],
                    0x06:["IN", [100000, 40000, 9600], -1],
                    0x07:["JP", [100000, 100000, 100000], -1],
                    0x08:["RU", [100000, 40000, 9600], -1],
                    0x09:["IL", [100000, 40000, 9600], -1],
                    0x0A:["KR", [100000, 100000, 100000], -1],
                    0x0B:["CN", [100000, 40000, 9600], -1],
                    0x0C:["US_LR1", [100000, 40000, 9600, 100000], 0],
                    0x0D:["US_LR2", [100000, 40000, 9600, 100000], 0],
                    0x0E:["US_LR_ED", [100000, 100000], 0]
                }
    
    def __init__(self, payload_encoder):
        self._pkg_index = 0
        self._encoder = None
        self.setPayloadEncoder(payload_encoder)
        self._homeid_hashmap = {}

    def setPayloadEncoder(self, encoder):
        if encoder != None:
            from zwave.zme_zwave_protocol import ZWaveTransportEncoder 
            self._encoder = ZWaveTransportEncoder(encoder)
        else:
            self._encoder = None
    @staticmethod
    def _convert1ByteFloat(b, coef):
        if b > 127:
            b -= 256
        b *= coef
        return b
    @staticmethod
    def parseRadioMetadata(raw_data, zwproto=False):
        md = {}
        if zwproto:
            if len(raw_data) > 4:
                md["rssi"] = ZWPKGParser._convert1ByteFloat(raw_data[0], 1.0)
                md["rssi"] += ZWPKGParser.RSSI_SHIFT
                raw_data = raw_data[1:]
            else:
                md["rssi"] = 0
        else:
            if len(raw_data) > 3:
                md["rssi"] = ZWPKGParser._convert1ByteFloat(raw_data[0], 1.0)
                md["rssi"] += ZWPKGParser.RSSI_SHIFT
                raw_data = raw_data[1:]
            else:
                md["rssi"] = 0
        md["is_lr"] = False
        md["freq"] = "UNKN"
        md["speed"] = 0
        md["channeli"] = 0
        if zwproto:
            md["freqi"] = raw_data[0]
            md["channeli"] = raw_data[1]
            md["prot_i"] = raw_data[2]
            fi = md["freqi"]
            freq = ZWPKGParser.REGION_MAP[fi]
            md["is_lr"] =  (md["channeli"] == freq[2])
            md["freq"] = freq[0]
            if(len(freq[1]) > md["channeli"]):
                md["speed"] = freq[1][md["channeli"]]
            else:
                md["speed"] = 0
            
        else:
            md["channeli"] = raw_data[0]
            md["prot_i"] = raw_data[1]
        
        return md
    @staticmethod
    def _addDictVal(encap, field, value):
        if encap == None:
            encap = {}
        encap[field] = value
        return encap
    @staticmethod
    def _getDictEncap(encap, field):
        if encap == None:
            return None
        if not (field in encap):
            return None
        return encap[field]
    @staticmethod
    def calcHomeIdHash(homeid):
        arr = zme_int_toarr(homeid, 4)
        hash_result = 0xFF
        for a in arr:
            hash_result = hash_result ^ a
        return hash_result

    def makeBeamPkg(self, raw_data, bStart, defaultFreq="UNKN"):
        pkg   = {"raw":raw_data, "dir":1, "rssi":0, "raw_md":[0,0,0,0], "ts":time.time()}
        pkg["is_lr"] = False
        pkg["freq"] = defaultFreq
        pkg["speed"] = 40000
        pkg["channeli"] = 1
        home_id_sign = None
        if raw_data[2] != 0x55:
            if raw_data[2] in self._homeid_hashmap:
                home_id_sign = self._homeid_hashmap[raw_data[2]]
            else:
                logging.warning("Can't find home id value for hash:%02x map:%s"%(raw_data[2], self._homeid_hashmap))
        self._encoder.fillBeamPackage(pkg, bStart, raw_data[1], home_id_sign)
        pkg["index"] = self._pkg_index
        self._pkg_index += 1 
        return pkg
    def parse(self, raw_data, raw_md, bzw=False):
        #print("raw:%s md:%s"%(splitHexBuff(raw_data), splitHexBuff(raw_md)))
        pkg = {"raw":raw_data, "raw_md":raw_md, "ts":time.time()}
        md_radio = ZWPKGParser.parseRadioMetadata(raw_md, bzw)
        if md_radio != None:
            pkg.update(md_radio)
        else:
            logging.warning("!{NO RADIO}")
            return pkg
        pkg["dir"] = 0
        if raw_data[0] == 0xF8:
            pkg["dir"] = 1
        elif raw_data[0] == 0xFC:
            pkg["dir"] = 2
        raw_data = raw_data[1:]
        pkg["index"] = self._pkg_index
        self._pkg_index += 1 
        if self._encoder != None:
            md_radio["freq"] = self._encoder.decodeFreq(md_radio["freq"], md_radio["channeli"])
            pkg["freq"] = md_radio["freq"]
            zw_pkg = self._encoder.decode_new_version(raw_data, md_radio["speed"], None, md_radio["freq"], md_radio["channeli"])
            if "homeid" in zw_pkg:
                hash  = ZWPKGParser.calcHomeIdHash(zw_pkg["homeid"])
                self._homeid_hashmap[hash] = zw_pkg["homeid"]
            if md_radio != None:
                pkg.update(zw_pkg)
        return pkg
    @staticmethod
    def _formatNID(nid, ep=None):
        if (ep!= None) and (ep != 0):
            return "%3d.%02d"%(nid, ep)
        return "%6d"%(nid)
    @staticmethod 
    def _hasFormatOptions(option_list, opt):
        if option_list == None:
            return False
        if opt in option_list:
            return True
        return False
    COLOR_POW_ARRAY = [Fore.BLUE, Fore.GREEN, Fore.CYAN,  Fore.YELLOW, Fore.RED, Fore.MAGENTA]
    DEFAULT_COLOR_SCHEME = {"index":Fore.WHITE, 
                            "spelling":Fore.CYAN, 
                            "encap_spelling":Fore.YELLOW, 
                            "raw":Fore.GREEN, 
                            "raw_payload":Fore.LIGHTGREEN_EX, 
                            "homeid":Fore.CYAN, 
                            "nodeid":Fore.YELLOW, 
                            "default":Fore.WHITE,
                            "validation_failed":Fore.RED}
    @staticmethod 
    def _extract_frompallete(type, color_scheme):
        if not (type in color_scheme):
            return color_scheme["default"]
        return color_scheme[type]
    @staticmethod 
    def _rssi2Color(rssi_val):
        div = 64 // len(ZWPKGParser.COLOR_POW_ARRAY)
        
        index = int((rssi_val + 48) * 1.0 / div)
        if index >= len(ZWPKGParser.COLOR_POW_ARRAY):
            index = len(ZWPKGParser.COLOR_POW_ARRAY)-1
        if index < 0:
            index = 0
        return ZWPKGParser.COLOR_POW_ARRAY[index]
    @staticmethod 
    def _colorizeText(text, color, options):
        if(ZWPKGParser._hasFormatOptions(options, "color")):
            return color+text
        return text
    @staticmethod 
    def formatTableRawHeader(options=None):
        text = ""
        color_map =  ZWPKGParser.DEFAULT_COLOR_SCHEME
        if options != None:
            if "colormap" in options:
                color_map =  options["colormap"]
        text += ZWPKGParser._colorizeText("%4s"%("#"),
                                           ZWPKGParser._extract_frompallete("index", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %15s"%("TimeStamp"),
                                           ZWPKGParser._extract_frompallete("ts", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %2s"%("<>"),
                                           ZWPKGParser._extract_frompallete("dir", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %10s"%("SPEED"),
                                           ZWPKGParser._extract_frompallete("speed", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %7s"%("RSSI"),
                                           ZWPKGParser._extract_frompallete("rssi", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %48s"%("RAW DATA"),
                                           ZWPKGParser._extract_frompallete("raw", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" ", Fore.WHITE, options)
        return text
        
    @staticmethod 
    def formatTableHeader(options=None):
        text = ""
        color_map =  ZWPKGParser.DEFAULT_COLOR_SCHEME
        if options != None:
            if "colormap" in options:
                color_map =  options["colormap"]
        text += ZWPKGParser._colorizeText("%8s"%("#"),
                                           ZWPKGParser._extract_frompallete("index", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %15s"%(""),
                                           ZWPKGParser._extract_frompallete("ts", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %2s"%("<>"),
                                           ZWPKGParser._extract_frompallete("dir", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %3s"%("REG"),
                                           ZWPKGParser._extract_frompallete("freq", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %8s"%("SPEED"),
                                           ZWPKGParser._extract_frompallete("speed", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %7s"%("RSSI"),
                                           ZWPKGParser._extract_frompallete("rssi", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %8s"%("HOMEID"),
                                           ZWPKGParser._extract_frompallete("homeid", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %6s"%("SRC"),
                                           ZWPKGParser._extract_frompallete("nodeid", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %6s"%("DST"),
                                          ZWPKGParser._extract_frompallete("nodeid", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %5s"%("TYPE"),
                                           ZWPKGParser._extract_frompallete("type", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %15s"%("ROUTE"),
                                           ZWPKGParser._extract_frompallete("route", color_map),
                                           options)
        if ("encap_spelling" in options) and (options["encap_spelling"]):
             text += ZWPKGParser._colorizeText(" %16s"%("ENCAPSULATION"),
                                           ZWPKGParser._extract_frompallete("encap_spelling", color_map),
                                           options)
        if not (ZWPKGParser._hasFormatOptions(options, "no_spelling")):
             text += ZWPKGParser._colorizeText(" %48s"%("SPELLING"),
                                           ZWPKGParser._extract_frompallete("spelling", color_map),
                                           options)
        if not (ZWPKGParser._hasFormatOptions(options, "no_raw")):
             text += ZWPKGParser._colorizeText(" %24s"%("RAW PAYLOAD"),
                                           ZWPKGParser._extract_frompallete("raw", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" ", Fore.WHITE, options)
        return text

    @staticmethod
    def formatRawPackage(pkg, options=None):
        text = ""
        color_map =  ZWPKGParser.DEFAULT_COLOR_SCHEME
        if options != None:
            if "colormap" in options:
                color_map =  options["colormap"]
        if not "ts" in pkg:
            #print("NO TS")
            return None
        if not "rssi" in pkg:
            #print("NO RSSI")
            return None
        ms = pkg["ts"] - int(pkg["ts"])
        dt_text =  datetime.datetime.fromtimestamp(pkg["ts"]).strftime("%H:%M:%S"+".%03d"%(ms*1000))
        dir = ">>"
        if "dir" in pkg:
            if pkg["dir"] == 1:
                dir = ">>"
            elif pkg["dir"] == 2:
                dir = "<<"
        text = ""
        text += ZWPKGParser._colorizeText("%4d"%(pkg["index"]),
                                           ZWPKGParser._extract_frompallete("index", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %15s"%(dt_text),
                                           ZWPKGParser._extract_frompallete("ts", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %2s"%(dir),
                                           ZWPKGParser._extract_frompallete("dir", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %5.1fkbps"%(pkg["speed"]/1000.0),
                                           ZWPKGParser._extract_frompallete("speed", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %4.0fdBm"%(pkg["rssi"]),
                                           ZWPKGParser._rssi2Color(pkg["rssi"]),
                                           options)
        text += ZWPKGParser._colorizeText(" %s"%(splitHexBuff(pkg["raw"])),
                                           ZWPKGParser._extract_frompallete("raw", color_map),
                                           options)
        return text
    @staticmethod
    def formatRoute(p):
        route_txt = ""
        if p["repeaters"] != None:
            sep = "-"
            if p["rt_src_node_id"] == p["src_node_id"]:
                sep = ">"
            route_txt += "%d%s"%(p["src_node_id"], sep)
            for r in p["repeaters"]:
                sep = "-"
                if p["rt_src_node_id"] == r:
                    sep = ">"
                route_txt += "%d%s"%(r, sep)
            route_txt += "%d"%(p["dst_node_id"]) 
        return route_txt
    @staticmethod
    def IsEPDSTRoute(p):
        if p["repeaters"] == None:
            return True
        ft = p["repeaters"][len(p["repeaters"])-1]
        return (ft == p["rt_src_node_id"])
    @staticmethod
    def formatPackage(pkg, options=None, sub_index=0):
        text = ""
        if not "ts" in pkg:
            #print("NO TS")
            return None
        if not "rssi" in pkg:
            #print("NO RSSI")
            return None
        if not "homeid" in pkg:
            #print("NO HOMEID")
            return None
        color_map =  ZWPKGParser.DEFAULT_COLOR_SCHEME
        if options != None:
            if "colormap" in options:
                color_map =  options["colormap"]
        
        raw_format = "payload"
        if "raw_format" in options:
            raw_format = options["raw_format" ]
        ms = pkg["ts"] - int(pkg["ts"])
        dt_text =  datetime.datetime.fromtimestamp(pkg["ts"]).strftime("%H:%M:%S"+".%03d"%(ms*1000))
        #dir_map ={0:"(?)",1:">>",2:"<<"}
        dir = ">>"
        if "dir" in pkg:
            if pkg["dir"] == 2:
                dir = "<<"
        routed_text = ZWPKGParser.formatRoute(pkg)
        text = ""
        index_text = "%4d   "%(pkg["index"])
        if ("app" in pkg) and (len(pkg["app"]) > 1):
            index_text = "%4d.%2d"%(pkg["index"], sub_index)
        text += ZWPKGParser._colorizeText(index_text,
                                           ZWPKGParser._extract_frompallete("index", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %15s"%(dt_text),
                                           ZWPKGParser._extract_frompallete("ts", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %2s"%(dir),
                                           ZWPKGParser._extract_frompallete("dir", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %3s"%(pkg["freq"]),
                                           ZWPKGParser._extract_frompallete("freq", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %5.1fkbps"%(pkg["speed"]/1000.0),
                                           ZWPKGParser._extract_frompallete("speed", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %4.0fdBm"%(pkg["rssi"]),
                                           ZWPKGParser._rssi2Color(pkg["rssi"]),
                                           options)
        text += ZWPKGParser._colorizeText(" %08X"%(pkg["homeid"]),
                                           ZWPKGParser._extract_frompallete("homeid", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %s"%(ZWPKGParser._formatNID(pkg["src_node_id"], pkg["src_ep"])),
                                           ZWPKGParser._extract_frompallete("nodeid", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %s"%(ZWPKGParser._formatNID(pkg["dst_node_id"], pkg["dst_ep"])),
                                          ZWPKGParser._extract_frompallete("nodeid", color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %5s"%(pkg["type"]),
                                           ZWPKGParser._extract_frompallete("type"+pkg["type"], color_map),
                                           options)
        text += ZWPKGParser._colorizeText(" %15s"%(routed_text),
                                           ZWPKGParser._extract_frompallete("route", color_map),
                                           options)

        if(not pkg["is_valid"]):
            text += ZWPKGParser._colorizeText(" [!]",
                                           ZWPKGParser._extract_frompallete("validation_failed", color_map),
                                           options)   
        else:
            text += ZWPKGParser._colorizeText("    ",
                                           ZWPKGParser._extract_frompallete("validation_ok", color_map),
                                           options)
        
        if ("encap_spelling" in options) and (options["encap_spelling"]):
            if "encap_spelling" in pkg:
                text += ZWPKGParser._colorizeText(" %-16s"%(pkg["encap_spelling"]),
                                                ZWPKGParser._extract_frompallete("encap_spelling", color_map),
                                                options)
            else:
                text += ZWPKGParser._colorizeText(" %-16s"%(""),
                                                ZWPKGParser._extract_frompallete("encap_spelling", color_map),
                                                options)     
        if pkg["type"] != "ACK" or raw_format == "full":
            if not "app" in pkg:
                text += " "
                if raw_format != "off":
                    shift = len(text)+1
                    if ZWPKGParser._hasFormatOptions(options, "color"):
                        shift -= 5*13
                        if ZWPKGParser._hasFormatOptions(options, "encap_spelling"):
                            shift -= 5
                    if  isinstance(pkg["raw"], str):
                        pkg["raw"] = formatHexInput(pkg["raw"])
                        #print("Strange RAW:%s"%(pkg["raw"]))
                    #else:
                    text += " %s"%(splitHexBuff(pkg["raw"], 12, " "*shift, True))
                
            else:
                if len(pkg["app"]) > sub_index:
                    app = pkg["app"][sub_index]
                    if not (ZWPKGParser._hasFormatOptions(options, "no_spelling")):
                        spelling = ""
                        if "spelling" in app:
                            spelling += app["spelling"]
                            text += ZWPKGParser._colorizeText(" %-48s"%(spelling),
                                                ZWPKGParser._extract_frompallete("spelling", color_map),
                                                options)
                    if raw_format != "off":
                        shift = len(text)+1
                        if ZWPKGParser._hasFormatOptions(options, "color"):
                            shift -= 5*13
                        if ZWPKGParser._hasFormatOptions(options, "encap_spelling"):
                            shift -= 5
                        raw_buff = app["payload"]
                        clr = ZWPKGParser._extract_frompallete("raw_payload", color_map)
                        if (raw_format == "full") or (raw_format == "complex"):
                            raw_buff = pkg["raw"]
                            clr = ZWPKGParser._extract_frompallete("raw", color_map)
                        shift_txt = " "*shift
                        raw_paload_text = " %s"%(splitHexBuff(raw_buff, 12, shift_txt, True))
                        text += ZWPKGParser._colorizeText(raw_paload_text,
                                                clr,
                                                options)
                        if raw_format == "complex":
                            raw_paload_text = "%s[ %s ]"%(shift_txt, splitHexBuff(app["payload"], 12, shift_txt, True))
                            text += "\n"+ZWPKGParser._colorizeText(raw_paload_text,
                                                ZWPKGParser._extract_frompallete("raw_payload", color_map),
                                                options)
        text += ZWPKGParser._colorizeText(" ", Fore.WHITE, options)
        return text
    

class PTIScannerThread(LoopingThread):
    PTI_TYPE_ZWAVE = 0
    PTI_TYPE_802_15_4 = 1

    PTI_TYPES = {"ZWAVE":PTI_TYPE_ZWAVE, "802.15.4":PTI_TYPE_802_15_4}

    MODE_CONNECTING_TO_SERIAL = -1
    MODE_CONNECTION_FAILED = -2
    MODE_CONNECTION_STOPPED = -3
    MODE_CONNECTION_RETRY = -4
    MODE_WAIT_START = 0
    MODE_RECV_HEADER = 1
    MODE_RECV_DATA = 2
    MODE_WAIT_MD_START = 3
    MODE_RECV_METADATA = 4
    MODE_RESYNC_RF = 4
    MODE_RECV_BEAM_HEADER = 10
    MODE_RECV_BEAM_PASS = 11
    MODE_RECV_BEAM_MD = 12
    
    
    MDLEN={0xF8:5,0xFC:4}
    
    RETRY_TAKES = 10
    
    def __init__(self, port_name, profile_name = None, pti_type = PTI_TYPE_ZWAVE, baud_rate = 230400):
        self._port = Port(port_name, baud_rate, True, True)
        self._type = pti_type
        self._pkg_lock = Lock()
        self._con_lock = Lock()
        self._pkg_list = []
        self._current_buff = []
        self._current_meta_buff = []
        self._pkg_parser = ZWPKGParser(profile_name)
        self._bpkg_start = False
        #self._port.Open()
        self._mode = PTIScannerThread.MODE_CONNECTING_TO_SERIAL
        self._llen = 0
        
        self._empty_cnt = 0
        self._pkg_handler = None
        self._state_handler = None
        self._custom_data = None
        self._retry_count = PTIScannerThread.RETRY_TAKES
        self._current_beam = None
        self._current_beam_pass = 0
        self._last_md = None
        self._delay = 0.001 # to archive the right precision
        self._default_freq = "N/A"
        LoopingThread.__init__(self, self.__stateMachineHandler)
    def setStateHandler(self, handler):
        self._state_handler = handler
    def __callStateHandler(self, state):
        if self._state_handler == None:
            return
        if self._custom_data != None:
            self._state_handler(self._custom_data, state)
        else:
            self._state_handler(state)
    def __stateMachineHandler(self):
        try:
            if self._mode >= PTIScannerThread.MODE_WAIT_START:
                self._scannerFunc()
            elif self._mode == PTIScannerThread.MODE_CONNECTING_TO_SERIAL:
                if not self._port.Open():
                    self.active_delay(1.0)
                    self._mode = PTIScannerThread.MODE_CONNECTION_RETRY
                else:
                    logging.debug("---Wait start---")
                    self._mode = PTIScannerThread.MODE_WAIT_START
                    self._retry_count = PTIScannerThread.RETRY_TAKES
                self.__callStateHandler(self._mode)
            elif self._mode == PTIScannerThread.MODE_CONNECTION_RETRY:
                logging.debug("---Conn retry---")
                self.active_delay(0.5)
                if self._retry_count > 0:
                    self._retry_count -= 1
                    self._mode = PTIScannerThread.MODE_CONNECTING_TO_SERIAL
                else:
                    self._mode = PTIScannerThread.MODE_CONNECTION_FAILED
                    self.__callStateHandler(self._mode)
        except ZMESerialPortException:
            logging.debug("---EXC!---")
            zmeProcessException()
            self._mode = PTIScannerThread.MODE_CONNECTION_RETRY
            self.__callStateHandler(self._mode)
    def setCustomData(self, d):
        self._custom_data = d
    def setPkgHandler(self, handler):
        self._pkg_handler = handler
    def _pushRadioPackage(self, pkg):
        if self._pkg_handler != None:
            if self._custom_data == None:
                self._pkg_handler(pkg)
            else:
                self._pkg_handler(self._custom_data, pkg)
        else:
            self._appendPackage(pkg)
    def _pushCurrentPkg(self):
        if len(self._current_buff) >0:
            logging.debug("PTI extracted pkg data:%s"%(splitHexBuff(self._current_buff)))
            pkg = self._pkg_parser.parse(self._current_buff, self._current_meta_buff, self._type == PTIScannerThread.PTI_TYPE_ZWAVE)
            if pkg == None:
               logging.error("Can't parse PTI RAW PKG!")   
            #print("PKG:%s"%(pkg))
            else:
                self._default_freq = pkg["freq"]
                self._pushRadioPackage(pkg)
        self._current_buff = []
        self._current_meta_buff = []
    def disconnect(self):
        self._port.Close()
    def on_stop(self):
        logging.debug("PTIThread:Stop action...")
        self.disconnect()
        r = super().on_stop()
        logging.debug("PTIThread:Stopped!")
        return r
    def resync(self):
        self._mode = PTIScannerThread.MODE_RESYNC_RF

    def _scannerFunc(self):
        if self._mode ==  PTIScannerThread.MODE_RESYNC_RF:
            self._port.Read(self._port.inWaiting())
            self._mode = PTIScannerThread.MODE_WAIT_START
        if self._port.inWaiting() > 0:
            self._empty_cnt = 0
            buff =  self._port.Read(self._port.inWaiting())
            logging.info("Incoming PTI buff:%s"%(splitHexBuff(buff)))
            #print("Input:%s"%(splitHexBuff(buff)))
            for b in buff:
                #print("Input:%02x"%(b))
                if self._mode == PTIScannerThread.MODE_WAIT_START:
                    #logging.debug("PTI:Wait start frame")
                    if (b==0xF8) or (b==0xFC) :
                        self._current_buff = [b]
                        if self._type == PTIScannerThread.PTI_TYPE_ZWAVE:
                            self._llen = 8
                        elif self._type == PTIScannerThread.PTI_TYPE_802_15_4:
                            self._llen = 1
                        self._mode = PTIScannerThread.MODE_RECV_HEADER
                        #print("got SOF")
                elif self._mode == PTIScannerThread.MODE_RECV_HEADER:
                    #logging.info("PTI:RCV header")
                    self._current_buff += [b]
                    # Check the WakeUp Beam
                    if((len(self._current_buff) == 2) and (self._type == PTIScannerThread.PTI_TYPE_ZWAVE) and (b == 0x55)):
                        if self._current_beam == None:
                            self._current_beam = [0x55]
                        self._llen = 3
                        self._mode = PTIScannerThread.MODE_RECV_BEAM_HEADER
                        continue
                    elif self._current_beam != None:
                        # Beam Stop
                        pkg = self._pkg_parser.makeBeamPkg(self._current_beam, False, self._default_freq)
                        logging.info("WakeUP Beam %s STOP"%(pkg))
                        self._pushRadioPackage(pkg)
                        self._current_beam = None
                    self._llen -= 1
                    if self._llen == 0:
                        if self._type == PTIScannerThread.PTI_TYPE_ZWAVE:
                            self._llen = self._current_buff[8] - 8
                        elif self._type == PTIScannerThread.PTI_TYPE_802_15_4:
                            self._llen = self._current_buff[1]
                        #logging.info("PTI:Need %d bytes"%(self._llen))
                        self._mode = PTIScannerThread.MODE_RECV_DATA
                        #print("got header. Remains:%d"%(self._llen))
                elif self._mode == PTIScannerThread.MODE_RECV_BEAM_HEADER:
                    if self._llen:
                        if len(self._current_beam) < 4:
                            self._current_beam += [b]
                        self._llen -= 1
                        if (self._llen == 0):
                            if (len(self._current_beam) == 4):
                                pkg = self._pkg_parser.makeBeamPkg(self._current_beam, True, self._default_freq)
                                logging.info("WakeUP Beam %s START"%(pkg))
                                self._pushRadioPackage(pkg)
                                #self._mode = PTIScannerThread.MODE_RECV_BEAM_PASS
                                self._current_beam += [1]
                            else:
                                #print("Beam:%s"%(self._current_beam))
                                self._current_beam[4] += 1
                            self._mode = PTIScannerThread.MODE_RECV_BEAM_PASS
                elif self._mode == PTIScannerThread.MODE_RECV_BEAM_PASS:
                    if(b == 0xF0): # Repeat of beam
                        self._llen = 4
                        self._mode = PTIScannerThread.MODE_RECV_BEAM_HEADER 
                    elif((b == 0xFE) or (b == 0xFA)): # Beam MD
                         self._mode = PTIScannerThread.MODE_RECV_BEAM_MD
                         self._beam_md = []
                         self._llen = 4
                    elif(b != 0x55):
                        logging.warning("Strange BEAM VALUE=%02x"%(b))
                elif self._mode == PTIScannerThread.MODE_RECV_BEAM_MD:
                    self._beam_md += [b]
                    self._llen -= 1
                    if self._llen == 0:
                        self._mode = PTIScannerThread.MODE_WAIT_START # Done. Wait for another package
                        self._current_beam_pass = time.time()
                elif self._mode == PTIScannerThread.MODE_RECV_DATA:
                    self._current_buff += [b]
                    self._llen -= 1
                    if self._llen == 0:
                        #logging.debug("PTI:Data received")
                        self._mode = PTIScannerThread.MODE_WAIT_MD_START
                        #print("got data. Waiting md SOF")
                elif self._mode == PTIScannerThread.MODE_WAIT_MD_START:
                    if b in [self._current_buff[0]+1, self._current_buff[0]+2]:
                        self._current_meta_buff = []
                        #logging.debug("PTI:Start MD")
                        self._mode = PTIScannerThread.MODE_RECV_METADATA
                        self._llen = PTIScannerThread.MDLEN[self._current_buff[0]]
                        if self._type != PTIScannerThread.PTI_TYPE_ZWAVE:
                            self._llen -= 1
                    else:
                        self._mode = PTIScannerThread.MODE_WAIT_START
                        #print("got md SOF. remains:%d"%(self._llen))
                elif self._mode == PTIScannerThread.MODE_RECV_METADATA:
                    self._current_meta_buff += [b]
                    self._llen -=  1
                    if self._llen == 0:
                        #logging.debug("PTI:MD finished")
                        self.current_md = self._current_meta_buff
                        try:
                            self._pushCurrentPkg()
                        except:
                            zmeProcessException("PTIClient _pushCurrentPkg")
                        self._mode =  PTIScannerThread.MODE_WAIT_START

                        #print("md received")
        else:
            if self._mode !=  PTIScannerThread.MODE_WAIT_START:
                self._empty_cnt += 1
                if self._empty_cnt > 3:
                    self._mode = PTIScannerThread.MODE_WAIT_START
            else:
                if (self._current_beam != None) and ((time.time() - self._current_beam_pass) > 0.1):
                    # Beam Stop
                    pkg = self._pkg_parser.makeBeamPkg(self._current_beam, False, self._default_freq)
                    logging.info("WakeUP Beam %s STOP"%(pkg))
                    self._pushRadioPackage(pkg)
                    self._current_beam = None
            #self.active_delay(0.01)
    def _appendPackage(self, pkg):
        #logging.info("(?) NEW PTI Pacakage OUTPUT:%s"%(splitHexBuff(pkg[1])));
        self._pkg_lock.acquire()
        self._pkg_list += [pkg]
        self._pkg_lock.release()
    def popPackage(self):
        res = None
        self._pkg_lock.acquire()
        if len(self._pkg_list) > 0:
            res = self._pkg_list[0]
            del self._pkg_list[0]
        self._pkg_lock.release()
        return res

def tracePTIFunc(args):
    sep = "*"*90
    colorama.init()
    options = {"color":True}
    print("%s[ %sPTI Tracer%s ]%s"%(sep,Fore.RED,Fore.WHITE,sep))
    if args.input != None:
        try:
            printStatus("Loading recorded trace from file:%s"%(args.input))
            with open(args.input, 'r') as fp:
                pkgs = json.load(fp)
            finallizeStatus()
            print("-"*(180+12))
            print(ZWPKGParser.formatTableHeader(options))
            print("-"*(180+12))
            for p in pkgs:
                if args.valid_only:
                    if (not ("is_valid" in p)) or (not p["is_valid"]):
                        continue
                txt = ZWPKGParser.formatPackage(p, options)
                print(txt)
        except  Exception as e:
            print("Can't load JSON-file:%s"%(e))
    else:
        print("Listening to external device. [Press Cntrl+C to stop]")
        print("-"*(180+12))
        baudrate = int(args.baudrate, 0)
        sc_path =  baseDirectoryPath(os.path.abspath(__file__))
        profile = args.profile
        zw_payload_encoder = None
        if (profile != "-"):
            if (profile == None) or (len(profile) == 0):
                from zwave.zme_zwave_profile import ZWaveDataEncoder 
                profile = sc_path + os.sep + "zme_zwave_profile.json"
            print("ZWave profile:%s"%(profile))
            zw_payload_encoder = ZWaveDataEncoder(profile)
        type = PTIScannerThread.PTI_TYPES[args.type]
        scaner = PTIScannerThread(args.device, zw_payload_encoder, type, baudrate)
        if zw_payload_encoder != None:
            print(ZWPKGParser.formatTableHeader(options))
        else:
            print(ZWPKGParser.formatTableRawHeader(options))
        print("-"*(180+12))
        terminator = GracefulTerminator()
        terminator.addThread(scaner)
        t1 = time.time()
        scaner.start()
        pkgs = []
        while  not terminator.wasStopped():
            p = scaner.popPackage()
            if p != None: 
                if args.valid_only:
                    if (not ("is_valid" in p)) or (not p["is_valid"]):
                        continue
                if zw_payload_encoder != None:
                    txt = ZWPKGParser.formatPackage(p, options)
                else:
                    txt = ZWPKGParser.formatRawPackage(p, options)
                if txt != None:
                    print(txt)
                pkgs += [p]
            time.sleep(0.1)
        if args.output != None:
            printStatus("Saving recorded trace to file:%s"%(args.output))
            with open(args.output, 'w') as fp:
                json.dump(pkgs, fp, sort_keys=True, indent=4)
            finallizeStatus()

if __name__ == "__main__":
    zmeSetupLogging("ZMEPTIClient", True, True)

    def dummyFunc(args):
        print("*** Platform: %s Version: %s ***"%(platform.system(), MY_VERSION))
    	
    def Main():
        logging.debug("\nStarting on %s.\nARGS:%s\nVERSION:%s MD5:%s" % (
            platform.system(), ' '.join(sys.argv), MY_VERSION, "-"))
        parser = argparse.ArgumentParser(description='ZWave>ME PTI Tracer tool for 7th generation. \n Welcome :)')

        parser.set_defaults(func=dummyFunc)
        subparsers = parser.add_subparsers()

        parserTracer = subparsers.add_parser('trace', help="Trace packages.")
        parserTracer.add_argument('-d', '--device', help="Device file (UNIX) or COM-port (WINDOWS)")
        parserTracer.add_argument('-b', '--baudrate', help="Device's baudrate.", default="230400")
        parserTracer.add_argument('-i', '--input', help="Uses JSON file instead of real PTI-device. Prints packages")
        parserTracer.add_argument('-o', '--output', help="Dumps all received packages to specified file")
        parserTracer.add_argument('-vo', '--valid_only', nargs='?', type=bool, const=True, default=False, help="Prints only packages with right CRC.")
        parserTracer.add_argument('-p', '--profile', default="", help="JSON file with Z-Wave protocol descriptions.")
        type_names = list(PTIScannerThread.PTI_TYPES)
        parserTracer.add_argument('-t', '--type', default=type_names[0], choices=type_names, help="Defines PTI TYPE.")
        parserTracer.set_defaults(func=tracePTIFunc)

        args = parser.parse_args()
        args.func(args)

    Main()

