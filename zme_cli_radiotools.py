from zme_modemhost import ZMEModemListener
from zme_pticlient import PTIScannerThread, ZWPKGParser
from zwave.zme_zwave_protocol import ZWaveDataEncoder
from zwave.zme_zwave_stat import ZWaveStatCollector
from zwave.zme_zwave_encap_parsers import ZWaveSecurityS2, ZWaveSecurityS0
from zwave.zme_zwave_protocol import ZWaveTransportEncoder
from zwave.zme_zwave_protocol import addAllianceXMLConverterParser
from common.zme_aux import *
from common.zme_serialport import Port
from common.zme_sapi import *
import os
import argparse
import logging
import colorama
from zlfdump import ZlfDump
from zme_threads import GracefulTerminator
from zme_web_sevices import ZMELicenseService

MY_VERSION = 0.1
g_pkg_list = []
g_setup = {"options":{"color":True, "encap_spelling":True}, "pkg_counter":0, "modem_started":False}
# --------------------------------------------------------------------------------------------
# EXPORT
# --------------------------------------------------------------------------------------------
REDUCED_PKG_STRG_FIELDS = {"ts":[False],"index":[False],"channeli":[False],"rssi":[False],"freqi":[False],"freq":[False],"speed":[False],"raw":[True], "dev":[False], "is_lr":[False]}
def int_dec_fmt(v):
    return "%d"%(v)
def int_hex_fmt(v):
    return "%x"%(v)
def str_fmt(v):
    return "%s"%(v)
def int_float1000_fmt(v):
    return " %5.1f"%(v/1000.0)
def list_dec_fmt(v):
    t = ""
    i = 0
    for vl in v:
        if i != 0:
            t += " "
        t += "%d"%(vl) 
        i +=1
    return t
def list_hex_fmt(v):
    return splitHexBuff(v, 256).replace(" ","")
def app_format_spelling(v):
    t = []
    for app in v:
        pl = []
        sp = ""
        if "payload" in app:
            pl = app["payload"]
        if "spelling" in app:
            sp = app["spelling"]
        t+= [app["spelling"], list_hex_fmt(app["payload"])]
    return t
CSV_FUNC_MAP = {"index":int_dec_fmt, 
                "ts":int_dec_fmt, 
                "freq":str_fmt, 
                "speed":int_float1000_fmt, 
                "rssi":int_dec_fmt, 
                "homeid":int_hex_fmt,
                "src_node_id":int_dec_fmt,
                "src_ep":int_dec_fmt,
                "dst_node_id":int_dec_fmt,
                "dst_ep":int_dec_fmt,
                "type":str_fmt,
                "route":list_dec_fmt,
                "app":app_format_spelling,
                "raw":list_hex_fmt
                }
def reducePKGData(pkg, b_noStr=False):
    reduced = {}
    for fld in pkg:
        if fld in REDUCED_PKG_STRG_FIELDS:
            is_lw = REDUCED_PKG_STRG_FIELDS[fld]
            value = pkg[fld]
            if (is_lw) and (not b_noStr):
                if isinstance(value, list) or isinstance(value, bytearray):
                    value = splitHexBuff(value, 2048).replace(" ","")
            reduced[fld] = value
    return reduced
def exportData2ARTProject(filename, pkgs, adv_data):
    reduced_pkgs = []
    for p in pkgs:
        reduced_pkgs += [reducePKGData(p)]
    sc = ZWaveStatCollector.getInstance()
    device_md = {"Name":"dev0"}
    device_md["Serial"] = adv_data["port"]
    device_md["Protocol"] = adv_data["transport"]
    if "dev_type" in adv_data:
        device_md["Dev.Type"] = adv_data["dev_type"]
    device_md["Baudrate"] = adv_data["baudrate"]
    if "region" in adv_data:
        device_md["Region"] = adv_data["region"]
    if "TX Power" in adv_data:
        device_md["TX Power"] = adv_data["tx_power"]
    if "uuid" in adv_data:
        device_md["UUID"] = adv_data["uuid"]
    traces_md = {"indexes":[0], "data":{"packages":reduced_pkgs, "name":"MainTrace", "config":{"auto_scroll":True}}}
    md = {"devices":[device_md], "traces":[traces_md], "cfg":{"auto_sync_s2": True}}
    md["stat"] = sc.serializeToDict()
    dumpJSONData(filename, md)
def exportData2CSV(filename, pkgs, csv_columns=None, sep = ";"):
    text = ""
    if csv_columns == None:
       csv_columns = list(CSV_FUNC_MAP)
    for p in pkgs:
        for f in csv_columns:
            if f in p:
                formatter = str_fmt
                if f in CSV_FUNC_MAP:
                    formatter = CSV_FUNC_MAP[f]
                v = p[f]
                if v == None:
                    text += sep
                    continue
                o1 = formatter(v)
                if isinstance(o1, list):
                    for i1 in o1:
                        text += i1 + sep
                else:
                    text += o1 + sep
        text += "\n"
    saveTextFile(filename, text)
    return text
def exportData2JSON(filename, pkgs):
    for p in pkgs:
        p["raw"] = list(p["raw"])
    dumpJSONData(filename, pkgs)
def exportData2ZLF(filename, pkgs):
    dumper = ZlfDump()
    dumper.add_multi(pkgs)
    dumper.save(filename)
def exportPackages2File(filename, pkgs, adv):
    ext = aux_extract_extention(filename)
    if ext == ".rtp":
        exportData2ARTProject(filename, pkgs, adv)
    elif ext == ".csv":
        exportData2CSV(filename, pkgs)
    elif ext == ".json":
        exportData2JSON(filename, pkgs)
    elif ext == ".zlf":
        exportData2ZLF(filename, pkgs)
    else:
        return False
    return True
# --------------------------------------------------------------------------------------------
# IMPORT
# --------------------------------------------------------------------------------------------
def importDataARTProject(filename, data_encoder):
    md = loadJSONData(filename)
    transport_encoder = ZWaveTransportEncoder(data_encoder)
    traced_list = {}
    if "traces" in md:
        for t in md["traces"]:
            if "data" in t:
                l = []
                traced_list[t["data"]["name"]] = []
                for p in t["data"]["packages"]:
                    lr_pkg = False
                    if "is_lr" in p:
                        lr_pkg = p["is_lr"] 
                    fs = (p["speed"] == 100000)
                    encoded = transport_encoder.decode(formatHexInput(p["raw"]), is_lr=lr_pkg, b_fullspeed=fs)
                    encoded.update(p)
                    l += [encoded]
                traced_list[t["data"]["name"]] = l
    return traced_list
def importDataJSON(filename):
    md = loadJSONData(filename)
    return md
def importZLFData(filename, data_encoder):
    importer = ZlfDump()
    res = importer.begin(filename)
    if res != ZlfDump.ZLF_DUMP_STATUS_OK:
        printError("Can't import ZLF:%s"%(res))
        return None
    transport_encoder = ZWaveTransportEncoder(data_encoder)
    cnt = 0
    pkgs = []
    while True:
        pkg = importer.nextSozStandart()
        # print("PKG:%s"%(pkg))
        if pkg == None:
            break
        decoded_pkg =  transport_encoder.decode(pkg["raw"], False, pkg["speed"] == 100000, pkg["ts"])
        decoded_pkg.update(pkg)
        decoded_pkg["index"] = cnt
        pkgs += [decoded_pkg]
        
        cnt += 1
    return pkgs
def printZWPackages(pkgs, data_encoder, max_count = None, bReencode=False):
    global g_pkg_list
    i = 0
    transport_encoder = ZWaveTransportEncoder(data_encoder)
    for p in pkgs:
        if bReencode:
            rp = reducePKGData(p, True)
            p =  transport_encoder.decode(rp["raw"], False, rp["speed"] == 100000, rp["ts"])
            p.update(rp)
        printPackage(p, False)
        g_pkg_list += [p]
        if (max_count != None) and (len(g_pkg_list) > max_count):
            break

def showImportedFile(filename, data_encoder, max_count = None, b_reencode = True):
    if not os.path.isfile(filename):
        printError("File \"%s\" does not exist!"%(filename))
        return False
    ext = aux_extract_extention(filename)
    sep = "*"*80
    pkgs = None
    if ext == ".rtp":
        pkgs = importDataARTProject(filename, data_encoder)
    elif ext == ".json":
        pkgs = importDataJSON(filename)
    elif ext == ".zlf":
        # print("ZLF!")
        pkgs = importZLFData(filename, data_encoder)
    else:
        printError("Unknown file format:%s"%(ext))
        return False
    if isinstance(pkgs, dict):
        for n in pkgs:
            print("%s[%s%s%s]%s"%(sep, colorama.Fore.RED,n,colorama.Fore.WHITE,sep))
            printZWPackages(pkgs[n], data_encoder, max_count, b_reencode)
    else:
        printZWPackages(pkgs, data_encoder, max_count, b_reencode)
    return  True
# --------------------------------------------------------------------------------------------
# PKG Transmitting
# --------------------------------------------------------------------------------------------
def _parseNodeId(t):
    point_index = t.find(".")
    if point_index == -1:
        return int(t, 0), None
    l = t.split(".")
    return int(l[0],0),int(l[1],0)
def _parseCCCMD(t):
    point_index = t.find(".")
    if point_index == -1:
        val = int(t, 16)
        return (val >> 8) & 0xFF, val & 0xFF
    l = t.split(".")
    return l[0], l[1]
def _parseStrValue(v):
    if v.lower() == "true":
        return True
    if v.lower() == "false":
        return False
    #if v.startswith("0x") or v.isdigit():
    #    return int(v, 0)
    return v
def _extractExtParams(l):
    adv_params = {}
    pos_params = []
    for el in l:
        eqv_indx = el.find("=")
        if eqv_indx == -1:
            pos_params += [el]
        else:
            vn = el.split("=")
            adv_params[vn[0]] = _parseStrValue(vn[1])
    return pos_params, adv_params
def _active_sleep(thread, interval):
    quantum = 0.01
    num = int(interval / quantum)+1
    while num:
        if not thread.isLooping():
            break
        num -= 1
        time.sleep(quantum)
def processSendData(dev, send_list, data_encoder):
    if not isinstance(dev, ZMEModemListener):
        if len(send_list) != 0:
            print("\n%sYou can send packages only in MODEM mode!%s\n"%(colorama.Fore.RED,colorama.Fore.WHITE))
            return
    transport_encoder = ZWaveTransportEncoder(data_encoder)
    for sp in send_list:
        send_args = sp.split(",")
        if len(send_args) > 1:
            if send_args[0] == "RAW":
                if len(send_args) >= 2:
                    channel = int(send_args[1],0)
                    data = formatHexInput(send_args[2])
                    data = [channel] + data
                    logging.info("RAW SEND:%s"%(splitHexBuff(data)))
                    dev.sendMessage(data)
                else:
                    printError("SEND.RAW:Wrong parameter count in \"%s\""%(sp))
            elif send_args[0] == "SLP":
                tm = float(send_args[1])
                _active_sleep(dev, tm)
            elif send_args[0] == "APP":
                if len(send_args) >= 6:
                    pkg = {}
                    channel = int(send_args[1],0)
                    pkg["homeid"] = int(send_args[2],16)
                    pkg["src_node_id"], src_ep = _parseNodeId(send_args[3])
                    if src_ep != None:
                        pkg["src_ep"] = src_ep
                    pkg["dst_node_id"], dst_ep = _parseNodeId(send_args[4])
                    if dst_ep != None:
                        pkg["dst_ep"] = dst_ep
                    cc, cmd = _parseCCCMD(send_args[5])
                    params, adv_params = _extractExtParams(send_args[6:])
                    pkg.update(adv_params)
                    version = data_encoder.getCCHighestVersion(cc)
                    pkg["payload"] = data_encoder.encodeApplication(cc, cmd, params, version)
                    #print("RAW PAYLOAD:%s"%(splitHexBuff(pkg["payload"])))
                    raw_data = transport_encoder.encode(pkg, channel == 0)
                    if raw_data == None:
                        printError("Can't encode message:%s"%(sp))
                        continue
                    raw_data = [channel] + raw_data
                    logging.info("APP SEND:%s"%(splitHexBuff(raw_data)))
                    dev.sendMessage(raw_data)
            else:
                printError("Wrong COMMAND encoding type:%s. Known types: RAW, APP, SLP."%(send_args[0]))
                continue
        else:
            printError("SEND:Wrong parameter count in \"%s\""%(sp))
            continue
# --------------------------------------------------------------------------------------------
def dispatchSecurityError(pkg, is_modem):
    home_id =  pkg["homeid"]
    src_id =  pkg["src_node_id"]
    dst_id = pkg["dst_node_id"]
    err_s2_code = None
    err_s0_code = None
    warn_message = None
    if "s2_err_code" in pkg:
        err_s2_code = pkg["s2_err_code"]
    if "s0_error" in pkg:
        err_s0_code = pkg["s0_error"]
    if is_modem:
        if err_s2_code == ZWaveSecurityS2.S2_DECODE_ERROR_NO_NONCE:
            warn_message = "S2 DECRYPTION ERROR: WE HAVE NO S2 CONTEXT FOR (%08x, %d, %d). Trying to resync..."%(home_id, src_id, dst_id)
    else:
         if err_s2_code == ZWaveSecurityS2.S2_DECODE_ERROR_NO_NONCE:
            warn_message = "S2 DECRYPTION ERROR: WE HAVE NO S2 CONTEXT FOR (%08x, %d, %d). You can only reboot some of these devices to get initial NONCE."%(home_id, src_id, dst_id)
    if err_s2_code == ZWaveSecurityS2.S2_DECODE_ERROR_NO_KEY:
        warn_message = "S2 DECRYPTION ERROR: WE HAVE NO S2 KEY FOR (%08x, %d, %d). Please provide a right one."%(home_id, src_id, dst_id)
    elif err_s2_code == ZWaveSecurityS2.S2_DECODE_ERROR_SYNC:
        warn_message = "S2 DECRYPTION ERROR: WRONG SYNC FOR (%08x, %d, %d). Seems S2 key was changed."%(home_id, src_id, dst_id)
    elif err_s2_code == ZWaveSecurityS2.S2_DECODE_ERROR_WRONG_MESSAGE:
        warn_message = "S2 DECRYPTION ERROR: MAC CODE mismatches for this message ^^^. May be provided key is wrong."
    elif err_s2_code == ZWaveSecurityS2.S2_DECODE_ERROR_INTERNAL_ERROR:
        warn_message = "S2 DECRYPTION ERROR: Internal library error. Contact Z-Wave.Me."
    elif (err_s2_code != None) and (err_s2_code != 0):
        warn_message = "S2 DECRYPTION ERROR: Unknown error_code:%d. Contact Z-Wave.Me."%(err_s2_code)
    if err_s0_code == ZWaveSecurityS0.S0_DECODE_ERROR_NO_KEY:
        warn_message = "S0 DECRYPTION ERROR: WE HAVE NO S0 KEY FOR (%08x, %d, %d). Please provide a right one."%(home_id, src_id, dst_id)
    elif err_s0_code == ZWaveSecurityS0.S0_DECODE_ERROR_NO_NONCE:
        warn_message = "S0 DECRYPTION ERROR: WE HAVE NO S0 NONCE for this messsage ^^^."
    elif err_s0_code == ZWaveSecurityS0.S0_DECODE_ERROR_WRONG_MESSAGE:
        warn_message = "S0 DECRYPTION ERROR: MAC CODE mismatches for this message ^^^. May be provided key is wrong."
    if warn_message != None:
        logging.warning(warn_message)
    return err_s2_code, warn_message
g_first_pack = True
def checkFilter(value, reqtype, set):
    #print("Value=%s rq:%d set:%s"%(value, reqtype, set))
    for en in set:
        if reqtype == 0: # equal
            if value == en:
                return True
        elif reqtype == 1: # equal
            if value == en:
                return False
    if reqtype == 0:
        return False
    return True
def _checkFilters(pkg, filters):
    for f in filters:
        if f[1] in pkg:
            if not checkFilter(pkg[f[1]], f[0], f[2]):
                return False
    return True
def printPackage(pkg, is_modem):
    global g_first_pack
    options = g_setup["options"]
    if (g_first_pack) and (options["raw_format"] != "hex_app"):
        print(ZWPKGParser.formatTableHeader(options))
        g_first_pack = False
    if g_setup["adv_options"]["filters"]:
        bbm = False
        if "is_beam" in pkg:
            bbm = pkg["is_beam"]
        else:
            logging.warning("Package without beam property:%s"%(pkg))
        if((not bbm) and (not _checkFilters(pkg, g_setup["adv_options"]["filters"]))):
            return 0
    logging.debug("DBG RAW PKG:%s"%(pkg))
    err_s2_code, warn_message = dispatchSecurityError(pkg, is_modem)
    
    if options["raw_format"] == "hex_app":
        if "raw" in pkg:
            if(len("raw") != 0):
                tm=int(time.time()*1000)
                rssi=int(pkg["rssi"])
                raw_buff = splitHexBuff(pkg["raw"], 128, True).replace(" ","")
                print("%d %d %s"%(tm, rssi, raw_buff))
        return err_s2_code
    if "app" in pkg:
        for i in range(len(pkg["app"])):
            t = ZWPKGParser.formatPackage(pkg, options, i)
            if t != None:
                print(t)
    else:
        t = ZWPKGParser.formatPackage(pkg, options)
        if t != None:
            print(t)
    if warn_message != None:
        print("%s%s(!)%s%s"%(" "*32+"^^^", colorama.Fore.RED, warn_message, colorama.Fore.WHITE))
    return err_s2_code

g_seq = 0
def pkgHandler(ud, pkg):
    global g_pkg_list, g_setup, g_seq
    is_modem = isinstance(ud, ZMEModemListener)
    err_s2_code = printPackage(pkg, is_modem)
    g_pkg_list += [pkg]
    g_setup["pkg_counter"] += 1
    if is_modem:
        modem = ud
        # Only for modem devices we are able to ask for syncronization
        # Только пакеты дошедшые до назначения должны вызывать отправку NonceGet
        if (err_s2_code == ZWaveSecurityS2.S2_DECODE_ERROR_NO_NONCE) and (ZWPKGParser.IsEPDSTRoute(pkg)):
            time.sleep(1.5)
            home_id =  pkg["homeid"]
            src_id =  pkg["src_node_id"]
            dst_id = pkg["dst_node_id"]
            seq = int(time.time()*1000)& 0xFF
            buff = [0x01]
            buff += zme_int_toarr(home_id, 4, bInv=True)
            buff += [src_id, 0x51, (g_seq&0x0F), 0x0d, dst_id, 0x9F, 0x01, g_seq]
            g_seq += 1
            #buff += [Checksum(buff) & 0xFF]
            modem.sendMessage(buff)
            #time.sleep(0.5)
   
def ModemStateListener(ud, s, dta):
    global g_setup
    logging.info("MODEM STATE:%s"%(s))
    if s == ZMEModemListener.MODE_INITED:
        g_setup["modem_started"] = True
    elif s == ZMEModemListener.MODE_STOPPED:
        printInfo("MODEM has been terminated")
        ud.stopLoop()
    elif s == ZMEModemListener.MODE_NOT_SUPPORTED:
        printError("MODEM mode is not supported for your device!")
        lic_svc = ZMELicenseService()
        uuid = "%x"%(dta["chip_uuid"])
        printInfo("\nYou can purchase a license for your device by following the link %s%s%s\n"%(colorama.Fore.RED, lic_svc.webUIURL(uuid), colorama.Fore.WHITE))
        ud.stopLoop()
def PTIStateListener(ud, s):
    logging.info("PTI STATE:%s"%(s))
def _InitRadioDevice(transport, portname, baudrate, data_encoder, dtype=None):
    dev = None
    if transport == "MODEM":
        dev = ZMEModemListener(portname, data_encoder, pkgHandler, baudrate, ModemStateListener, dev_type=dtype)
    else:
        dev = PTIScannerThread(portname, data_encoder, baud_rate=baudrate)
        dev.setCustomData(0)
        dev.setPkgHandler(pkgHandler)
        dev.setStateHandler(PTIStateListener)
    return dev
def _parseArgFilterArg(text, bInt, bRec=False):
    val = text
    if text.find(",") != -1:
        items = text.split(",")
        l = []
        for i in items:
            l += [_parseArgFilterArg(i, bInt, True)]
        return l
    if bInt or text.isdigit() or text.startswith("0x"):
        val = int(text, 0)
    if bRec:
        return val
    return [val]
def _parseFilterString(s):
    filters = []
    rules_list = s.split(";")
    for r in rules_list:
        if r.find("!=") != -1:
            parts = r.split("!=")
            n = parts[0]
            filters += [[1, n, _parseArgFilterArg(parts[1], False)]]
        elif r.find("=") != -1:
            parts = r.split("=")
            n = parts[0]
            filters += [[0, n, _parseArgFilterArg(parts[1], False)]]
    return filters

def traceFunc(args):
    global g_pkg_list, g_setup
    colorama.init()
    g_setup["options"]["raw_format"] = args.raw_mode
    sep = "*"*80
    print("%s[ %sZWave>ME %sCLI Radio Tools%s ]%s"%(sep, colorama.Fore.CYAN, colorama.Fore.RED,colorama.Fore.WHITE,sep))
    max_pkgs = args.max_packages
    if max_pkgs != None:
        max_pkgs = int(max_pkgs, 0)
    max_time = args.max_time
    if max_time != None:
        max_time = int(max_time, 0)
    rc_path =  baseDirectoryPath(os.path.abspath(__file__)) + os.sep  #+"rc"+ os.sep
    if args.profile != None:
        if not os.path.isfile(args.profile):
            printError("Wrong profile %s. File doesn't exist!"%(args.profile))
            sys.exit(1)
        profile = args.profile
    else:
        profile = rc_path + "zme_zwave_profile.json"
    data_encoder = ZWaveDataEncoder(profile)
    if args.input != None:
        g_setup["adv_options"] = {}
        g_setup["adv_options"]["port"] = ""
        g_setup["adv_options"]["transport"] = "PTI"
        g_setup["adv_options"]["baudrate"] = "230400"
        g_setup["adv_options"]["region"] = "EU"
        g_setup["adv_options"]["tx_power"] = 50
        g_setup["adv_options"]["uuid"] = ""
        showImportedFile(args.input, data_encoder, max_pkgs, args.input_reencode)
    else:
        port_md = Port.portMetadata(args.device)
        if port_md == None:
            printError("Unknown serial port:%s"%(args.device))
            sys.exit(2)
        gt = GracefulTerminator()
        br = int(args.baudrate)
        DEVICE_TYPE={"auto":SerialAPIUtilities.DETECT_MODE_AUTO, 
                    "z-uno":SerialAPIUtilities.DETECT_MODE_ZUNO,
                    "sapi":SerialAPIUtilities.DETECT_MODE_SAPI}
         # SerialAPIUtilities.DETECT_MODE_ZUNO
        dev = _InitRadioDevice(args.transport_type, args.device, br, data_encoder, DEVICE_TYPE[args.device_type])
        if dev == None:
            printError("Can't initialize Radio Receiver!")
            sys.exit(-1)
        gt.addThread(dev)
        print("\nPress [%sCntrl+C%s] to stop the tool\n"%(colorama.Fore.RED,colorama.Fore.WHITE))
        dev.start()
        tx_power = int(args.tx_power)
        start_ts = time.time()
        if(args.transport_type == "MODEM"):
            dev.connect(args.frequency, tx_power)
            dev.setUserData(dev)
            start_ts += 2.0
        
        g_setup["adv_options"] = {}
        g_setup["adv_options"]["port"] = args.device
        g_setup["adv_options"]["transport"] = args.transport_type
        g_setup["adv_options"]["baudrate"] = args.baudrate
        g_setup["adv_options"]["region"] = args.frequency
        g_setup["adv_options"]["tx_power"] = tx_power
        g_setup["adv_options"]["uuid"] = port_md["uuid"]
        g_setup["adv_options"]["filters"] = None
        if args.filter:
             g_setup["adv_options"]["filters"] = _parseFilterString(args.filter)
        send_processed = False
        while not gt.wasStopped():
            if g_setup["modem_started"] and not send_processed:
                start_ts = time.time()
                time.sleep(0.2) # Нужно чуть-чуть подождать
                processSendData(dev, args.send, data_encoder)
                send_processed = True
            if max_time != None:
                dt = int((time.time() - start_ts) * 1000)
                if dt > max_time:
                    dev.stopLoop()
                    break
            if max_pkgs != None:
                if g_setup["pkg_counter"] > max_pkgs:
                    dev.stopLoop()
                    break
            if not dev.isLooping():
                break
            time.sleep(0.1)
    if args.output != None:
        print("\n%sExport data to file:%s%s%s\n"%(colorama.Fore.RED, colorama.Fore.GREEN, args.output, colorama.Fore.WHITE))
        exportPackages2File(args.output, g_pkg_list, g_setup["adv_options"])
send_help="""
        Sends Z-Wave message. You can send multiple messages using this parameter multiple times. 
        You can use several modes to send messages: RAW, APP, SLP. 
        RAW mode sends the Z-Wave message as is, everything written in the second 
        parameter is sent without additional checks. 
            Format: -s RAW,CH,HEXSTR 
            Where CH is the channel through which the message is sent (0 - 100 kbps, 1 - 40kbps, 2-9.6kbps), 
            HEXSTR is a hexadecimal string. 
            Example:
            -s RAW,0,AABBCCDD00010203 sends arbitrary data via a 100 kilobit (#0) channel.
        APP mode generates an application-level Z-Wave package based on data provided by the user separated by commas.
        The user must specify the channel, home id, source node_id, destination node_id, command class.command and 
        further parameters of this Z-Wave command, in addition, optional parameters can be specified by enumeration. 
            Format: -s APP,CH,HOMEID,SRC_NODE_ID,DST_NODE_ID,CC.CMD,[Param1,...,ParamN][,Option1=Value1,...,OptionM=ValueM]
            Where:
            CH is the channel through which the message is sent (0 - 100 kbps, 1 - 40kbps, 2-9.6kbps),
            HOMEID is address of needed Z-Wave Network,
            SRC_NODE_ID - address of sender (fake address in this case),
            SRC_NODE_ID - address of receiver (fake address in this case). If you use a dot in the address, the message will be wrapped in a Multichannel,
            CC.CMD - Application level command class and its command. You can use text or hexadecimal format. For example BASIC.SET or equivalently 2001.
            Param1...ParamN - parameters of desired command,
            Option1..OptionM - options of encoder
            Examples:
              -s APP,1,FD0F1122,1,50,SWITCH_BINARY.SET,255 - sends SwitchBinary.set(255) to NodeID 50 in FD0F1122 network
              -s APP,1,FD0F1122,1,50,SWITCH_BINARY.SET,0,is_ack=True - sends SwitchBinary.set(0) to NodeID 50 in FD0F1122 network and requests ACK from this node
              -s APP,1,FD0F1122,1,50,SWITCH_BINARY.SET,0,is_ack=True,crc16_encap=True - sends SwitchBinary.set(0) to NodeID 50 in FD0F1122 network and requests ACK from this node and wraps payload to crc16 CommandClass
        SLP mode simply inserts a delay between the previous and next packet.
            Format: -s SLP,time_in_seconds
            Example:
               -s APP,1,FD0F1122,1,50,SWITCH_BINARY.SET,255,is_ack=True -s SLP,20.0 -s APP,1,FD0F1122,1,50,SWITCH_BINARY.SET,0,is_ack=True Sends a BinarySwitch.Set(255) then waits 20 seconds and sends a Binary  BinarySwitch.Set(0)
    """
def createTracerParser(subparsers):
    parserTracer = subparsers.add_parser('trace', help="Trace packages.")
    parserTracer.add_argument('-d', '--device', help="Device file (UNIX) or COM-port (WINDOWS)")
    parserTracer.add_argument('-b', '--baudrate', help="Device's baudrate.", default="230400")
    parserTracer.add_argument('-fr', '--frequency', choices=FREQ_TABLE_U7.keys(), help="Defines Z-Wave region (for MODEM mode ONLY).", default="EU")
    parserTracer.add_argument('-tp', '--tx_power', help="Defines Z-Wave tx power (for MODEM mode ONLY).", default="50")
    parserTracer.add_argument('-t', '--transport_type', choices=['MODEM', 'PTI'], default="PTI", help="Select needed transport protocol")
    parserTracer.add_argument('-i', '--input', default=None, help="Imports specified file instead of device. Utility supports *.rtp, *.json, *.zlf files.")
    parserTracer.add_argument('-f', '--filter', default=None, help="Filters data. ")
    parserTracer.add_argument('-ir', '--input_reencode', nargs='?', type=bool, const=True, default=False, help="Reencodes incoming data during print")
    parserTracer.add_argument('-o', '--output', default=None, help="Dumps all received packages to specified file")
    parserTracer.add_argument('-mp', '--max_packages', default=None, help="Stops when the packet counter reaches the set value")
    parserTracer.add_argument('-mt', '--max_time', default=None, help="Stops after reaching the specified time interval")
    parserTracer.add_argument('-p', '--profile', default=None, help="JSON file with Z-Wave protocol descriptions.")
    parserTracer.add_argument('-s', '--send',  default=[], action='append', help=send_help)
    parserTracer.add_argument('-r', '--raw_mode', choices=["off","payload","full","complex","hex_app"], help="Defines the raw data printing mode. \"off\" - data is disabled, \"payload\" - only payload (starting from the application-level command class), \"full\" - print the entire package as it is, \"complex\" - print the package and then its payload in parentheses,  \"hex_app\" - hexadecimal payload data only", default="payload")
    parserTracer.add_argument('-dt', '--device_type', choices=["auto","z-uno","sapi"], help="Selects device type", default="auto")
    parserTracer.add_argument('-nab', '--no_auto_baud', nargs='?', type=bool, const=True, default=False, help="Don't use auto baud detection. Use precise baudrate. Option is useful for devices without #DTR pin.")
    # SerialAPIUtilities.DETECT_MODE_ZUNO
    parserTracer.set_defaults(func=traceFunc)
    return parserTracer

if __name__ == "__main__":
    def dummyFunc(args):
        print("*** Platform: %s Version: %s ***"%(platform.system(), MY_VERSION))
    
    def Main():
        zmeSetupLogging("ZMECLIRadioTools", True, True)
        logging.debug("\nStarting on %s.\nARGS:%s\nVERSION:%s MD5:%s" % (
            platform.system(), ' '.join(sys.argv), MY_VERSION, "-"))
        parser = argparse.ArgumentParser(description='ZWave>ME PTI Tracer tool for 7th generation. \n Welcome :)')
        parser.set_defaults(func=dummyFunc)
        subparsers = parser.add_subparsers()
        createTracerParser(subparsers)
        addAllianceXMLConverterParser(subparsers)
        args = parser.parse_args()
        args.func(args)

    Main()