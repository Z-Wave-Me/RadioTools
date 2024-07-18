from zme_modemhost import ZMEModemListener
from common.zme_aux import *
from common.zme_sapi import *
from common.zme_serialport import Port
from zwave.zme_zwave_protocol import ZWaveDataEncoder
import os
import argparse
import logging
import colorama
from zme_threads import GracefulTerminator
from zme_web_sevices import ZMELicenseService
from threading import Lock

MY_VERSION = 0.1
RETRY_PKG_TIME = 0.015
g_devices = []
def ts2Text(ts):
    ms = int((ts - int(ts)) * 1000)
    dt_text =  datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S"+".%03d"%(ms))
    return dt_text

def filterPackage(pkg, homeid, source_nodes, destnation_nodes):
    if(pkg["homeid"] != homeid):
        print("---HW Filter fails. Another HOMEID:%08x"%(pkg["homeid"]))
        return False
def extractRAWData(pkg):
    last_index = -1
    if pkg["speed"] == 100000:
       last_index = -2
    out_data = [pkg["channeli"]]
    out_data += pkg["raw"][:last_index] # Crop the crc
    return out_data
def __getAckedData(key,cfg):
    d = None
    cfg["lock"].acquire()
    if key in cfg["lst"]:
        d = list(cfg["lst"][key])
    cfg["lock"].release()
    return d
def __setAckedData(key,cfg, d):
    cfg["lock"].acquire()
    cfg["lst"][key] = list(d)
    cfg["lock"].release()
def __clearAckedData(key,cfg):
    cfg["lock"].acquire()
    if key in cfg["lst"]:
        del cfg["lst"][key]
    cfg["lock"].release()
def __extractAckKeys(cfg):
    keys = []
    cfg["lock"].acquire()
    keys = list(cfg["lst"].keys())
    cfg["lock"].release()
    return keys
def processIncomingAck(pkg, cfg):
    seq =  pkg["sequence"] 
    dst = pkg["dst_node_id"]
    pkg_key = "%d-%d"%(dst, seq)
    # Is it ACK?
    # It's a simple non-routed ACK
    if (pkg["type"] == "ACK") or (("rt_ack" in pkg) and pkg["rt_ack"]):
        ack_data = __getAckedData(pkg_key, cfg)
        if ack_data == None:
            logging.warning("Seems we don't have a data for this ACK:%s"%(pkg))
        __clearAckedData(pkg_key, cfg)
        return True
    return False
def _makeRawWUPBeamPackage(homeid, dst_nodeid, duration=1100):
    home_id_hash = _calcHomeIdHash(homeid)
    body = [0x55, dst_nodeid, home_id_hash, 0x55] + [0x55]*20 
    ret = [0x81,(duration >> 8) & 0xFF, (duration & 0xFF)]
    ret += body
    # for i in range(3):
    #     ret += body
    # ret += [0x00]*24
    return ret
dbg_beam_time_send=0
def _calcHomeIdHash(homeid):
    arr = zme_int_toarr(homeid, 4)
    hash_result = 0xFF
    for a in arr:
        hash_result = hash_result ^ a
    return hash_result

def _makeRawAckPackage(pkg):
    channeli = pkg["channeli"]
    raw_data = [channeli]
    raw_data += zme_int_toarr(pkg["homeid"], 4, bInv=True)
    raw_data += [pkg["dst_node_id"]]
    if pkg["is_routed"]:
        # It's a routed packed
        raw_data += [0x81] # type == packet (0x01) + routed flag (0x80)
        raw_data += [pkg["sequence"]]
        if channeli == 0: # length
            raw_data += [0x13] # because of 2 byte crc
        else:
            raw_data += [0x12]
        raw_data += [pkg["src_node_id"]]
        raw_data += [0x0B] # dir == back (0x01) | RTACK (0x02) | EXTHDR (0x08)
        num_repeaters = len(pkg["repeaters"])
        raw_data += [(num_repeaters << 0x04) & 0xF0]
        raw_data += pkg["repeaters"]
        raw_data += [0x41, 0x7F, 0x7F, 0x7F, 0x7F] # Extheader size + empty backward rssi
    else:
        raw_data += [0x03] # type == ACK (0x03) 
        raw_data += [0x80 | pkg["sequence"] & 0x0F]
        if channeli == 0: # length
            raw_data += [0x0B] # because of 2 byte crc
        else:
            raw_data += [0x0A]
        raw_data += [pkg["src_node_id"]]
    return  raw_data   
def transmitPackage(src_hub, dst_hub, cfg, pkg):
    output_data = extractRAWData(pkg)
    seq =  pkg["sequence"] 
    pkg_key = "%d-%d"%(pkg["src_node_id"], seq)
    # Do we need to send ACK?
    if pkg["dst_node_id"] != 0xFF and pkg["is_ack"]:
        ack_data = __getAckedData(pkg_key, cfg)
        if ack_data != None:
            print("-DUP")
            return
        ack_data = [time.time(), output_data, 3, pkg["dst_node_id"]]
        __setAckedData(pkg_key, cfg, ack_data)
        ackpkg = _makeRawAckPackage(pkg)
        print("\t<<  FAKE ACK:%s "%(splitHexBuff(ackpkg)))
        src_hub.sendMessage(ackpkg)
    dst_hub.sendMessage(output_data)
def processIncomingAckTmr(cfg, hub, main_cfg, name):
    keys = __extractAckKeys(cfg)
    #print("keys:%s"%(keys))
    # testcode
    global dbg_beam_time_send
    # TEST CASE 1
    # if name =="EU subnetwork" and (time.time() - dbg_beam_time_send) > 60:
    #     beam_pkg = _makeRawWUPBeamPackage(main_cfg["homeid"], 5)
    #     print("\t<< %s (%s) SEND TEST BEAM PKG:%s "%(ts2Text(time.time()), name, splitHexBuff(beam_pkg)))
    #     hub.sendMessage(beam_pkg)
    #     time.sleep(1.3)
    #     #test_pkg = {"sequence":3, "channeli":0,  "is_routed":False, "homeid":main_cfg["homeid"],  "src_node_id":1, "dst_node_id":7}
    #     #ackpkg = _makeRawAckPackage(test_pkg)
    #     #hub.sendMessage(ackpkg)
    #     # D6 19 CD D9 01 41 05 0B 05 00 6F
    #     nop_pkg = [2, 0xD6, 0x19, 0xCD, 0xD9, 0x01, 0x41, 0x05, 0x0B, 0x05, 0x00]
    #     hub.sendMessage(nop_pkg)
    #     dbg_beam_time_send = time.time()
    for k in keys:
        #print("Processing ACK key:%s"%(k)) 
        d = __getAckedData(k, cfg)
        if d != None:
            start_time = d[0]
            ct = time.time()
            if (ct - start_time) > RETRY_PKG_TIME:
                pkg = d[1]
                dst_node_id = d[3]
                is_flirs = dst_node_id in  main_cfg["flirs_nodes"]
                if is_flirs:
                    beam_pkg = _makeRawWUPBeamPackage(main_cfg["homeid"], dst_node_id)
                    print("\t<< %s (%s) SEND BEAM PKG:%s "%(ts2Text(time.time()), name, splitHexBuff(beam_pkg)))
                    hub.sendMessage(beam_pkg)
                    time.sleep(1.3)
                print("\t<< %s (%s) RESEND PKG:%s "%(ts2Text(time.time()), name, splitHexBuff(pkg)))
                hub.sendMessage(pkg)
                if is_flirs:
                    time.sleep(0.2)
                d[0] = time.time()
                d[2] -= 1
                if d[2] != 0:
                    __setAckedData(k, cfg, d)
                else:
                    __clearAckedData(k, cfg)

def _getPkgCurrentDST(pkg):
    if pkg["repeaters"] == None:
        return pkg["dst_node_id"]
    for i in range(len(pkg["repeaters"])):
        r = pkg["repeaters"][i]
        if r == pkg["rt_src_node_id"]:
            break
    if i < (len(pkg["repeaters"]) - 1):
        i += 1
        return pkg["repeaters"][i]
    return pkg["dst_node_id"]
def _isExtHop(pkg, dst_list):
    dst = _getPkgCurrentDST(pkg)
    return (dst in dst_list)
def pkgHandler(ud, pkg):
    my_index = ud[0]
    hub_devices = ud[1]
    cfg = ud[2]
    subn_name = cfg["hubs"][my_index]["name"]

    if(pkg["dir"] != 1):
        return 
    # Filter by homeid
    if(pkg["homeid"] != cfg["homeid"]):
        print("---HW Filter fails. Another HOMEID:%08x"%(pkg["homeid"]))
        return
    print(">> [%s] (%s) HOMEID:%08X SRC:%d DST:%d RAW:%s"%(ts2Text(time.time()),subn_name, pkg["homeid"], pkg["src_node_id"], pkg["dst_node_id"], splitHexBuff(pkg["raw"])))
    #print(">> [%s ; %s] (%s) HOMEID:%08X SRC:%d DST:%d RAW:%s"%(ts2Text(pkg["ts"]), ts2Text(time.time()),subn_name, pkg["homeid"], pkg["src_node_id"], pkg["dst_node_id"], splitHexBuff(pkg["raw"])))
    # Filter packages outside from hub control set
    if not(pkg["src_node_id"] in cfg["hubs"][my_index]["nodes"]):
        print("   (- SRC NODEID )")
        return
    if processIncomingAck(pkg, cfg["hubs"][my_index]):
        print("   (- ACK )")
        return
    # Filter by Destination NodeId, trying to find hub
    found = False
    for i in range(len(hub_devices)):
        if i == my_index:
            continue # Selfloop exclusion
        subn_out_name = cfg["hubs"][i]["name"]
        if(pkg["is_beam"]):
            # if(pkg["dst_node_id"] != 0):
            #     if not (pkg["dst_node_id"] in cfg["hubs"][i]["nodes"]):
            #         continue
            # print("\t<< BEAM %08.4f (%s) RAW:%s"%(time.time(), subn_out_name, splitHexBuff(pkg["raw"])))
            # transmitPackage(hub_devices[my_index], hub_devices[i], cfg["hubs"][i], pkg);
            continue
        # Broadcast package
        if (pkg["dst_node_id"] == 0xFF):
            print("\t<< BROADC. %08.4f (%s) RAW:%s"%(time.time(), subn_out_name, splitHexBuff(pkg["raw"])))
            transmitPackage(hub_devices[my_index], hub_devices[i], cfg["hubs"][i], pkg);
            continue
        # Singlecast
        if (_isExtHop(pkg, cfg["hubs"][i]["nodes"])):
            print("\t<< %08.4f (%s) RAW:%s"%(time.time(), subn_out_name, splitHexBuff(pkg["raw"])))
            transmitPackage(hub_devices[my_index], hub_devices[i], cfg["hubs"][i], pkg);
            found = True
            break # no crosses inside the subsets
    if not found:
        print("   (- DST NODEID )")
def ModemStateListener(ud, s, dta):
    my_index = ud[0]
    hub_devices = ud[1]
    cfg = ud[2]
    subn_name = cfg["hubs"][my_index]["name"]
    #logging.info("MODEM STATE:%s"%(s))
    if s == ZMEModemListener.MODE_INITED:
        printInfo(">>> Started %s@%s"%(cfg["hubs"][my_index]["name"], cfg["hubs"][my_index]["uuid"]))
        hub_devices[my_index].setHomeIdFilters([cfg["homeid"]])
        #g_setup["modem_started"] = True
    elif s == ZMEModemListener.MODE_IDLED:
        processIncomingAckTmr(cfg["hubs"][my_index], hub_devices[my_index], cfg, subn_name)
    elif s == ZMEModemListener.MODE_STOPPED:
        printInfo("MODEM \"%s\" has been terminated"%(cfg["hubs"][my_index]["name"]))
        hub_devices[my_index].stopLoop()
    elif s == ZMEModemListener.MODE_NOT_SUPPORTED_LICENSE:
        printError("MODEM \"%s\" mode is not supported for your device!"%(cfg["hubs"][my_index]["name"]))
        lic_svc = ZMELicenseService()
        uuid = "%x"%(dta["chip_uuid"])
        printInfo("\nYou can purchase a license for your device by following the link %s%s%s\n"%(colorama.Fore.RED, lic_svc.webUIURL(uuid), colorama.Fore.WHITE))
        hub_devices[my_index].stopLoop()
def trunsmissionFunc(args):
    DEVICE_TYPE={"auto":SerialAPIUtilities.DETECT_MODE_AUTO, 
                "z-uno":SerialAPIUtilities.DETECT_MODE_ZUNO,
                "sapi":SerialAPIUtilities.DETECT_MODE_SAPI}
    printInfo("Transmission Bridge Service")
    printStatus("Loading configuration file: \"%s\""%(args.config))
    if not os.path.isfile(args.config):
        printError("Configuration file doesn't exist!")
        return 10
    cfg = loadJSONData(args.config)
    if cfg == None:
        printError("Can't parse configuration file!")
        return 11
    finallizeStatus()
    rc_path =  baseDirectoryPath(os.path.abspath(__file__)) + os.sep  #+"rc"+ os.sep
    if args.profile != None:
        if not os.path.isfile(args.profile):
            printError("Wrong profile %s. File doesn't exist!"%(args.profile))
            sys.exit(1)
        profile = args.profile
    else:
        profile = rc_path + "zme_zwave_profile.json"
    data_encoder = ZWaveDataEncoder(profile)
    cfg["homeid"] = int(cfg["homeid"], 16)
    printStatus("Create a serial map by means of WebSerial")
    serial_map = {}
    for host in cfg["hosts"]:
        lst = Port.portList(host["ip"])
        for entity in lst:
            uuid = entity["uuid"]
            serial_name = entity["name"]
            if not uuid in serial_map:
                serial_map[uuid] = []
            serial_map[uuid] += [serial_name]
    finallizeStatus()
    printStatus("Initializing hubs")
    devices = []
    gt = GracefulTerminator()
    i = 0
    for ep in cfg["hubs"]:
        region = cfg["region"]
        tx_power = cfg["tx_power"]
        ep_uuid = ep["uuid"]
        ep_index = 0
        ep["lst"] = {}
        ep["lock"] = Lock()
        if "index" in ep:
            ep_index = ep["index"]
        baudrate = 230400
        if "baudrate" in  ep:
            baudrate = ep["baudrate"]
        dtype = "z-uno"
        if "device_type" in  ep:
            dtype = ep["device_type"]
        if dtype in DEVICE_TYPE:
            dtype = DEVICE_TYPE[dtype]
        else:
            printError("Unknown device type for uuid:%s (%s)"%(ep_uuid, dtype))
            return 100
        if "region" in ep:
            region = ep["region"]
        if "tx_power" in ep:
            tx_power = ep["tx_power"]
        if not ep_uuid in serial_map:
            printError("Can't find endpoint with uuid:%s"%(ep_uuid))
            return 100
        if ep_index >= len(serial_map[ep_uuid]):
            printError("Can't find wrong index (%d) of serial port for uuid (%s). (MAX=%d)"%(ep_index, ep_uuid, len(serial_map[ep_uuid])))
            return 101
        j=0
        if "port_prefix" in ep:
            port_name = None
            for pn in serial_map[ep_uuid]:
                if pn.startswith(ep["port_prefix"]):
                    if j == ep_index:
                        port_name = pn
                    j += 1
            if port_name == None:
                printError("Can't find port with prefix:%x index (%d) of serial port for uuid (%s). (MAX=%d)"%(ep["port_prefix"], ep_index, ep_uuid, len(serial_map[ep_uuid])))
                return 102
        else:
            port_name = serial_map[ep_uuid][ep_index]
        dev = ZMEModemListener(port_name, data_encoder, pkgHandler, baudrate, ModemStateListener, dev_type=dtype)
        if dev == None:
            printError("Can't start modem device: %s (%s)"%(ep["uuid"], ep["name"]))
        dev.setUserData([i, devices, cfg])
        dev.setLatency(0.0005)
        dev.setPayloadParseFlag(False)
        dev.setTxLoopBack(False)
        devices += [dev]
        gt.addThread(dev)
        dev.start()
        dev.connect(region, tx_power)
        i += 1
    while not gt.wasStopped():
        time.sleep(0.1)
    return 0


def createTransmissionParser(subparsers):
    parserTransmission = subparsers.add_parser('svc', help="Starts transmission service.")
    parserTransmission.add_argument('-c', '--config', help="Defines utility configuration file", default="transmission.json")
    parserTransmission.add_argument('-p', '--profile', default=None, help="JSON file with Z-Wave protocol descriptions.")
    parserTransmission.set_defaults(func=trunsmissionFunc)
    return parserTransmission
def portListFunc(args):
    host = args.host
    print("%s [PORTS HOST:%s] %s"%("-"*40, host, "-"*40))
    lst = Port.portList(host)
    print("%-38s %-8s %-8s %-50s"%("UUID", "VID", "PID", "NAME"))
    for l in lst:
        print("%-38s %-8s %-8s %-50s"%(l["uuid"], l["vid"], l["pid"], l["name"]))
if __name__ == "__main__":
    def dummyFunc(args):
        print("*** Platform: %s Version: %s ***"%(platform.system(), MY_VERSION))
    def Main():
        zmeSetupLogging("ZMETransmissionTool", True, True)
        logging.debug("\nStarting on %s.\nARGS:%s\nVERSION:%s" % (
            platform.system(), ' '.join(sys.argv), MY_VERSION))
        parser = argparse.ArgumentParser(description='ZWave>ME Transmission. \n Welcome :)')
        parser.set_defaults(func=dummyFunc)
        subparsers = parser.add_subparsers()
        createTransmissionParser(subparsers)
        parserPorts = subparsers.add_parser('ports', help="Prints port list.")
        parserPorts.add_argument('-hs', '--host', help="Set the destination host ip-address", default=None)
        parserPorts.set_defaults(func=portListFunc)
        args = parser.parse_args()
        args.func(args)

    Main()