import time
import zlib
from common.zme_aux import *
from zwave.zme_zwave_encap_parsers import *
from zwave.zme_zwave_profile import *
from zwave.zme_zwave_stat import ZWaveStatCollector
from zlfdump import ZlfDump

ENCAP_LIST = [ZWaveMultichannel(), ZWaveCRC16(), ZWaveSecurityS0(), ZWaveSecurityS2(), ZWaveSupervision(), ZWaveMulticommand(), ZWaveTransportService()]

class ZWaveTransportEncoder:

    SECURITY_LEVEL_NONE = 0
    SECURITY_LEVEL_S2_UNAUTH = 1
    SECURITY_LEVEL_S2_AUTH = 2
    SECURITY_LEVEL_S2_ACCESS = 3
    SECURITY_LEVEL_S0 = 4
    SECURITY_LEVEL_S2_UNDETECT = 0x10

    PKG_TYPE_SINGL = 0x01
    PKG_TYPE_MULTI = 0x02
    PKG_TYPE_ACK = 0x03
    PKG_TYPE_FLOOD = 0x04
    PKG_TYPE_EXPLR = 0x05
    PKG_TYPE_ROUTED = 0x8
    PKG_TYPE_BEAM_START = 0x1FF
    PKG_TYPE_BEAM_STOP = 0x2FF
    PKG_TYPE_MAP = {PKG_TYPE_SINGL:"SINGL", PKG_TYPE_MULTI:"MULTI", PKG_TYPE_ACK:"ACK", PKG_TYPE_FLOOD:"FLOOD", PKG_TYPE_EXPLR:"EXPLR", PKG_TYPE_ROUTED:"ROUTED"}
    def __init__(self, payload_encoder, encap_list=ENCAP_LIST):
        self._pkg_index = 0
        self._encap_parser_set = {}
        self._encap_parser_order = {}
        for c in encap_list:
            self.addEncapParser(c)
        self._payload_encoder = payload_encoder#ZWaveDataEncoder(profile_name)
    def addEncapParser(self, encap_obj):
        encap_obj.setExtDataHolder(encap_obj)
        key = encap_obj.getCommandClassKey()
        if isinstance(key, list):
            for k in key:
                self._encap_parser_set[k] = encap_obj
                self._encap_parser_order[len(self._encap_parser_set)] = k
        else:
            self._encap_parser_set[key] = encap_obj
            self._encap_parser_order[len(self._encap_parser_set)] = key

    

    @staticmethod
    def checkPayloadCRC(pkg, b_fullspeed):
        d = pkg["raw"] 
        crc = 0
        if not b_fullspeed:
            crc = Checksum(d) 
        else:
            crc = calcSigmaCRC16(0x1D0F, d, 0, len(d))
        return crc
    def parseTransportSpecificPacket(self, d, md):
        if (len(d) > 0) and (d[0] == 0):
            md["app"] = [{"spelling":"NOP", "payload":d}]
            return True
        if md["is_routed"]:
            # Пакет с маршрутизацией - возможно, что чисто служебный
            if md["rt_ack"]:
                # Это Routed.Ack
                md["app"] = [{"spelling":"ROUTED ACK", "payload":d}]
                return True
            if md["rt_error"]:
                # Это Routed.Error
                md["app"] = [{"spelling":"ROUTED ERROR", "payload":d}]
                return True
        if md["type_id"] == ZWaveTransportEncoder.PKG_TYPE_EXPLR:
            # Это explorer-пакет
            if md["explr_cmd_typei"] == 0x02:
                md["app"] = [{"spelling":"EXPLORER SEARCH RESULT", "payload":d}]
                return True
        return False
    def parsePayloadEncap(self, d, md):
        md["__is_transport_spec"] = False
        if self.parseTransportSpecificPacket(d, md):
            md["__is_transport_spec"] = True
            return True
        if len(d) < 2:
            return False
        cc = d[0]
        if not ("app" in md):
            md["app"] = []
        if not ("encap_spelling" in md):
            md["encap_spelling"] = ""
        if len(d) > 2:
            encap_key = (d[0] << 8) + d[1] 
            if encap_key in self._encap_parser_set:
                encap_obj = self._encap_parser_set[encap_key]
                pl = None
                try:
                    pl, encap_md= encap_obj.decode(d, md)
                except:
                    logging.error("Encap parser exception:%s"%(traceback.format_exc()))
                    return False
                if pl == None:
                    if encap_md != None:
                        md.update(encap_md)
                    app_md = self._payload_encoder.decodeApplication(d)
                    if app_md != None:
                        app_md["payload"] = d
                        md["app"]+= [app_md]
                        return True
                    #print("APP.MD==None. Payload:%s"%(splitHexBuff(d)))
                    return False
                if len(md["encap_spelling"]) >0:
                    md["encap_spelling"] += "+"
                md["encap_spelling"] += encap_md["encap_type"]
                md.update(encap_md)
                all_ok = True
                for l in pl:
                    if not self.parsePayloadEncap(l, md):
                        all_ok = False
                return all_ok
        app_md = self._payload_encoder.decodeApplication(d)
        if app_md != None:
            app_md["payload"] = d
            md["app"]+= [app_md]
        else:
            #print("APP.MD==None (NE). Payload:%s"%(splitHexBuff(d)))
            md["app"]+= [{"spelling":"", "payload":d}]
        return True
    def fillBeamPkgDefault(self, pkg):
        pkg["src_ep"] = None
        pkg["dst_ep"] = None
        pkg["is_beam"] = True
        pkg["is_routed"] = False
        pkg["is_ack"] = False
        pkg["ext_header"] = None
        pkg["repeaters"] = None
        pkg["type_id"] = 0xFF
        pkg["sequence"] = 0
        pkg["type"] = "----"
        sp = "WAKEUP BEAM. STOP"
        if pkg["beam_start"]:
            sp = "WAKEUP BEAM. START"
        pkg["app"] = [{"spelling":sp, "payload":pkg["payload_raw"]}]
        pkg["__is_transport_spec"] = True
        pkg["is_valid"] = True

    def calc_routed_nodeid(self, src_nid, repeaters, direction, hopi):
        if direction:
            if hopi == 0x0F:
                return repeaters[0]
            hopi += 1
            if hopi == len(repeaters):
                return src_nid
        else:
            if hopi == 0x00:
                return src_nid
            hopi -= 1
        if hopi >= len(repeaters):
            return src_nid
        return repeaters[hopi]
    def calc_backward_rssi(self, repeaters, data):
        rssi_d = {}
        i = 0
        for r in repeaters:
            if i < len(data):
                if data[i] != 127:
                    rssi_d[r] = data[i]
            i += 1
        if len(rssi_d) != 0:
            return rssi_d
        return None

    def get_multicast_node(self, node_mask:bytes, max_node:int) -> list:
        multicast_node = []
        currentNodeId = 0x0
        while currentNodeId < max_node:
            bit = node_mask[(currentNodeId >> 0x3)]
            mask = ((0x1 << (currentNodeId % 0x8)))
            currentNodeId = currentNodeId + 0x1
            if (bit & mask) != 0x0:
                multicast_node = multicast_node + [currentNodeId]
            pass
        return (multicast_node)

    def fillBeamPackage(self, pkg, bStart=False, dst_node_id=None, home_sign=None):
        pkg["is_beam"] = False
        pkg["homeid"] = 0
        if home_sign != None:
            pkg["homeid"] = home_sign
        pkg["src_node_id"] = 0
        pkg["dst_node_id"] = 0
        if dst_node_id != None:
            pkg["dst_node_id"] = dst_node_id
        pkg["beam_start"] = bStart
        pkg["payload_raw"] =  pkg["raw"]
        self.fillBeamPkgDefault(pkg)
        pkg["is_valid"] = True
    def decode(self, raw_data, b_no_crc= True, b_fullspeed = False, ts = None, is_lr = False, region = ZlfDump.ZME_RADIOTOOLS_REGION_EU_STR):
        pkg = {}
        if ts == None:
            pkg["ts"] = time.time()
        else:
            pkg["ts"] = ts
        pkg["raw"] = bytearray(raw_data)
        pkg["is_beam"] = False
        hashable_data = list(raw_data)
        pkg["hash"] = zlib.crc32(bytearray(hashable_data))
        pkg["secure_level"] = ZWaveTransportEncoder.SECURITY_LEVEL_NONE
        # Проверяем, что это возможно WakeUp Beam
        if raw_data[0] == 0x55:
            pkg["homeid"] = 0
            pkg["src_node_id"] = 0
            pkg["dst_node_id"] = raw_data[1]
            if raw_data[2] & 0x01:
                 pkg["homeid"] = raw_data[3]
            pkg["beam_start"] = True
            pkg["payload_raw"] = raw_data[1:]
            self.fillBeamPkgDefault(pkg)
            pkg["is_valid"] = True
            return pkg
        elif raw_data[0] == 0x00:
            pkg["homeid"] = 0
            pkg["src_node_id"] = 0
            pkg["dst_node_id"] = 0
            pkg["beam_start"] = False
            pkg["payload_raw"] = raw_data[1:]
            self.fillBeamPkgDefault(pkg)
            pkg["is_valid"] = True
            return pkg
        pkg["homeid"] = 0
        pkg["src_ep"] = None
        pkg["dst_ep"] = None
        pkg["ext_header"] = None
        pkg["repeaters"] = None
        pkg["is_valid"] = False

        pkg["src_node_id"] = 0
        pkg["dst_node_id"] = 0
        pkg["type_id"] = 0
        pkg["is_ack"] = 0
        pkg["is_extended"] = 0
        pkg["sequence"] = 0
        pkg["lr_noize_floor"] = 0
        pkg["lr_tx_power"] = 0
        pkg["is_routed"] = 0
        pkg["type"] = "----"
        if not b_no_crc:
            if not b_fullspeed:
                if len(raw_data) < 2:
                    return pkg
                crc = Checksum(raw_data[:len(raw_data) - 1])
                if raw_data[len(raw_data) - 1] != crc:
                    return pkg
            else:
                if len(raw_data) < 3:
                    return pkg
                crc = calcSigmaCRC16(0x1D0F, raw_data, 0, len(raw_data) - 2)
                if ((raw_data[len(raw_data) - 2] << 8) | raw_data[len(raw_data) - 1]) != crc:
                    return pkg
        pkg["homeid"] = zme_costruct_int(raw_data, 4, False)
        pkg["length"] = (raw_data[7])
        if b_fullspeed:
            cut_index = -2
        else:
            cut_index = -1
        hashable_data = hashable_data[:cut_index]
        pkg["hash"] = zlib.crc32(bytearray(hashable_data))
        #logging.debug("---Raw Data:%s data.len:%d pkg.len:%d  no_crc:%s"%(splitHexBuff(pkg["raw"]), len(pkg["raw"]), pkg["length"], b_no_crc))
        if region == ZlfDump.ZME_RADIOTOOLS_REGION_US_LR1_STR or region == ZlfDump.ZME_RADIOTOOLS_REGION_US_LR2_STR or region == ZlfDump.ZME_RADIOTOOLS_REGION_US_END_STR:
            is_lr = True
        pkg["is_lr"] = is_lr
        if is_lr:
            pkg["src_node_id"] = (raw_data[4] << 4) + ((raw_data[5]>>4)&0x0F)
            pkg["dst_node_id"] = ((raw_data[5]&0x0F)<<8) + raw_data[6]
            pkg["type_id"] = (raw_data[8] & 0x0F)
            pkg["is_ack"] = ((raw_data[8] & 0x80) != 0)
            pkg["is_extended"] = ((raw_data[8] & 0x40) != 0)
            pkg["sequence"] = raw_data[9]
            pkg["lr_noize_floor"] = raw_data[10]
            pkg["lr_tx_power"] = raw_data[11]
            pkg["is_routed"] = False
            payload = hashable_data[12:] 
        elif region == ZlfDump.ZME_RADIOTOOLS_REGION_KR_STR or region == ZlfDump.ZME_RADIOTOOLS_REGION_JP_STR:
            pkg["type_id"] = (raw_data[5] & 0x0F)
            pkg["src_node_id"] = raw_data[4]
            pkg["is_speed_modify"] = ((raw_data[5] & 0x10) != 0)
            pkg["is_low_power"] = ((raw_data[5] & 0x40) != 0)
            pkg["is_ack"] = ((raw_data[5] & 0x80) != 0)
            if pkg["type_id"] == ZWaveTransportEncoder.PKG_TYPE_ROUTED:
                pkg["is_routed"] = True
            else:
                pkg["is_routed"] = False
            pkg["sequence"] = raw_data[8]
            pkg["dst_node_id"] = raw_data[9]
            if pkg["is_routed"]:
                pkg["rt_direction"] = ((raw_data[10] & 0x01) != 0)
                pkg["rt_ack"] = ((raw_data[10] & 0x02) != 0)
                pkg["rt_error"] = ((raw_data[10] & 0x04) != 0)
                pkg["rt_has_eheader"] = ((raw_data[6] & 0x80) != 0)
                pkg["rt_failed_hops"] = 0
                pkg["rt_hops"] = (raw_data[11]) & 0x0F
                if(len(raw_data) < 14):
                    return pkg
                repeater_count = (raw_data[11]>>4) & 0x0F
                pkg["repeaters"] = raw_data[12:12+repeater_count]
                if pkg["rt_has_eheader"]:
                    if(len(raw_data) < (14 + repeater_count)):
                        return pkg
                    #print("RAW:%s"%(splitHexBuff(raw_data, 64)))
                    ext_len = (raw_data[13+repeater_count] >> 4) & 0x0F
                    pkg["ext_header"] = raw_data[14+repeater_count:14+repeater_count+ext_len]
                    payload = hashable_data[14+repeater_count+ext_len:]
                    if pkg["rt_ack"]:
                        pkg["rt_backward_rssi"] = self.calc_backward_rssi(pkg["repeaters"], pkg["ext_header"])
                else:
                    payload = hashable_data[13+repeater_count:]
                pkg["rt_src_node_id"] = self.calc_routed_nodeid(pkg["src_node_id"],pkg["repeaters"], pkg["rt_direction"], pkg["rt_hops"])
            else:
                if pkg["type_id"] == ZWaveTransportEncoder.PKG_TYPE_EXPLR:
                    pkg["explr_cmd_typei"] =  raw_data[10] & 0x1F
                    pkg["explr_cmd_version"] =  (raw_data[10] >> 5) & 0x07
                    if pkg["explr_cmd_typei"] == 0x1:
                        payload = hashable_data[22:]
                    else:
                        payload = hashable_data[18:]
                elif pkg["type_id"] == ZWaveTransportEncoder.PKG_TYPE_MULTI:
                    multiNodeMaskLen = (raw_data[9] & 0x1F)
                    NodeMaskOffset = (raw_data[9] >> 0x5) * 0x4
                    mask_node = bytes(NodeMaskOffset * [0x0]) + raw_data[10:10 + multiNodeMaskLen]
                    pkg["dst_node_id_multicast"] = self.get_multicast_node(mask_node, 232)
                    payload = hashable_data[10 + multiNodeMaskLen:]
                else:
                    payload = hashable_data[10:]
            pass
        else:
            pkg["type_id"] = (raw_data[5] & 0x0F)
            pkg["src_node_id"] = raw_data[4]
            pkg["is_speed_modify"] = ((raw_data[5] & 0x10) != 0)
            pkg["is_low_power"] = ((raw_data[5] & 0x20) != 0)
            pkg["is_ack"] = ((raw_data[5] & 0x40) != 0)
            pkg["is_routed"] = ((raw_data[5] & 0x80) != 0)
            pkg["sequence"] = (raw_data[6] & 0x0F)
            pkg["dst_node_id"] = raw_data[8]
            if pkg["is_routed"]:
                pkg["rt_direction"] = ((raw_data[9] & 0x01) != 0)
                pkg["rt_ack"] = ((raw_data[9] & 0x02) != 0)
                pkg["rt_error"] = ((raw_data[9] & 0x04) != 0)
                pkg["rt_has_eheader"] = ((raw_data[9] & 0x08) != 0)
                pkg["rt_failed_hops"] = (raw_data[9] >> 4) & 0x0F
                pkg["rt_hops"] = (raw_data[10]) & 0x0F
                if(len(raw_data) < 12):
                    return pkg
                repeater_count = (raw_data[10]>>4) & 0x0F
                pkg["repeaters"] = raw_data[11:11+repeater_count]
                if pkg["rt_has_eheader"]:
                    if(len(raw_data) < (11 + repeater_count)):
                        return pkg
                    #print("RAW:%s"%(splitHexBuff(raw_data, 64)))
                    ext_len = (raw_data[11+repeater_count] >> 4) & 0x0F
                    pkg["ext_header"] = raw_data[12+repeater_count:12+repeater_count+ext_len]
                    payload = hashable_data[12+repeater_count+ext_len:]
                    if pkg["rt_ack"]:
                        pkg["rt_backward_rssi"] = self.calc_backward_rssi(pkg["repeaters"], pkg["ext_header"])
                else:
                    payload = hashable_data[11+repeater_count:]
                pkg["rt_src_node_id"] = self.calc_routed_nodeid(pkg["src_node_id"],pkg["repeaters"], pkg["rt_direction"], pkg["rt_hops"])
            else:
                if pkg["type_id"] == ZWaveTransportEncoder.PKG_TYPE_EXPLR:
                    pkg["explr_cmd_typei"] =  raw_data[9] & 0x1F
                    pkg["explr_cmd_version"] =  (raw_data[9] >> 5) & 0x07
                    if pkg["explr_cmd_typei"] == 0x1:
                        payload = hashable_data[21:]
                    else:
                        payload = hashable_data[17:]
                elif pkg["type_id"] == ZWaveTransportEncoder.PKG_TYPE_MULTI:
                    multiNodeMaskLen = (raw_data[8] & 0x1F)
                    NodeMaskOffset = (raw_data[8] >> 0x5) * 0x4
                    mask_node = bytes(NodeMaskOffset * [0x0]) + raw_data[9:9 + multiNodeMaskLen]
                    pkg["dst_node_id_multicast"] = self.get_multicast_node(mask_node, 232)
                    payload = hashable_data[9 + multiNodeMaskLen:]
                else:
                    payload = hashable_data[9:]
        pkg["is_valid"] = True
        if pkg["type_id"] in ZWaveTransportEncoder.PKG_TYPE_MAP:
            pkg["type"] = ZWaveTransportEncoder.PKG_TYPE_MAP[pkg["type_id"]]
        else:
            pkg["type"] = "----"
        #logging.debug("---Payload:%s"%(splitHexBuff(payload)))
        pkg["payload_raw"] = payload
        self.parsePayloadEncap(payload, pkg)
        if (len(pkg["payload_raw"]) > 2):
            if (pkg["payload_raw"][0] == 0x98) and ((pkg["payload_raw"][1] == 0x81)or(pkg["payload_raw"][1] == 0xC1)):
                pkg["secure_level"] = ZWaveTransportEncoder.SECURITY_LEVEL_S0
            elif (pkg["payload_raw"][0] == 0x9F) and (pkg["payload_raw"][1] == 0x03):
                if "s2_key_class" in pkg:
                    s2c = pkg["s2_key_class"]
                    if s2c >= ZWaveStatCollector.NETWORK_KEY_S2_LR_AUTH:
                        s2c -= ZWaveStatCollector.NETWORK_KEY_S0
                    pkg["secure_level"] = s2c
                else:
                    pkg["secure_level"] = ZWaveTransportEncoder.SECURITY_LEVEL_S2_UNDETECT
        # Обновляем статистику в пакете
        stat_collector = ZWaveStatCollector.getInstance()
        stat_collector.process(pkg)
        return pkg

    def decodeFreq(self, region:str, channeli:int) -> str:
        if (region == ZlfDump.ZME_RADIOTOOLS_REGION_US_LR1_STR or region == ZlfDump.ZME_RADIOTOOLS_REGION_US_LR2_STR or region == ZlfDump.ZME_RADIOTOOLS_REGION_US_END_STR) and channeli != 0x3:
            region = ZlfDump.ZME_RADIOTOOLS_REGION_US_STR
        return (region)

    def decode_new_version(self, raw_data, speed:int, ts:float, region:str, channeli:int, fCrcCheck=False, bParsePayload=True):
        region = self.decodeFreq(region, channeli)
        pkg = {}
        if ts == None:
            pkg["ts"] = time.time()
        else:
            pkg["ts"] = ts
        pkg["raw"] = bytearray(raw_data)
        pkg["is_beam"] = False
        hashable_data = list(raw_data)
        pkg["hash"] = zlib.crc32(bytearray(hashable_data))
        pkg["secure_level"] = ZWaveTransportEncoder.SECURITY_LEVEL_NONE
        # Проверяем, что это возможно WakeUp Beam
        if raw_data[0] == 0x55:
            pkg["homeid"] = 0
            pkg["src_node_id"] = 0
            pkg["dst_node_id"] = raw_data[1]
            if raw_data[2] & 0x01:
                 pkg["homeid"] = raw_data[3]
            pkg["beam_start"] = True
            pkg["payload_raw"] = raw_data[1:]
            self.fillBeamPkgDefault(pkg)
            pkg["is_valid"] = True
            return pkg
        elif raw_data[0] == 0x00:
            pkg["homeid"] = 0
            pkg["src_node_id"] = 0
            pkg["dst_node_id"] = 0
            pkg["beam_start"] = False
            pkg["payload_raw"] = raw_data[1:]
            self.fillBeamPkgDefault(pkg)
            pkg["is_valid"] = True
            return pkg
        pkg["homeid"] = 0
        pkg["src_ep"] = None
        pkg["dst_ep"] = None
        pkg["ext_header"] = None
        pkg["repeaters"] = None
        pkg["is_valid"] = False

        pkg["src_node_id"] = 0
        pkg["dst_node_id"] = 0
        pkg["type_id"] = 0
        pkg["is_ack"] = 0
        pkg["is_extended"] = 0
        pkg["sequence"] = 0
        pkg["lr_noize_floor"] = 0
        pkg["lr_tx_power"] = 0
        pkg["is_routed"] = 0
        pkg["type"] = "----"

        pkg["length"] = (raw_data[7])
        cut_index = 0
        crc_size = 1
        if(speed == 100000):
            crc_size = 2
        if((pkg["length"] > len(raw_data)) and 
           (pkg["length"] - len(raw_data)) > crc_size):
            return pkg
        if(pkg["length"] == len(raw_data)):
            # Это полный пакет содержащий CRC
            if speed == 9600 or speed == 40000:
                if len(raw_data) < 2:
                    return pkg
                crc = Checksum(raw_data[:len(raw_data) - 1])
                if raw_data[len(raw_data) - 1] != crc:
                    return pkg
                cut_index = -1
            else:
                if len(raw_data) < 3:
                    return pkg
                crc = calcSigmaCRC16(0x1D0F, raw_data, 0, len(raw_data) - 2)
                incoming_crc = (raw_data[len(raw_data) - 2] << 8) | raw_data[len(raw_data) - 1]
                if incoming_crc != crc:
                    return pkg
                cut_index = -2
        elif fCrcCheck:
            return pkg
        pkg["homeid"] = zme_costruct_int(raw_data, 4, False)
        if cut_index != 0:  
            hashable_data = hashable_data[:cut_index]
        pkg["hash"] = zlib.crc32(bytearray(hashable_data))
        #logging.debug("---Raw Data:%s data.len:%d pkg.len:%d  no_crc:%s"%(splitHexBuff(pkg["raw"]), len(pkg["raw"]), pkg["length"], b_no_crc))
        if region == ZlfDump.ZME_RADIOTOOLS_REGION_US_LR1_STR or region == ZlfDump.ZME_RADIOTOOLS_REGION_US_LR2_STR or region == ZlfDump.ZME_RADIOTOOLS_REGION_US_END_STR:
            is_lr = True
        else:
            is_lr = False
        pkg["is_lr"] = is_lr
        if is_lr:
            if(len(raw_data) < 13):
                return pkg
            pkg["src_node_id"] = (raw_data[4] << 4) + ((raw_data[5]>>4)&0x0F)
            pkg["dst_node_id"] = ((raw_data[5]&0x0F)<<8) + raw_data[6]
            pkg["type_id"] = (raw_data[8] & 0x0F)
            pkg["is_ack"] = ((raw_data[8] & 0x80) != 0)
            pkg["is_extended"] = ((raw_data[8] & 0x40) != 0)
            pkg["sequence"] = raw_data[9]
            pkg["lr_noize_floor"] = raw_data[10]
            pkg["lr_tx_power"] = raw_data[11]
            pkg["is_routed"] = False
            payload = hashable_data[12:] 
        elif region == ZlfDump.ZME_RADIOTOOLS_REGION_KR_STR or region == ZlfDump.ZME_RADIOTOOLS_REGION_JP_STR:
            if(len(raw_data) < 10):
                return pkg
            pkg["type_id"] = (raw_data[5] & 0x0F)
            pkg["src_node_id"] = raw_data[4]
            pkg["is_speed_modify"] = ((raw_data[5] & 0x10) != 0)
            pkg["is_low_power"] = ((raw_data[5] & 0x40) != 0)
            pkg["is_ack"] = ((raw_data[5] & 0x80) != 0)
            if pkg["type_id"] == ZWaveTransportEncoder.PKG_TYPE_ROUTED:
                pkg["is_routed"] = True
            else:
                pkg["is_routed"] = False
            pkg["sequence"] = raw_data[8]
            pkg["dst_node_id"] = raw_data[9]
            if pkg["is_routed"]:
                if(len(raw_data) < 14):
                    return pkg
                pkg["rt_direction"] = ((raw_data[10] & 0x01) != 0)
                pkg["rt_ack"] = ((raw_data[10] & 0x02) != 0)
                pkg["rt_error"] = ((raw_data[10] & 0x04) != 0)
                pkg["rt_has_eheader"] = ((raw_data[6] & 0x80) != 0)
                pkg["rt_failed_hops"] = 0
                pkg["rt_hops"] = (raw_data[11]) & 0x0F
                repeater_count = (raw_data[11]>>4) & 0x0F
                pkg["repeaters"] = raw_data[12:12+repeater_count]
                if pkg["rt_has_eheader"]:
                    if(len(raw_data) < (14 + repeater_count)):
                        return pkg
                    #print("RAW:%s"%(splitHexBuff(raw_data, 64)))
                    ext_len = (raw_data[13+repeater_count] >> 4) & 0x0F
                    if(len(raw_data) < (14 + repeater_count+ext_len)):
                        return pkg
                    pkg["ext_header"] = raw_data[14+repeater_count:14+repeater_count+ext_len]
                    payload = hashable_data[14+repeater_count+ext_len:]
                    if pkg["rt_ack"]:
                        pkg["rt_backward_rssi"] = self.calc_backward_rssi(pkg["repeaters"], pkg["ext_header"])
                else:
                    payload = hashable_data[13+repeater_count:]
                pkg["rt_src_node_id"] = self.calc_routed_nodeid(pkg["src_node_id"],pkg["repeaters"], pkg["rt_direction"], pkg["rt_hops"])
            else:
                if pkg["type_id"] == ZWaveTransportEncoder.PKG_TYPE_EXPLR:
                    if(len(raw_data) < 19):
                        return pkg
                    pkg["explr_cmd_typei"] =  raw_data[10] & 0x1F
                    pkg["explr_cmd_version"] =  (raw_data[10] >> 5) & 0x07
                    if pkg["explr_cmd_typei"] == 0x1:
                        if(len(raw_data) < 23):
                            return pkg
                        payload = hashable_data[22:]
                    else:
                        payload = hashable_data[18:]
                elif pkg["type_id"] == ZWaveTransportEncoder.PKG_TYPE_MULTI:
                    if(len(raw_data) < 11):
                        return pkg
                    multiNodeMaskLen = (raw_data[9] & 0x1F)
                    NodeMaskOffset = (raw_data[9] >> 0x5) * 0x4
                    if(len(raw_data) < (10 + multiNodeMaskLen)):
                        return pkg
                    mask_node = bytes(NodeMaskOffset * [0x0]) + raw_data[10:10 + multiNodeMaskLen]
                    pkg["dst_node_id_multicast"] = self.get_multicast_node(mask_node, 232)
                    
                    payload = hashable_data[10 + multiNodeMaskLen:]
                else:
                    payload = hashable_data[10:]
            pass
        else:
            if(len(raw_data) < 9):
                return pkg
            pkg["type_id"] = (raw_data[5] & 0x0F)
            pkg["src_node_id"] = raw_data[4]
            pkg["is_speed_modify"] = ((raw_data[5] & 0x10) != 0)
            pkg["is_low_power"] = ((raw_data[5] & 0x20) != 0)
            pkg["is_ack"] = ((raw_data[5] & 0x40) != 0)
            pkg["is_routed"] = ((raw_data[5] & 0x80) != 0)
            pkg["sequence"] = (raw_data[6] & 0x0F)
            pkg["dst_node_id"] = raw_data[8]
            if pkg["is_routed"]:
                if(len(raw_data) < 12):
                    return pkg
                pkg["rt_direction"] = ((raw_data[9] & 0x01) != 0)
                pkg["rt_ack"] = ((raw_data[9] & 0x02) != 0)
                pkg["rt_error"] = ((raw_data[9] & 0x04) != 0)
                pkg["rt_has_eheader"] = ((raw_data[9] & 0x08) != 0)
                pkg["rt_failed_hops"] = (raw_data[9] >> 4) & 0x0F
                pkg["rt_hops"] = (raw_data[10]) & 0x0F
                repeater_count = (raw_data[10]>>4) & 0x0F
                pkg["repeaters"] = raw_data[11:11+repeater_count]
                if pkg["rt_has_eheader"]:
                    if(len(raw_data) < (11 + repeater_count)):
                        return pkg
                    #print("RAW:%s"%(splitHexBuff(raw_data, 64)))
                    ext_len = (raw_data[11+repeater_count] >> 4) & 0x0F
                    pkg["ext_header"] = raw_data[12+repeater_count:12+repeater_count+ext_len]
                    payload = hashable_data[12+repeater_count+ext_len:]
                    if pkg["rt_ack"]:
                        pkg["rt_backward_rssi"] = self.calc_backward_rssi(pkg["repeaters"], pkg["ext_header"])
                else:
                    payload = hashable_data[11+repeater_count:]
                pkg["rt_src_node_id"] = self.calc_routed_nodeid(pkg["src_node_id"],pkg["repeaters"], pkg["rt_direction"], pkg["rt_hops"])
            else:
                if pkg["type_id"] == ZWaveTransportEncoder.PKG_TYPE_EXPLR:
                    if(len(raw_data) < 18):
                        return pkg
                    pkg["explr_cmd_typei"] =  raw_data[9] & 0x1F
                    pkg["explr_cmd_version"] =  (raw_data[9] >> 5) & 0x07
                    if pkg["explr_cmd_typei"] == 0x1:
                        if(len(raw_data) < 22):
                            return pkg
                        payload = hashable_data[21:]
                    else:
                        payload = hashable_data[17:]
                elif pkg["type_id"] == ZWaveTransportEncoder.PKG_TYPE_MULTI:
                    multiNodeMaskLen = (raw_data[8] & 0x1F)
                    NodeMaskOffset = (raw_data[8] >> 0x5) * 0x4
                    if(len(raw_data) < (9+multiNodeMaskLen)):
                        return pkg
                    mask_node = bytes(NodeMaskOffset * [0x0]) + bytes(raw_data[9:9 + multiNodeMaskLen])
                    pkg["dst_node_id_multicast"] = self.get_multicast_node(mask_node, 232)
                    payload = hashable_data[9 + multiNodeMaskLen:]
                else:
                    payload = hashable_data[9:]
        pkg["is_valid"] = True
        if pkg["type_id"] in ZWaveTransportEncoder.PKG_TYPE_MAP:
            pkg["type"] = ZWaveTransportEncoder.PKG_TYPE_MAP[pkg["type_id"]]
        else:
            pkg["type"] = "----"
        #logging.debug("---Payload:%s"%(splitHexBuff(payload)))
        pkg["payload_raw"] = payload
        if bParsePayload:
            self.parsePayloadEncap(payload, pkg)
            if (len(pkg["payload_raw"]) > 2):
                if (pkg["payload_raw"][0] == 0x98) and ((pkg["payload_raw"][1] == 0x81)or(pkg["payload_raw"][1] == 0xC1)):
                    pkg["secure_level"] = ZWaveTransportEncoder.SECURITY_LEVEL_S0
                elif (pkg["payload_raw"][0] == 0x9F) and (pkg["payload_raw"][1] == 0x03):
                    if "s2_key_class" in pkg:
                        s2c = pkg["s2_key_class"]
                        if s2c >= ZWaveStatCollector.NETWORK_KEY_S2_LR_AUTH:
                            s2c -= ZWaveStatCollector.NETWORK_KEY_S0
                        pkg["secure_level"] = s2c
                    else:
                        pkg["secure_level"] = ZWaveTransportEncoder.SECURITY_LEVEL_S2_UNDETECT
            # Обновляем статистику в пакете
            stat_collector = ZWaveStatCollector.getInstance()
            stat_collector.process(pkg)
        return pkg
    def encode(self, pkg, b_fullspeed = False, b_no_crc = True):
        raw_data = []
        if not ( "homeid" in pkg):
            return None
        if not ("src_node_id" in pkg):
            return None
        if not ( "dst_node_id" in pkg):
            return None
        if not ( "payload" in pkg):
            return None
        type_id = 0x01
        if "type_id" in pkg:
            type_id = pkg["type_id"] & 0x0F
        sequence = 1
        if "sequence" in pkg:
            sequence = pkg["sequence"] & 0x0F
        raw_data += zme_int_toarr(pkg["homeid"], 4, bInv=True)
        raw_data += [pkg["src_node_id"]]
        encoded_typeid = type_id
        if ("is_ack" in pkg) and (pkg["is_ack"]):
            encoded_typeid |= 0x40
        if ("is_low_power" in pkg) and (pkg["is_low_power"]):
            encoded_typeid |= 0x20
        if ("is_speed_modify" in pkg) and (pkg["is_speed_modify"]):
            encoded_typeid |= 0x10
        raw_data += [encoded_typeid]
        pl = pkg["payload"]
        for order in self._encap_parser_order:
            key = self._encap_parser_order[order]
            encap_encoder = self._encap_parser_set[key]
            pl = encap_encoder.encode(pl, pkg)
        length = len(pl) + 10 # CRC8 included !
        if b_fullspeed:
            length += 1
        if type_id == 1:
            raw_data += [sequence]
            raw_data += [length]
            raw_data += [pkg["dst_node_id"]]
        raw_data += pl
        if not b_no_crc:
            crc = ZWaveTransportEncoder.checkPayloadCRC(pkg, b_fullspeed)
            if b_fullspeed:
                raw_data += [(crc >> 8) & 0xFF]
            raw_data += [crc & 0xFF]
        return raw_data



        



