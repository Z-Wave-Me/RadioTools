import time
import traceback
from zwave.zme_zwave_stat import ZWaveStatCollector
from zwave.zme_zwave_s2crypto import S2CryptoProvider
from common.zme_aux import *
import copy
class ZWaveEncapParser:
    def __init__(self, ext_data=None):
        self._ext_dh = ext_data
        self.ClsID = 0x0000
    def setExtDataHolder(self, dataholder):
        self._ext_dh = dataholder
    def decode(self, raw_data, net_params=None):
        payload_list = None
        md = {}
        return payload_list, md
    def encode(self, payload, params):
        encap_data = None
        return encap_data
    def getCommandClassKey(self):
        return self.ClsID


class  ZWaveMultichannel(ZWaveEncapParser):
    def __init__(self, ext_data=None):
        ZWaveEncapParser.__init__(self, ext_data)
        self.ClsID = 0x600D
        self.ParamNameLst = []
    def decode(self, raw_data, net_params=None):
        if len(raw_data) < 5:
            return None, None
        payload_list = [raw_data[4:]]
        md = {"src_ep":raw_data[2], "dst_ep":raw_data[3], "encap_type":"MCH"}
        return payload_list, md
    def encode(self, payload, params=None):
        src_nid = 0
        dst_nid = 0
        if isinstance(params, list):
            if len(params) > 0:
                src_nid = params[0]
            if len(params) > 1:
                dst_nid = params[1]
        elif isinstance(params, dict):
            if ("src_ep" in params) and (params["src_ep"] != None):
                src_nid = params["src_ep"]
            if ("dst_ep" in params) and (params["dst_ep"] != None):
                dst_nid = params["dst_ep"]
        if (src_nid != 0) or (dst_nid != 0):
            return [0x60, 0x0d, src_nid, dst_nid] + payload
        return payload

class  ZWaveCRC16(ZWaveEncapParser):
    def __init__(self, ext_data=None):
        ZWaveEncapParser.__init__(self, ext_data)
        self.ClsID = 0x5601
        self.ParamNameLst = []
    def decode(self, raw_data, net_params=None):
        if len(raw_data) < 6:
            return None, None
        crc_index = len(raw_data) - 2
        crc16 = (raw_data[crc_index] << 8) + raw_data[crc_index+1]
        payload = raw_data[2:crc_index]
        calculated = calcSigmaCRC16(0x1D0F, payload, 0, len(payload))
        logging.debug("ENCAP: E_CRC16:%04x C_CRC16:%04x payload:%s pkg:%s"%(crc16, calculated, splitHexBuff(payload), raw_data))
        md = {"crc16_value":crc16, "crc16_valid":(calculated == crc16), "encap_type":"CRC16"}
        return [payload], md
    def encode(self, payload, params=None):
        encap = False
        if isinstance(params, list):
            if len(params) > 0:
                encap = params[0] 
        elif isinstance(params, dict):
            if "crc16_encap" in params:
                encap = params["crc16_encap"]
        if encap:
            crc16 = calcSigmaCRC16(0x1D0F, payload, 0, len(payload))
            return [0x56, 0x01] + payload + [crc16 >> 8, crc16 & 0xFF]
        return payload

class  ZWaveSecurityS0(ZWaveEncapParser):
    S0_DEFAULT_NETWORK_KEY = [0x00]*16
    SO_PACKET_PREFIX_LEN = 10
    SO_PACKET_POSTFIX_LEN = 9
    S0_PACKET_ADV_PAYLOAD = SO_PACKET_PREFIX_LEN + SO_PACKET_POSTFIX_LEN
    S0_CMDFLAG_SEQUENCED = 0x10
    S0_CMDFLAG_SECOND_PACK = 0x20
    S0_CMDFLAG_SEQMASK = (S0_CMDFLAG_SEQUENCED | S0_CMDFLAG_SECOND_PACK)
    
    S0_DECODE_ERROR_NO_KEY = -1
    S0_DECODE_ERROR_NO_NONCE = -2
    S0_DECODE_ERROR_WRONG_MESSAGE = -3

    
    def __init__(self, ext_data=None):
        ZWaveEncapParser.__init__(self, ext_data)
        self.ClsID = [0x9881, 0x98C1]
        self.ParamNameLst = []
        self._prev_sequenced = {}
    def _decryptS0Message(self, raw_data, receiver_nonce, src_node_id, dst_node_id, net_key):
        packet_text = splitHexBuff(raw_data)
        payload_len = len(raw_data) - ZWaveSecurityS0.S0_PACKET_ADV_PAYLOAD
        sender_nonce = raw_data[2:2+8]
        receiver_nonce_key = raw_data[ZWaveSecurityS0.SO_PACKET_PREFIX_LEN + payload_len]
        sender_mac   = raw_data[ZWaveSecurityS0.SO_PACKET_PREFIX_LEN + payload_len + 1:ZWaveSecurityS0.SO_PACKET_PREFIX_LEN + payload_len + 9]
        logging.info("S0 NONCE (RI:%02x Nonce:%s)"%(receiver_nonce_key, splitHexBuff(receiver_nonce)))
        if receiver_nonce[0] != receiver_nonce_key:
            logging.info("S0 NONCE mismatches (RI:%02x Nonce:%s) for node:%d. Can't decrypt packet:%s"%(receiver_nonce_key, splitHexBuff(receiver_nonce), src_node_id, packet_text))
            return None
        Ka, Ke = makeS0Keys(net_key)
        logging.debug("S0 Keys Ka:%s Ke:%s"%(splitHexBuff(Ka), splitHexBuff(Ke)))
        iv = sender_nonce
        iv += receiver_nonce
        crypted_payload = raw_data[ZWaveSecurityS0.SO_PACKET_PREFIX_LEN:ZWaveSecurityS0.SO_PACKET_PREFIX_LEN+payload_len]
        mac_data = [raw_data[1], src_node_id, dst_node_id, payload_len]
        mac_data += crypted_payload
        mac_code = calcS0MACCode(mac_data, Ka, iv)
        if mac_code != sender_mac:
            logging.info("S0 MAC mismatches (sender_mac:%s calculated:%s) for node:%d. Can't decrypt packet:%s"%(splitHexBuff(sender_mac), splitHexBuff(mac_code), src_node_id, packet_text))
            return None
        data = decryptS0Data(crypted_payload, Ke, iv)
        logging.info("Decrypted message:%s"%(splitHexBuff(data)))
        return data
        
    def decode(self, raw_data, net_params=None):
        packet_text = splitHexBuff(raw_data)
        if net_params == None:
            logging.info("Network parameters is not provided to ZWaveSecurityS0. Can't decrypt packet:%s"%(packet_text))
            return None, None
        if not "homeid" in net_params:
            logging.info("HomeID is not provided to ZWaveSecurityS0. Can't decrypt packet:%s"%(packet_text))
            return None, None
        home_id = net_params["homeid"]
        if not "src_node_id" in net_params:
            logging.info("Source NodeID is not provided to ZWaveSecurityS0. Can't decrypt packet:%s"%(packet_text))
            return None, None
        src_node_id = net_params["src_node_id"]
        if not "dst_node_id" in net_params:
            logging.info("Destination NodeID is not provided to ZWaveSecurityS0. Can't decrypt packet:%s"%(packet_text))
            return None, None
        dst_node_id = net_params["dst_node_id"]
        if len(raw_data) <= ZWaveSecurityS0.S0_PACKET_ADV_PAYLOAD:
            logging.info(" The package is too short. Minimal lenth is %d. Can't decrypt packet:%s"%(ZWaveSecurityS0.S0_PACKET_ADV_PAYLOAD, packet_text))
            return None, None
        sc = ZWaveStatCollector.getInstance()
        net_key = sc.getNetworkKey(home_id)
        b_try_key = False
        if net_key == None:
            logging.info("No S0 key for network:%08x. Seems we can't decrypt packet:%s. Trying default key"%(home_id, packet_text))
            net_key = ZWaveSecurityS0.S0_DEFAULT_NETWORK_KEY
            b_try_key = True
        receiver_nonce = sc.getS0NonceForNode(home_id, src_node_id, dst_node_id)
        if receiver_nonce == None:
            logging.info("No S0 NONCE for node:%d (HomeID:%08x). Can't decrypt packet:%s"%(src_node_id, home_id, packet_text))
            return None, {"s0_error":ZWaveSecurityS0.S0_DECODE_ERROR_NO_NONCE}
        receiver_nonce = receiver_nonce[1] # На данный момент нам не интересен временной момент
        decrypted_message = self._decryptS0Message(raw_data, receiver_nonce, src_node_id, dst_node_id, net_key)
        if decrypted_message == None:
            if b_try_key:
                return None, {"s0_error":ZWaveSecurityS0.S0_DECODE_ERROR_NO_KEY}
            logging.error("Can't decrypt S0 message %s home_id:%08x"%(packet_text, home_id))
            return None, {"s0_error":ZWaveSecurityS0.S0_DECODE_ERROR_WRONG_MESSAGE}
        properties = decrypted_message[0]
        payload_list = decrypted_message[1:]
        if properties & ZWaveSecurityS0.S0_CMDFLAG_SEQUENCED:
            seq_key = "%08x_%d_%d"%(home_id, src_node_id, dst_node_id)
            # Передается сообщение из нескольких пакетов
            if properties&ZWaveSecurityS0.S0_CMDFLAG_SECOND_PACK:
                # Это вторая часть - нужно начало
                if (seq_key in self._prev_sequenced):
                    #logging.info("S0 Can't find start of sequenced pacakage(res:%s) for node:%d (HomeID:%08x). Can't decrypt packet:%s"%(splitHexBuff(payload_list), src_node_id, home_id, packet_text))
                    first_part = self._prev_sequenced[seq_key]
                    payload_list = first_part + payload_list
                    del self._prev_sequenced[seq_key]
            else:
                # Это первая часть - нужно ее сохранить
                self._prev_sequenced[seq_key] = payload_list
        md = {"encap_type":"S0", "s0_encap_sequenced":properties&ZWaveSecurityS0.S0_CMDFLAG_SEQMASK}
        return [payload_list], md
    def encode(self, payload, params=None):
        home_id = None
        if isinstance(params, list):
            if len(params) > 0:
                home_id = params[0] 
        elif isinstance(params, dict):
            if "homeid" in params:
                home_id = params["homeid"]
        if home_id == None:
            return payload
        return payload

class  ZWaveSecurityS2(ZWaveEncapParser):
    S2_DECODE_ERROR_NO_KEY = S2CryptoProvider.S2_ERR_NO_KEY
    S2_DECODE_ERROR_NO_NONCE = S2CryptoProvider.S2_ERR_NO_NONCE
    S2_DECODE_ERROR_WRONG_MESSAGE = S2CryptoProvider.S2_ERR_NO_CANTDECRYPT
    S2_DECODE_ERROR_SYNC = S2CryptoProvider.S2_ERR_DECR_FAILED_FOR_RKEY
    S2_DECODE_ERROR_INTERNAL_ERROR = -10
    
    def __init__(self, ext_data=None):
        ZWaveEncapParser.__init__(self, ext_data)
        self.ClsID = 0x9F03
        self.ParamNameLst = []
        self._cr = S2CryptoProvider()
        self._stat = ZWaveStatCollector.getInstance()
    def decode(self, raw_data, net_params=None):
        packet_text = splitHexBuff(raw_data, 256)
        if not "homeid" in net_params:
            logging.info("HomeID is not provided to ZWaveSecurityS0. Can't decrypt packet:%s"%(packet_text))
            return None, None
        home_id = net_params["homeid"]
        if not "src_node_id" in net_params:
            logging.info("Source NodeID is not provided to ZWaveSecurityS0. Can't decrypt packet:%s"%(packet_text))
            return None, None
        src_node_id = net_params["src_node_id"]
        if not "dst_node_id" in net_params:
            logging.info("Destination NodeID is not provided to ZWaveSecurityS0. Can't decrypt packet:%s"%(packet_text))
            return None, None
        dst_node_id = net_params["dst_node_id"]
        #print("---decrypt MSG")
        try:
            payload = self._cr.decryptS2Message(home_id, src_node_id, dst_node_id, raw_data)
            #print("---decrypt OK")
            if payload == None:
                err_code = self._cr.getLastDecodeError()
                logging.debug("S2 errcode:%s"%(err_code))
                return None, {"s2_err_code":err_code}
            s2_md = copy.deepcopy(self._cr.getLastDecodeMetadata()) 
            key_class = self._stat.getKeyS2ClassForNodes(home_id, src_node_id, dst_node_id)
            md = {"encap_type":"S2(%s)"%(ZWaveStatCollector.NETWORK_KEY_NAMES[key_class]), "s2_key_class":key_class, "s2_dbg_data":s2_md}
        except:
            zmeProcessException()
            return None, {"s2_err_code":ZWaveSecurityS2.S2_DECODE_ERROR_INTERNAL_ERROR}
        return [payload], md
    def encode(self, payload, params=None):
        home_id = None
        if isinstance(params, list):
            if len(params) > 0:
                home_id = params[0] 
        elif isinstance(params, dict):
            if "homeid" in params:
                home_id = params["homeid"]
        if home_id == None:
            return payload
        return payload

class  ZWaveSupervision(ZWaveEncapParser):
    def __init__(self, ext_data=None):
        ZWaveEncapParser.__init__(self, ext_data)
        self.ClsID = 0x6C01
        self.ParamNameLst = []
    def decode(self, raw_data, net_params=None):
        if len(raw_data) < 6:
            return None, None
        propertises = raw_data[2]
        cmd_len = raw_data[3]
        if cmd_len > (len(raw_data) - 4):
            return None, None
        payload_list = [raw_data[4:4+cmd_len]]
        md = {"supervision_properties":propertises, "encap_type":"SV"}
        return payload_list, md
    def encode(self, payload, params=None):
        properties = None
        if isinstance(params, list):
            if len(params) > 0:
                properties = params[0] 
        elif isinstance(params, dict):
            if "supervision_properties" in params:
                properties = params["crc16_encap"]
        if properties != None:
            return [0x6C, 0x01, properties, len(payload)] + payload
        return payload
class  ZWaveMulticommand(ZWaveEncapParser):
    def __init__(self, ext_data=None):
        ZWaveEncapParser.__init__(self, ext_data)
        self.ClsID = 0x8F01
        self.ParamNameLst = []
    def decode(self, raw_data, net_params=None):
        if len(raw_data) < 6:
            return None, None
        cmd_count = raw_data[2]
        i = 0
        offset = 3
        payload_list = []
        while i < cmd_count:
            cmd_len = raw_data[offset]
            offset += 1
            payload_list += [raw_data[offset:offset+cmd_len]]
            offset += cmd_len
            if offset >= len(raw_data):
                break
        payload_list = [raw_data[4:4+cmd_len]]
        md = {"encap_type":"MCMD"}
        return payload_list, md
    def encode(self, payload, params=None):
        properties = None
        if not isinstance(payload[0], list):
            return payload
        encapsulated_lst = []
        for p in payload:
            encapsulated_lst += [[len(p)] + p]
        return [0x8F, 0x01, len(payload)] + encapsulated_lst

class  ZWaveTransportService(ZWaveEncapParser):
    def __init__(self, ext_data=None):
        ZWaveEncapParser.__init__(self, ext_data)
        self.ClsID = [0x55C0, 0x55E0, 0x55C1, 0x55E1, 0x55C2, 0x55E2]
        self.ParamNameLst = []
    def decode(self, raw_data, net_params=None):
        packet_text = splitHexBuff(raw_data, 256)
        logging.debug("ZWaveTransportService:%s"%(packet_text))
        if len(raw_data) < 8:
            return None, None
        if net_params == None:
            logging.info("Network parameters is not provided to ZWaveTransportService. Can't decode packet:%s"%(packet_text))
            return None, None
        if not "homeid" in net_params:
            logging.info("HomeID is not provided to ZWaveTransportService. Can't decode packet:%s"%(packet_text))
            return None, None
        home_id = net_params["homeid"]
        if not "src_node_id" in net_params:
            logging.info("Source NodeID is not provided to ZWaveTransportService. Can't decode packet:%s"%(packet_text))
            return None, None
        src_node_id = net_params["src_node_id"]
        if not "dst_node_id" in net_params:
            logging.info("Destination NodeID is not provided to ZWaveTransportService. Can't decode packet:%s"%(packet_text))
            return None, None
        dst_node_id = net_params["dst_node_id"]
        sub_cmd = (raw_data[1] >> 4) & 0x0F
        msb_len = raw_data[1] & 0x07
        lsb_len = raw_data[2]
        sessiod_id = (raw_data[3] >> 4) & 0x0F
        l = (msb_len << 8) + lsb_len
        sc = ZWaveStatCollector.getInstance()
        header_offset = 4
        if sub_cmd == 0x0E:
            header_offset += 1
        if raw_data[3] & 0x08:
            header_len = raw_data[header_offset]
            header_offset += header_len+1
        payload_len = len(raw_data)-header_offset-2
        sub_payload = raw_data[header_offset:header_offset+payload_len]
        if sub_cmd == 0x0C:
            # Start packet
            sc.createNewTSSession(home_id, src_node_id, dst_node_id, sessiod_id, l, sub_payload)
            return None, None
        if sub_cmd == 0x0E:
            offset = raw_data[3] & 0x07
            offset <<= 8
            offset += raw_data[4]
            done, payload = sc.updateTSSessionPayload(home_id, src_node_id, dst_node_id, sessiod_id, l, offset, sub_payload)
            if done:
                md = {"encap_type":"TS"}
                return [payload], md
        return None, None
    def encode(self, payload, params=None):
        return payload
        