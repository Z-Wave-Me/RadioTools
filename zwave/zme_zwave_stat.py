import time
import traceback
from common.zme_aux import *


class ZWaveStatCollector:
    SECUIRITY_V1_COMMANDCLASS = 0x98
    SECUIRITY_V1_COMMAND_NONCE_REPORT = 0x80
    SECUIRITY_V1_COMMAND_KEY_SET = 0x06
    
    SECUIRITY_V2_COMMANDCLASS = 0x9F
    SECUIRITY_V2_COMMAND_NONCE_REPORT = 0x02
    NETWORK_KEY_S0 = 4
    NETWORK_KEY_S2_UNAUTH = 1
    NETWORK_KEY_S2_AUTH = 2
    NETWORK_KEY_S2_ACCESS = 3
    NETWORK_KEY_S2_LR_AUTH = 5
    NETWORK_KEY_S2_LR_ACCESS = 6
    NETWORK_KEY_CTT = 7
    

    NETWORK_KEY_NAMES = {NETWORK_KEY_S0:"S0", NETWORK_KEY_S2_UNAUTH:"UN_AUTH", NETWORK_KEY_S2_AUTH:"AUTH", NETWORK_KEY_S2_ACCESS:"ACCESS", NETWORK_KEY_S2_LR_AUTH:"LR_AUTH", NETWORK_KEY_S2_LR_ACCESS:"LR_ACCESS", NETWORK_KEY_CTT:"CTT"}
    NETWORK_KEY_LIST = [NETWORK_KEY_S0, NETWORK_KEY_S2_UNAUTH, NETWORK_KEY_S2_AUTH, NETWORK_KEY_S2_ACCESS, NETWORK_KEY_S2_LR_AUTH, NETWORK_KEY_S2_LR_ACCESS]
    NETWORK_KEY_LIST_ZM = [NETWORK_KEY_S2_AUTH, NETWORK_KEY_S2_UNAUTH, NETWORK_KEY_S2_ACCESS, NETWORK_KEY_S0]
    
    NONCE_TYPE_S0=0
    NONCE_TYPE_S2_SINGLE=1
    NONCE_TYPE_S2_MULTI=2
    
    DEFAULT_KEY_STORAGE =  "/ZMEStorage/SecurityKeys/"
    __instance = None
    def __init__(self):
        if not ZWaveStatCollector.__instance:
            #print(" __init__ method called..")
            self._networks = {}
            self._user_storage_keydir = ZWaveStatCollector.defautKeyStorageDir()
        else:
            pass
            #print("Instance already created:", self.getInstance())
    @staticmethod 
    def defautKeyStorageDir():
        return os.path.expanduser("~") + ZWaveStatCollector.DEFAULT_KEY_STORAGE
    def setUserKeyStorage(self, dir):
        self._user_storage_keydir = dir
    @staticmethod
    def __storeNonce(home_md, src_id, dst_id, nonce_data, ts,  bS2=False, nonce_mask=0, nonce_seq=0):
        nonce_key = "%03d-%03d"%(src_id, dst_id)
        nonce_dir = "nonces_s0"
        if bS2:
            nonce_dir = "nonces_s2"
            #print("Nonce mask%x"%(nonce_mask))
            if (nonce_mask & 0x02) != 0:
                nonce_dir = "nonces_s2m"
        if not nonce_dir in home_md:
            home_md[nonce_dir] = {}
        if not nonce_key in home_md[nonce_dir]:
            home_md[nonce_dir][nonce_key] = []
        if bS2:
            nonce_lst = [ts, nonce_seq, nonce_data]
        else:
            nonce_lst = [ts, nonce_data]
        logging.info("Nonce update:(%s %s) = %s"%(nonce_dir, nonce_key, splitHexBuff(nonce_data)))
        home_md[nonce_dir][nonce_key] += [nonce_lst]
    def storeNonce(self, home_id,  src_id, dst_id, nonce_data, ts,  bS2=False, nonce_mask=0, nonce_seq=0):
        home_id_key = self.__homeIDKey(home_id)
        if not (home_id_key in self._networks):
            self._networks[home_id_key] = {"nodes":{}, "keys":{}}
        home_md = self._networks[home_id_key]
        ZWaveStatCollector.__storeNonce(home_md, src_id, dst_id, nonce_data, ts,  bS2, nonce_mask, nonce_seq)
    def _process_node(self, pkg, home_md):
        src_id = 0
        dst_id = 0
        if not "src_node_id" in pkg: 
            return 0, None
        src_id_i = pkg["src_node_id"]
        src_id = "%2d"%(src_id_i)
        if not (src_id in home_md["nodes"]):
            home_md["nodes"][src_id] = {"last_send":pkg["ts"], "ccs_list":{}, "outgoing_nodes":[]}
        node_md = home_md["nodes"][src_id]
        if "dst_node_id" in pkg:
            dst_id = pkg["dst_node_id"]
            if not dst_id in node_md["outgoing_nodes"]:
                node_md["outgoing_nodes"] += [dst_id]
        if "app" in  pkg:
            for a in pkg["app"]:
                if "cc_value" in a:
                    cc_value = "%d"%(a["cc_value"])
                    if not cc_value in node_md["ccs_list"]:
                        node_md["ccs_list"][cc_value] = {"commands":[]}
                    if not a["cmd_value"] in node_md["ccs_list"][cc_value]["commands"]:
                        node_md["ccs_list"][cc_value]["commands"] += [a["cmd_value"] ]
                    if (a["cc_value"] == ZWaveStatCollector.SECUIRITY_V1_COMMANDCLASS) and (a["cmd_value"] == ZWaveStatCollector.SECUIRITY_V1_COMMAND_NONCE_REPORT):
                        nonce_data = a["payload"][2:2+8]
                        self.__storeNonce(home_md, src_id_i, dst_id, nonce_data, pkg["ts"], False);
                        logging.debug("Store S0 nonce %s for (%d, %d) "%(splitHexBuff(nonce_data), src_id_i, dst_id))
                    elif (a["cc_value"] == ZWaveStatCollector.SECUIRITY_V1_COMMANDCLASS) and (a["cmd_value"] == ZWaveStatCollector.SECUIRITY_V1_COMMAND_KEY_SET):
                        # Нам повезло - мы перехватили ключ сети
                        last_index = 3+16
                        if len(a["payload"]) >= last_index:
                            key_data = a["payload"][3:last_index]
                            logging.info("S0 KEY:%s for HOMEID:%08x was sniffed!"%(splitHexBuff(key_data), pkg["homeid"]))
                            current_key = self.getNetworkKey(pkg["homeid"])
                            if current_key != key_data:
                                self._addSecurityKey2Network(pkg["homeid"], key_data, ZWaveStatCollector.NETWORK_KEY_S0)
                                self.storeNetworkKeysToFile(pkg["homeid"])
                    elif (a["cc_value"] == ZWaveStatCollector.SECUIRITY_V2_COMMANDCLASS) and (a["cmd_value"] == ZWaveStatCollector.SECUIRITY_V2_COMMAND_NONCE_REPORT):
                        nonce_data = a["payload"][4:4+16]
                        self.__storeNonce(home_md, src_id_i, dst_id, nonce_data, pkg["ts"], True, a["payload"][3], a["payload"][2]);
        return src_id, node_md
    def __homeIDKey(self, homeid_val):
        if isinstance(homeid_val, str):
            return homeid_val
        return "%08X"%(homeid_val)
    def __homeIDVal(self, homeid_key):
        return int(homeid_key, 16)
    def process(self, pkg):
        try:
            if "homeid" in pkg:
                home_id_key = self.__homeIDKey(pkg["homeid"])
                if not (home_id_key in self._networks):
                    self._networks[home_id_key] = {"nodes":{}, "keys":{}, "nonces_s0":{}}
                node_id, node_md  = self._process_node(pkg, self._networks[home_id_key])
                if node_id != 0:
                    logging.info("Node %s.%s MD was updated:%s"%(home_id_key, node_id, node_md))
        except:
            logging.error("ZWaveStatCollector exception:%s"%(traceback.format_exc()))
    def getNetworkList(self, b_hex= False):
        '''
        l = list(self._networks)
        if b_hex:
            hex_l = []
            for h in l:
               hex_l += ["%08X"%(int(h))]
            return hex_l
        '''
        return self._networks
    def _extractKeyFromLine(self, l):
        parts = l.split(";")
        if len(parts) < 2:
            return None
        if len(parts[1]) == 0:
            return None
        key_buff = formatHexInput(parts[1])
        return key_buff
    def _addSecurityKey2Network(self, home_id, key, key_type):
        home_id_key = self.__homeIDKey(home_id)
        if not (home_id_key in self._networks):
            self._networks[home_id_key] = {"nodes":{}, "keys":{}}
        key_type_id = "%02x"%(key_type)
        self._networks[home_id_key]["keys"][key_type_id] = key
        logging.info("Register key:%s class:%s homeid:%s"%(splitHexBuff(key), key_type_id, home_id_key))
        #print("Keys:%s"%(self._networks[home_id_key]["keys"]))
    def _loadKeyFromStorage(self, home_id):
        try:
            #print("Loading key from storage")
            if not os.path.exists(self._user_storage_keydir):
                os.makedirs(self._user_storage_keydir)
                #print("No storage dir!")
                return False
            home_id_key = self.__homeIDKey(home_id)
            needed_file = "%s%s.txt"%(self._user_storage_keydir, home_id_key)
            if not os.path.isfile(needed_file):
                logging.debug("No needed file:%s!"%(needed_file))
                #print("No needed file:%s!"%(needed_file))
                return False
            lines = loadSourceFile(needed_file)
            #print("KeyFile lines:%s"%(lines))
            i = 0
            num_keys = 0
            for l in lines:
                key = self._extractKeyFromLine(l)
                if key != None:
                    num_keys += 1
                    #print("Add key type%d:%s"%(ZWaveStatCollector.NETWORK_KEY_LIST[i], key))
                    self._addSecurityKey2Network(home_id, key, ZWaveStatCollector.NETWORK_KEY_LIST[i])
                i += 1
                if i>= len(ZWaveStatCollector.NETWORK_KEY_LIST):
                    break
            return (num_keys > 0)
        except:
            zmeProcessException("_loadKeyFromStorage")
    def dumpNetworkKeysToFile(self, home_id, filename):
        text = ""
        for t in ZWaveStatCollector.NETWORK_KEY_LIST:
            key = self.getNetworkKey(home_id, t)
            key_str = ""
            if key != None:
                key_str = splitHexBuff(key).replace(" ","")
            if t == ZWaveStatCollector.NETWORK_KEY_S0:
                text += "98;%s;1\n"%(key_str)
            else:
                text += "9F;%s;1\n"%(key_str)
        try:
            saveTextFile(filename, text)
        except:
            zmeProcessException("dumpNetworkKeysToFile")
    def storeNetworkKeysToFile(self, home_id):
        home_id_key = self.__homeIDKey(home_id)
        if not os.path.exists(self._user_storage_keydir):
            os.makedirs(self._user_storage_keydir)
        filename = "%s%s.txt"%(self._user_storage_keydir, home_id_key)
        self.dumpNetworkKeysToFile(home_id, filename)
    def getNetworkKey(self, home_id, key_type = NETWORK_KEY_S0):
        if key_type == ZWaveStatCollector.NETWORK_KEY_CTT:
            key = [0x00]*16
            key[0] = 0xC1
            return key
        home_id_key = self.__homeIDKey(home_id)
        key_type_id = "%02x"%(key_type)
        if  home_id_key in self._networks:
            if key_type_id in self._networks[home_id_key]["keys"]:
                # Такой ключ уже есть в метаданных и он был закэширован
                return self._networks[home_id_key]["keys"][key_type_id]
        # Пробуем найти ключ сети в каталоге с ключами - вдруг туда его положил пользователь
        if self._loadKeyFromStorage(home_id_key):
            if key_type_id in self._networks[home_id_key]["keys"]:
                return self._networks[home_id_key]["keys"][key_type_id]
        return None
    def updateNetworkKeysFromRawVec(self, home_id, key_vec):
        bUpdated = False
        offset = 0
        empty_keys = [[0x00]*16, [0xFF]*16]
        for k in ZWaveStatCollector.NETWORK_KEY_LIST_ZM:
            vec = key_vec[offset:offset+16]
            if not (vec in empty_keys):
                if self.getNetworkKey(home_id, k) == None:
                    # Такого ключа еще нет в хранилище
                    self._addSecurityKey2Network(home_id, vec, k)
                    logging.info("updated SecurityKey (%02x) for %08x network. Key:%s"%(k, home_id, splitHexBuff(vec)))
                    bUpdated = True
            offset += 16
        if bUpdated:
            self.storeNetworkKeysToFile(home_id)
        return bUpdated

    def getKeyS2ClassForNodes(self, home_id, src_node_id, dst_node_id):
        home_id_key = self.__homeIDKey(home_id)
        if not home_id_key in self._networks:
            return None
        if not "s2classes" in self._networks[home_id_key]:
            return None
        a = min(src_node_id, dst_node_id)
        b = max(src_node_id, dst_node_id)
        context_key = "%d-%d"%(a, b)
        if not (context_key in self._networks[home_id_key]["s2classes"]):
            return None
        return self._networks[home_id_key]["s2classes"][context_key]
    def registerKeyS2ClassForNodes(self, home_id, src_node_id, dst_node_id, key_cl):
        home_id_key = self.__homeIDKey(home_id)
        if not (home_id_key in self._networks):
            self._networks[home_id_key] = {"nodes":{}, "keys":{}, "nonces_s0":{}}
        if not "s2classes" in self._networks[home_id_key]:
            self._networks[home_id_key]["s2classes"] = {}
        a = min(src_node_id, dst_node_id)
        b = max(src_node_id, dst_node_id)
        context_key = "%d-%d"%(a, b)
        self._networks[home_id_key]["s2classes"][context_key] = key_cl
    
    def getNonceForNode(self, type, home_id, src_node_id, dst_node_id, index = -1):
        nonce_dir = "nonces_s0"
        if type == ZWaveStatCollector.NONCE_TYPE_S2_SINGLE:
            nonce_dir =  "nonces_s2"
        elif type == ZWaveStatCollector.NONCE_TYPE_S2_MULTI:
            nonce_dir =  "nonces_s2m"
        home_id_key = self.__homeIDKey(home_id)
        if not home_id_key in self._networks:
            return None
        if not nonce_dir in self._networks[home_id_key]:
            return None
        nonce_key = "%03d-%03d"%(dst_node_id, src_node_id)
        if not nonce_key in self._networks[home_id_key][nonce_dir]:
            logging.warning("Can't find S0 nonce: %s NonceMap:%s"%(nonce_key, list(self._networks[home_id_key][nonce_dir])))
            return None
        l = len(self._networks[home_id_key][nonce_dir][nonce_key])
        if index < 0:
            if (index + l) < 0:
                return None
        elif index>=l:
            return None
        return self._networks[home_id_key][nonce_dir][nonce_key][index]
    def getS0NonceForNode(self, home_id, src_node_id, dst_node_id, index = -1):
        return self.getNonceForNode(ZWaveStatCollector.NONCE_TYPE_S0, home_id, src_node_id, dst_node_id, index)
    def __TSsessionKey(self, home_id, src_node_id, session_number):
        home_id_key = self.__homeIDKey(home_id)
        key = "%s-%03d-%02d"%(home_id_key, src_node_id, session_number)
        return key
    def createNewTSSession(self, home_id, src_node_id, dst_node_id, session_number, l, payload):
        home_id_key = self.__homeIDKey(home_id)
        if not home_id_key in self._networks:
            self._networks[home_id_key] = {"nodes":{}, "keys":{}}
        if not ("ts_sessions" in self._networks[home_id_key]):
            self._networks[home_id_key]["ts_sessions"] = {}
        ts_key = self.__TSsessionKey(home_id, src_node_id, session_number)
        adv_lst = []
        bitmap = [0x01]*len(payload)
        if l > len(payload):
            adv_lst = [0x00]*(l - len(payload))
        else:
            logging.warning("Stat.NEWTSSession. Wrong session length=%d. First payload length:%d"%(l,len(payload)))
        bitmap += adv_lst
        self._networks[home_id_key]["ts_sessions"][ts_key] = {"dst":dst_node_id, "bitmap":bitmap, "max_len":l,"payload":payload+adv_lst}
    def updateTSSessionPayload(self, home_id, src_node_id, dst_node_id, session_number, l, offset, adv_payload):
        home_id_key = self.__homeIDKey(home_id)
        if not home_id_key in self._networks:
            return False, None
        if not home_id_key in self._networks:
            return False, None
        ts_key = self.__TSsessionKey(home_id, src_node_id, session_number)
        if not (ts_key in self._networks[home_id_key]["ts_sessions"]):
            return False, None
        s = self._networks[home_id_key]["ts_sessions"][ts_key]
        if s["max_len"] != l:
            logging.warning("Stat.updateTSSessionPayload. Session legth(=%d) mismatches. Fragment length:%d"%(s["max_len"], l))
            return False, None
        if offset >= s["max_len"]:
            logging.warning("Stat.updateTSSessionPayload. Wrong sub payload offset:%d (len:%d)"%(offset, s["max_len"]))
            offset = s["max_len"]-1
        final_index = offset + len(adv_payload)
        if final_index > s["max_len"]:
            logging.warning("Stat.updateTSSessionPayload. Wrong sub payload length:%d (offset:%d)"%(len(adv_payload), offset))
            final_index = s["max_len"]
        s["payload"][offset:final_index] =  adv_payload[:final_index-offset]
        s["bitmap"][offset:final_index] = [0x01]*(final_index-offset)
        logging.debug("TS Session:%s Payload:%s Bitmap:%s"%(ts_key, splitHexBuff(s["payload"]), splitHexBuff(s["bitmap"])))
        if s["bitmap"].count(0x00) == 0:
            return True, s["payload"]
        return False, None

    def serializeToDict(self):
        return dict(self._networks)
    def loadFromDict(self, md):
        self._networks = dict(md)
    @classmethod
    def getInstance(cls):
        if not cls.__instance:
            cls.__instance = ZWaveStatCollector()
        return cls.__instance