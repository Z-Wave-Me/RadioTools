#!/usr/bin/python
# -*- coding: utf-8 -*-

from copy import deepcopy
import sys
import os
from zwave.zme_zwave_stat import ZWaveStatCollector
from common.zme_aux import *

class S2DRBGen:
    STATE_NOT_INITIALIZED = 0
    STATE_ACTIVE = 3
    KEYLEN = 16
    def __init__(self):
        self._v = [0]*S2DRBGen.KEYLEN
        self._k = [0]*S2DRBGen.KEYLEN
        self._state = S2DRBGen.STATE_NOT_INITIALIZED
    @staticmethod
    def ctr_inc(buff):
        res = deepcopy(buff)
        index = len(buff)-1
        #logging.debug("Start state:%s"%(splitHexBuff(res)))
        count = 0
        try:
            while index >= 0:
                res[index] += 1
                res[index] &= 0x00FF
                if res[index] != 0:
                    break
                index -= 1
                #count += 1
        except:
            zmeProcessException()
        #logging.debug("INC state:%s count:%d"%(splitHexBuff(res), count))
        return res
    def update(self, d):
        self._v = S2DRBGen.ctr_inc(self._v)
        t = encryptAESBlock(self._v, self._k)
        self._v = S2DRBGen.ctr_inc(self._v)
        t1 = encryptAESBlock(self._v, self._k)
        t += t1
        t = xorBuff(t, d)
        self._k = t[:S2DRBGen.KEYLEN] 
        self._v = t[S2DRBGen.KEYLEN:] 
    def reseed(self, entropy):
        self.update(entropy)
    def instantiate(self, entropy, personal):
        ent = xorBuff(entropy, personal)
        self._v = [0]*S2DRBGen.KEYLEN
        self._k = [0]*S2DRBGen.KEYLEN
        self.reseed(ent)
    def generate(self):
        self._v = S2DRBGen.ctr_inc(self._v)
        r = encryptAESBlock(self._v, self._k)
        self.update([0]*(2*S2DRBGen.KEYLEN))
        return r
class S2CryptoProvider:
    BLOCK_SIZE = 16
    MAC_SIZE = 8
    CCM_Q = 2
    CCM_N = (15 - CCM_Q)
    B0_ADD = 0x40
    ADD_BLOCK0_SIZE = 14
    ADD_BLOCK0_SHIFT = 2

    DECRYPT_CODE_OK = 0
    DECRYPT_CODE_LENGTH = 1
    DECRYPT_CODE_AUTH = 2
    
    CMD_CLASS_S2 = 0x9F
    CMD_MSG_ENCAP = 0x03
    CMD_FLAGS_EXTENTION = 0x01
    CMD_FLAGS_ENCRYPTED_EXTENSION = 0x02
    EXTHDR_TYPE_MASK = 0x3F
    EXTHDR_TYPE_SN = 0x01
    FLAG_EXTHDR_MORE = 0x80
    LOWEST_LONG_RANGE_NODE_ID = 0x100

    CONSTANT_NONCE = [0x26]*BLOCK_SIZE

    S2_ERR_OK = 0
    S2_ERR_NO_NONCE = -2
    S2_ERR_NO_KEY = -1
    S2_ERR_NO_CANTDECRYPT = -3
    S2_ERR_DECR_FAILED_FOR_RKEY = -4
    S2_ERR_OLD_SEQUENCE = -5
    

    S2_WARNING_FLAG_KEY_ZERO = 0x01
    S2_WARNING_FLAG_KEY_CTT = 0x02
    S2_WARNING_FLAG_NONCE_RECALL = 0x04
    S2_WARNING_FLAG_SEQUENCE_OVERFLOW = 0x08
    
    S2_VALID_RECALL_INETRVAL = 5


    def __init__(self):
        self._contexts = {}
        self._networks = {}
        self._last_decode_error = 0
        self._last_decode_warning = 0
        self._last_decode_metadata = None

    def getLastDecodeMetadata(self):
        return self._last_decode_metadata
    def getLastDecodeError(self):
        return self._last_decode_error
    def getLastDecodeWarnings(self):
        return self._last_decode_warning
        
    @staticmethod
    def ckdf_nonce0_expnd(prk):
        cnst_nk = [0x88]*15
        t0 = cnst_nk + [0x00] + cnst_nk + [0x01]
        t1 = calcAESCMAC(prk, t0)
        t2 = calcAESCMAC(prk, t1[:16] + cnst_nk + [0x02])
        mei = t1[:16] + t2[:16]
        return mei
    @staticmethod 
    def netkey_expnd(key):
        cnst_nk = [0x55]*15
        ccm_key = calcAESCMAC(key, cnst_nk + [0x01])
        nonce_key1 = calcAESCMAC(key, ccm_key + cnst_nk + [0x02])
        nonce_key2 = calcAESCMAC(key, nonce_key1[:16] + cnst_nk + [0x03])
        nonce_key = nonce_key1[:16] + nonce_key2[:16]
        mpan_key = calcAESCMAC(key, nonce_key2[:16] + cnst_nk + [0x04])
        return ccm_key, nonce_key, mpan_key
    @staticmethod
    def next_nonce_generate(drbg):
        return drbg.generate()
    @staticmethod
    def next_nonce_instantiate(drbg, ei_sender, ei_receiver, k_nonce):
        ent = ei_sender + ei_receiver
        cmac = calcAESCMAC(S2CryptoProvider.CONSTANT_NONCE, ent)
        mei = S2CryptoProvider.ckdf_nonce0_expnd(cmac[:16])
        drbg.instantiate(mei, k_nonce)

    @staticmethod
    def ccmMakeBlock0(nonce, ecrypt_len):
        blk = [0]*S2CryptoProvider.BLOCK_SIZE
        blk_start = S2CryptoProvider.B0_ADD
        blk_start |= (((S2CryptoProvider.MAC_SIZE - 2) >> 1) & 0x07) << 3
        blk_start |= (S2CryptoProvider.CCM_Q - 1) & 0x07
        blk[0] = blk_start
        blk[1:1+S2CryptoProvider.CCM_N] = nonce[:S2CryptoProvider.CCM_N]
        blk[14] = (ecrypt_len >> 8) & 0xFF
        blk[15] = (ecrypt_len) & 0xFF
        return blk
    @staticmethod
    def ccmMakeCounterBlock(nonce, index):
        ctr = [0]*S2CryptoProvider.BLOCK_SIZE
        ctr[0] = ((S2CryptoProvider.CCM_Q-1) & 0x07)
        ctr[1:1+S2CryptoProvider.CCM_N] = nonce[:S2CryptoProvider.CCM_N]
        ctr[14] = (index >> 8) & 0xFF
        ctr[15] = (index) & 0xFF
        return ctr
    @staticmethod 
    def chop2SubArrays(l, arr, quant):
        num_blocks = len(arr) // quant
        rest = len(arr) % quant
        offset = 0
        for i in range(num_blocks):
            l += [arr[offset:offset+quant]]
            offset +=quant
        if rest != 0:
            l += [arr[offset:offset+rest] + [0x00]*(quant-rest)]
    @staticmethod
    def formatCCM_AP(aad, data):
        blocks = []
        b1 = [0x00, len(aad)]
        if len(aad) <= S2CryptoProvider.ADD_BLOCK0_SIZE:
            b1 += aad
            b1 += [0x00]*(S2CryptoProvider.ADD_BLOCK0_SIZE-len(aad))
        else:
            b1 += aad[:S2CryptoProvider.ADD_BLOCK0_SIZE]
        blocks += [b1]
        if len(aad) > S2CryptoProvider.ADD_BLOCK0_SIZE:
            S2CryptoProvider.chop2SubArrays(blocks, aad[S2CryptoProvider.ADD_BLOCK0_SIZE:], S2CryptoProvider.BLOCK_SIZE)
        S2CryptoProvider.chop2SubArrays(blocks, data, S2CryptoProvider.BLOCK_SIZE)
        return blocks
    @staticmethod
    def calcCCMMAC(key, nonce, aad, data):
        b0 = S2CryptoProvider.ccmMakeBlock0(nonce, len(data))
        y0 = encryptAESBlock(b0, key)
        B = S2CryptoProvider.formatCCM_AP(aad, data)
        y = y0
        i = 0
        #print("Block:0 {%s}"%( splitHexBuff(b0)))
        #print("Y:0 {%s}"%( splitHexBuff(y)))
        for b in B:
            #print("Block:%d {%s}"%(i+1, splitHexBuff(b)))
            c = xorBuff(b, y)
            y = encryptAESBlock(c, key)
            #print("Y:%d {%s}"%(i+1, splitHexBuff(y)))
            i += 1
        return y[:S2CryptoProvider.MAC_SIZE]
    @staticmethod
    def parseS2MSG(msg_buff):
        msg = {"crypted_payload":None, "header":None, "sequence":0}
        if len(msg_buff) < 4:
            #print("OUT1")
            return None
        if (msg_buff[0] != S2CryptoProvider.CMD_CLASS_S2) or (msg_buff[1] != S2CryptoProvider.CMD_MSG_ENCAP):
            #print("OUT2")
            return None
        msg["sequence"] = msg_buff[2]
        flags = msg_buff[3]
        offset = 4
        if (flags & S2CryptoProvider.CMD_FLAGS_EXTENTION) != 0:
            while offset < len(msg_buff):
                ext_len = msg_buff[offset]
                #print("extlen:%d offset:%d"%(ext_len, offset))
                if len(msg_buff) < (offset + ext_len):
                    #print("OUT3")
                    return None
                header_type = msg_buff[offset+1] & S2CryptoProvider.EXTHDR_TYPE_MASK
                if header_type == S2CryptoProvider.EXTHDR_TYPE_SN:
                    msg["s_nonce"] = msg_buff[offset+2:offset+2+16]
                b_more = (msg_buff[offset+1] & S2CryptoProvider.FLAG_EXTHDR_MORE) != 0
                offset += ext_len
                if not b_more:
                    break
        msg["header"] = msg_buff[0:offset]
        msg["crypted_payload"] = msg_buff[offset:]
        return msg
    @staticmethod
    def isLRNode(node_id):
        return (node_id >= S2CryptoProvider.LOWEST_LONG_RANGE_NODE_ID)
    @staticmethod
    def makeS2aad(homeid, src_node, dst_node, msg, hdr_len):
        aad = []
        if S2CryptoProvider.isLRNode(src_node) or S2CryptoProvider.isLRNode(dst_node):
            aad += [(src_node >> 8) & 0xFF]
            aad += [(src_node) & 0xFF]
            aad += [(dst_node >> 8) & 0xFF]
            aad += [(dst_node) & 0xFF]
        else:
            aad += [src_node & 0xFF]
            aad += [dst_node & 0xFF]
        aad += [(homeid >> 24) & 0xFF]
        aad += [(homeid >> 16) & 0xFF]
        aad += [(homeid >> 8) & 0xFF]
        aad += [(homeid) & 0xFF]
        l = len(msg)
        aad += [(l >> 8) & 0xFF]
        aad += [(l) & 0xFF]
        aad += msg[2:2+hdr_len-2]
        return aad
    @staticmethod
    def decryptCCMAuth(key, nonce, aad, msg_buff):
        payload_len = len(msg_buff) - S2CryptoProvider.MAC_SIZE
        if payload_len < 0:
            return S2CryptoProvider.DECRYPT_CODE_LENGTH, None
        n_blocks = (payload_len // S2CryptoProvider.BLOCK_SIZE) + 1
        P = []
        if payload_len % S2CryptoProvider.BLOCK_SIZE != 0:
            n_blocks += 1
        Sl = []
        block0 = None
        offset = 0
        for i in range(n_blocks):
            ctr_blk = S2CryptoProvider.ccmMakeCounterBlock(nonce, i)
            s = encryptAESBlock(ctr_blk, key)
            if i == 0:
                block0 = s
            else:
                crb = msg_buff[offset:offset+S2CryptoProvider.BLOCK_SIZE]
                p = xorBuff(crb, s)
                offset += S2CryptoProvider.BLOCK_SIZE
                P += p
        crypted_mac = msg_buff[payload_len:payload_len+S2CryptoProvider.MAC_SIZE]
        decryped_mac = xorBuff(crypted_mac, block0)
        logging.debug("decrypted MAC:%s"%(splitHexBuff(decryped_mac)))
        P = P[:payload_len]
        calculated_mac = S2CryptoProvider.calcCCMMAC(key, nonce, aad, P)
        
        logging.debug("calculated MAC:%s"%(splitHexBuff(calculated_mac)))
        if calculated_mac != decryped_mac:
            logging.debug("Payload:%s"%(splitHexBuff(P)))
            return S2CryptoProvider.DECRYPT_CODE_AUTH, None
        return S2CryptoProvider.DECRYPT_CODE_OK, P
    def _extractNetKey(self, home_id, key_cls):
        # Пробуем найти нужный ключ через модуль статистики
        stat = ZWaveStatCollector.getInstance()
        net_key = stat.getNetworkKey(home_id, key_cls)
        if net_key == None:
            logging.warning("Key for %08x, %s not found"%(home_id, key_cls))
            # Нет ключа
            return None
        return net_key
    def getNetworkKeys(self, home_id, key_cls):
        if home_id in self._networks:
            if key_cls in self._networks[home_id]:
                return self._networks[home_id][key_cls]
        else:
            self._networks[home_id] = {}
        net_key = self._extractNetKey(home_id, key_cls)
        if net_key == None:
            return None
        logging.info("Net key:%s (type:%d)"%(splitHexBuff(net_key), key_cls))
        # Генерируем "производные" ключи
        ccm_key, nonce_key, mpan_key = S2CryptoProvider.netkey_expnd(net_key)
        self._networks[home_id][key_cls] = [ccm_key, nonce_key, mpan_key]
        return self._networks[home_id][key_cls]
    @staticmethod 
    def __contextKey(home_id, src_nodeid, dst_nodeid):
        a = min(src_nodeid, dst_nodeid)
        b = max(src_nodeid, dst_nodeid)
        return "%s-%d-%d"%(home_id, a, b)
    def S2Context(self, home_id, src_nodeid, dst_nodeid):
        key = S2CryptoProvider.__contextKey(home_id, src_nodeid, dst_nodeid)
        logging.info("S2 get context (%s, %d, %d, %s)"%(home_id, src_nodeid, dst_nodeid, key))
        if not key in self._contexts:
            logging.info("*** NOT FOUND")
            return None
        #logging.info("*** S2 Context:%s"%(self._contexts[key]))
        return self._contexts[key]
    def getFirstAvaliableKeyClass(self, home_id, lr_mode):
        key_set = self.activeKeySet(lr_mode)
        for key in key_set:
            if self._extractNetKey(home_id, key) != None:
                return key
        return None
    def makeS2Context(self, home_id, src_node_id, dst_node_id, r_nonce, s_nonce, starti_src, starti_dst, key_class =None):
        text = "S2 make context (%s, %d, %d, %s):(%s %s)"%(home_id, src_node_id, dst_node_id, key_class, splitHexBuff(r_nonce), splitHexBuff(s_nonce))
        logging.info(text)
        #print(text)
        lr_mode = S2CryptoProvider.isLRNode(src_node_id) or S2CryptoProvider.isLRNode(dst_node_id)
        key = S2CryptoProvider.__contextKey(home_id, src_node_id, dst_node_id)
        drng = S2DRBGen()
        stat = ZWaveStatCollector.getInstance()
        if key_class == None:
            # Нужен класс безопасности 
            key_class = stat.getKeyS2ClassForNodes(home_id, src_node_id, dst_node_id)
            if key_class == None:
                # Пока он не известен
                key_class = self.getFirstAvaliableKeyClass(home_id, lr_mode)
                logging.info("*** Found key class:%d"%(key_class))
        keys  = self.getNetworkKeys(home_id, key_class)
        if keys == None:
            logging.warning("S2 NO Net Key for (%s, %d)"%(home_id, key_class))
            return None
        #print("nonce_key:%s"%(splitHexBuff(keys[1])))
        initial_state = [s_nonce, r_nonce, {src_node_id:starti_src, dst_node_id:starti_dst}]
        S2CryptoProvider.next_nonce_instantiate(drng, s_nonce, r_nonce, keys[1])
        self._contexts[key] = [drng, key_class, {src_node_id:-1, dst_node_id:-1}, {src_node_id:{}, dst_node_id:{}}, False, initial_state, 0]
        return self._contexts[key]
    @staticmethod
    def activeKeySet(bLR):
        if bLR:
            return [ZWaveStatCollector.NETWORK_KEY_S2_LR_AUTH, ZWaveStatCollector.NETWORK_KEY_S2_LR_ACCESS, ZWaveStatCollector.NETWORK_KEY_CTT]
        return [ZWaveStatCollector.NETWORK_KEY_S2_UNAUTH, ZWaveStatCollector.NETWORK_KEY_S2_AUTH, ZWaveStatCollector.NETWORK_KEY_S2_ACCESS, ZWaveStatCollector.NETWORK_KEY_S0, ZWaveStatCollector.NETWORK_KEY_CTT]
    @staticmethod
    def _modGreater(a, b, interval = S2_VALID_RECALL_INETRVAL):
        ub = (a + interval) & 0xFF
        if ub < a:
            if b <= ub:
                return True
        if b> a:
            return True 
        return False
    @staticmethod
    def _seqDiff(a, b):
        if a >= b:
            return a-b 
        return a+256-b
    @staticmethod
    def calcRawContextIteration(node1_id, node1_seq, node2_id, node2_seq, start_set):
        node1_s_seq = start_set[node1_id]
        node2_s_seq = start_set[node2_id]
        return S2CryptoProvider._seqDiff(node1_seq, node1_s_seq) + S2CryptoProvider._seqDiff(node2_seq, node2_s_seq)
    def calculateNonce(self, context, src_node_id, dst_node_id, src_seq, keys):
        ctx_cls             = context[1]
        last_sequences      = context[2]
        previous_nonces     = context[3]
        active_context      = context[4]
        initial_state       = context[5]
        current_iteration   = context[6]
        initial_state_seq = initial_state[2]
        dst_seq = last_sequences[dst_node_id]
        if(dst_seq == -1):
            dst_seq = initial_state_seq[dst_node_id]
        rnd_nonce = None
        index = 0
        ovf = False
        if(active_context):
            df = S2CryptoProvider._seqDiff(src_seq, last_sequences[src_node_id])
            if (df < S2CryptoProvider.S2_VALID_RECALL_INETRVAL) and (not S2CryptoProvider._modGreater(last_sequences[src_node_id], src_seq)):
                # Пробуем найти такой Nonce если он уже был
                if src_seq in previous_nonces[src_node_id]:
                    rnd_nonce = previous_nonces[src_node_id][src_seq]
                    self._last_decode_warning |= S2CryptoProvider.S2_WARNING_FLAG_NONCE_RECALL
                    logging.info("S2 nonce recall (%d->%d) seq=%d nonce:%s. Duplicate message"%(src_node_id, dst_node_id, src_seq, splitHexBuff(rnd_nonce)))
                    return rnd_nonce
            iteration_count = S2CryptoProvider.calcRawContextIteration(src_node_id, src_seq, dst_node_id, dst_seq, last_sequences)
            if iteration_count == 0:
                logging.error("S2 Nonce. Active context. NULL ITERATION!!! src_node_id:%d  dst_node_id:%d"%(src_node_id, dst_node_id))
            logging.info("S2 Nonce. Active context. Iterate:%d prev_sequence:%s current_src:%d current_dst:%d"%(iteration_count, last_sequences, src_seq, dst_seq))
            last_sequences[src_node_id] = src_seq # В любом случае нужно сохранить порядковый номер последнего пакета 
            while iteration_count:
                rnd_nonce = S2CryptoProvider.next_nonce_generate(context[0])
                iteration_count -= 1 
            context[6] += iteration_count
        else:
            # Контекст пока еще не был синхронизирован - пока еще нет ни одного правильно расшифрованного сообщения
            iteration_count = S2CryptoProvider.calcRawContextIteration(src_node_id, src_seq, dst_node_id, dst_seq, initial_state_seq) + 1
            logging.info("S2 Nonce. Sync context. Iterate:%d init_sequence:%s current_src:%d current_dst:%d"%(iteration_count, initial_state_seq, src_seq, dst_seq))
            context[0] = S2DRBGen()
            S2CryptoProvider.next_nonce_instantiate(context[0], initial_state[0], initial_state[1], keys[1])
            context[6] = iteration_count
            while iteration_count:
                rnd_nonce = S2CryptoProvider.next_nonce_generate(context[0])
                iteration_count -= 1 
            last_sequences[dst_node_id] = dst_seq
            last_sequences[src_node_id] = src_seq
            context[3] = {src_node_id:{}, dst_node_id:{}}
        return rnd_nonce

    def decryptS2Message(self, home_id, src_node_id, dst_node_id, raw_msg):
        parsed_msg = S2CryptoProvider.parseS2MSG(raw_msg)
        lr_mode = S2CryptoProvider.isLRNode(src_node_id) or S2CryptoProvider.isLRNode(dst_node_id)
        s2_context = self.S2Context(home_id, src_node_id, dst_node_id)
        stat = ZWaveStatCollector.getInstance()
        self._last_decode_error = 0
        self._last_decode_warning = 0
        self._last_decode_metadata = {}
        nonce = None
        s_nonce = None
        b_new_context = False
        
        if (s2_context == None) or ("s_nonce" in parsed_msg):
            # Контекст не был инициализирован до этого
            # Попробуем найти Nonce 
            nonce = stat.getNonceForNode(ZWaveStatCollector.NONCE_TYPE_S2_SINGLE, home_id, src_node_id, dst_node_id)
            if nonce == None:
                logging.warning("S2 no NONCE for (%s, %d, %d)"%(home_id, src_node_id, dst_node_id))
                # Нет Nonce - нельзя создать контекст
                self._last_decode_error = S2CryptoProvider.S2_ERR_NO_NONCE
                return None
            nonce_seq = nonce[1]
            nonce = nonce[2]
            # В текущем сообщении должна быть вторая часть Nonce
            if not ("s_nonce" in parsed_msg):
                logging.warning("S2 no SIE for (%s, %d, %d) in message"%(home_id, src_node_id, dst_node_id))
                # Без этого нельзя создать новый контекст - выходим
                self._last_decode_error = S2CryptoProvider.S2_ERR_NO_NONCE
                return None
            s_nonce = parsed_msg["s_nonce"]
            #stat.storeNonce(home_id, src_node_id, dst_node_id, s_nonce, time.time(), True, 1, 0)
            if s2_context != None:
                if nonce_seq < s2_context[2][dst_node_id]:
                    self._last_decode_error = S2CryptoProvider.S2_ERR_OLD_SEQUENCE
                    return None
                #nonce_seq = s2_context[2][dst_node_id]
            s2_context = self.makeS2Context(home_id, src_node_id, dst_node_id, nonce, s_nonce, parsed_msg["sequence"], nonce_seq)
            if s2_context == None:
                logging.warning("Can't create S2 context, seems we have no key (%s)"%(home_id))
                self._last_decode_error = S2CryptoProvider.S2_ERR_NO_KEY
                return None
            b_new_context = True
        aad = S2CryptoProvider.makeS2aad(home_id, src_node_id, dst_node_id, raw_msg, len(parsed_msg["header"]))
        logging.debug("S2 AAD:%s for (%s, %d, %d):%s"%(splitHexBuff(aad), home_id, src_node_id, dst_node_id, splitHexBuff(raw_msg)))
        key_cls_set = S2CryptoProvider.activeKeySet(lr_mode)
        ctx_cls = s2_context[1]
        last_sequences = s2_context[2]
        previous_nonces = s2_context[3]
        b_right_key = s2_context[4]
        if not b_right_key:
            ctx_cls = self.getFirstAvaliableKeyClass(home_id, lr_mode)
        logging.info("--- Decrypting. Key class:%d for:%d, %d "%(ctx_cls, src_node_id, dst_node_id))
        i = 0
        while 1:
            #print(" -- DEC LOOP %d"%(i))
            #print("Key type:%s"%(ctx_cls))
            seq = parsed_msg["sequence"]
            keys  = self.getNetworkKeys(home_id, ctx_cls)
            #print(" -- DEC KEYS")
            if keys != None:
                rnd_nonce = self.calculateNonce(s2_context, src_node_id, dst_node_id, seq, keys)
                logging.debug("RND NONCE:%s"%(splitHexBuff(rnd_nonce)))
                #print(" -- DEC INTERNAL")
                code, payload = S2CryptoProvider.decryptCCMAuth(keys[0], rnd_nonce, aad, parsed_msg["crypted_payload"])
                #print(" -- DEC INTERNAL ---")
                if code == 0:
                    self._last_decode_metadata["seq"] = seq
                    self._last_decode_metadata["nonce"] = rnd_nonce
                    self._last_decode_metadata["aad"] = aad
                    self._last_decode_metadata["main_key"] = keys[0]
                    self._last_decode_metadata["nonce_key"] = keys[1]
                    self._last_decode_metadata["key_class"] = ctx_cls
                    previous_nonces[src_node_id][seq] = rnd_nonce
                    last_sequences[src_node_id] = seq
                    s2_context[4] = True
                    s2_context[1] = ctx_cls
                    #last_sequences[src_node_id] = seq
                    logging.debug("Decrypted:%s key_class:%d"%(splitHexBuff(payload), ctx_cls))
                    stat.registerKeyS2ClassForNodes(home_id, src_node_id, dst_node_id, ctx_cls)
                    return payload
                else:
                    if b_right_key:
                        # Только для пакета c неверным ключем имеет смысл перебирать ключи
                        logging.warning("--- Something goes wrong in S2!")
                        #last_sequences[src_node_id] = seq
                        self._last_decode_error = S2CryptoProvider.S2_ERR_DECR_FAILED_FOR_RKEY
                        return None
            
            if i>=(len(key_cls_set)-1):
                self._last_decode_error = S2CryptoProvider.S2_ERR_NO_KEY
                return None
            # Перебираем ключи
            ki = key_cls_set.index(ctx_cls)
            ki = (ki + 1) % len(key_cls_set)
            ctx_cls = key_cls_set[ki]
            logging.info("--- Trying next key class:%d for:%d, %d "%(ctx_cls, src_node_id, dst_node_id))
            i += 1
        return None

        

