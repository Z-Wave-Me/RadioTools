#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import argparse
import platform
import uuid
import time
#import license
import time

#import programmer.sign
from zme_web_sevices import *
from common.zme_aux import *
from common.zme_sapi import SerialAPICommand
from common.zme_devsn import ZMEDeviceSn

MY_VERSION = "0.1b1"

class RazberrySAPICmd(SerialAPICommand):
    ZME_RAZ_KEY = "0000000000000000000000000000000000000000000000000000000000000000"
    ZME_RAZ_INFOADDR = 0xFFFF00
    ZME_RAZ_INFOLEN = 0x31
    
    ZME_LICENSE_CMD = 0xF5
    ZME_LICENSE_NONCE_SUBCMD = 0x02
    ZME_LICENSE_GET_SUBCMD = 0x00
    ZME_LICENSE_SET_SUBCMD = 0x01

    ZME_LICENSE_CMD_LEN = 0x30
    ZME_LICENSE_NONCE_LEN = 0x08

    ZME_LIC_STATUS_OK = 0
    ZME_LIC_STATUS_TRANSPORT_ERROR = 0x01
    ZME_LIC_STATUS_PROTOCOL_ERROR = 0x02
    ZME_LIC_STATUS_INTERNAL_ERROR = 0x03
    ZME_LIC_STATUS_RESPONSE_ERROR = 0x04
    ZME_LIC_STATUS_RESPONSE_WRONG_LEN = 0x05
    ZME_LIC_STATUS_RESPONSE_DECRYPT_ERROR = 0x06
    ZME_LIC_STATUS_RESPONSE_WRONG_SUBCMD = 0x07
    ZME_LIC_STATUS_NONCE_FAILED = 0x08
    ZME_LIC_STATUS_WRONG_INFO_LENGTH = 0x09
    ZME_LIC_STATUS_WRONG_LICENSE = 0x0A

    ZME_RAZ_LOCK_STATUS_UNLOCK = 0x0
    ZME_RAZ_LOCK_STATUS_DEBUG_LOCK = 0x1
    ZME_RAZ_LOCK_STATUS_APP_UNLOCK = 0x2
    ZME_RAZ_LOCK_STATUS_FULL = 0x3
    

    ZME_LIC_RESULT_OK = 0
    ZME_LIC_RESULT_WRONG_CRC = 0x01
    ZME_LIC_RESULT_WRONG_UUID = 0x02
    ZME_LIC_RESULT_FLASH_WRITE_FAILED = 0x03
    ZME_LIC_RESULT_WRONG_SUBCMD = 0x04
    ZME_LIC_RESULT_EXPECT_NONCE = 0x05
    ZME_LIC_RESULT_RANDOM_FAILED = 0x06

    ZME_FUNC_TYPE_SETUP_NOTIFICATION = 0x01
    ZME_FUNC_TYPE_SETUP_JD = 0x02
    ZME_FUNC_TYPE_SETUP_COMMHANDLER_EXT = 0x03
    ZME_FUNC_TYPE_SETUP_STATIC = 0x04
    ZME_FUNC_TYPE_SETUP_ULTRA_USART = 0x05
    ZME_FUNC_TYPE_SETUP_REAL_ZNIFFER = 0x06
    ZME_FUNC_TYPE_SETUP_REAL_ZNIFFER_REPORT = 0x07
    ZME_FUNC_TYPE_SETUP_EXCEPTION_REPORT = 0x8
    ZME_FUNC_TYPE_SETUP_TIME_STAMP = 0x9
    ZME_FUNC_TYPE_SETUP_PTI_ZNIFFER = 0x0A
    ZME_FUNC_TYPE_SETUP_MODEM = 0x0B

    ZME_FREQ_TABLE = { 	"EU": 	0x00, 
                        "RU": 	0x01,
                        "IN":	0x02,
                        "US": 	0x03,
                        "ANZ":	0x04,
                        "HK": 	0x05,
                        "CN": 	0x06,
                        "JP": 	0x07,
                        "KR": 	0x08,
                        "IL": 	0x09,
                        "MY": 	0x0A,
                        "FK":   0x20
                    }

    def __init__(self, dev_name, baudrate=115200):
        logging.info("SAPI DEV:%s"%(dev_name))
        self._prc_handler = None
        self._binded_interface = False
        super().__init__(dev_name, baudrate)

    def bindToExistedInterface(self, instance):   
        self.port = instance.port
        self.rcv_sof_timeout = 3.5
        self._port_name = instance._port_name
        self._port_baud = instance._port_baud
        self._binded_interface = True
    def cryptData(self, d, iv, key=None):
        main_key = key
        if key == None:
            main_key = bytearray.fromhex(RazberrySAPICmd.ZME_RAZ_KEY)
        return encryptOFB(d, main_key, iv)

    def decryptLicResponse(self, resp, iv=None):
        crypted_data = resp[:RazberrySAPICmd.ZME_LICENSE_CMD_LEN]
        main_iv = iv
        if iv == None:
            main_iv = bytearray(resp[RazberrySAPICmd.ZME_LICENSE_CMD_LEN:])
        decrypt_data = self.cryptData(crypted_data, main_iv)
        s = len(decrypt_data)
        crc16 = calcSigmaCRC16(0x1D0F, decrypt_data, 0, s - 2)
        if crc16 != zme_costruct_int(decrypt_data[s-2:], 2):
            return None
        return decrypt_data
    def getControllerRegion(self):
        region = None
        response = self.setFrequency(0xFF)
        if len(response) < 6:
            return None
        reg_code = response[5]
        return zmeDictVal2Key(RazberrySAPICmd.ZME_FREQ_TABLE, reg_code)
    def setControllerRegion(self, region):
        if region in RazberrySAPICmd.ZME_FREQ_TABLE:
            self.setFrequency(RazberrySAPICmd.ZME_FREQ_TABLE[region])
            return True
        return False
    def extractControllerInfo(self):
        info_md = None
        raw_info = self.getControllerInfo()
        if len(raw_info) > 10:
            info_md = {"version":(raw_info[4]<<8 | raw_info[5]) &0xFFFF, 
                        "vendor":(raw_info[6]<<8 | raw_info[7]) &0xFFFF,
                        "vendor_name":"",
                        "product_type":(raw_info[8]<<8 | raw_info[9]) &0xFFFF,
                        "product_id":(raw_info[10]<<8 | raw_info[11]) &0xFFFF}
            if info_md["vendor"] in license.LicenseClassRazberry.VENDOR_NAMES:
                info_md["vendor_name"] = license.LicenseClassRazberry.VENDOR_NAMES[info_md["vendor"]]
        return info_md
    def sendTestNIFFrame(self, index = 1):
        self.sendNIF(0xff, 0, (index)&0xFF)
        request  = self.recvIncomingRequest()
    def startInclusion(self):
        self.sendCommandUnSz(0x4a, [0xc1], True)
        request  = self.recvIncomingRequest()


    def licCmd(self, data, iv=None):
        ret_data = {"status": RazberrySAPICmd.ZME_LIC_STATUS_OK}
        answ = self.sendCommandUnSz(
            RazberrySAPICmd.ZME_LICENSE_CMD, data, True)
        if answ[0] != 0:
            ret_data["status"] = RazberrySAPICmd.ZME_LIC_STATUS_TRANSPORT_ERROR
            return ret_data
        if answ[3] != RazberrySAPICmd.ZME_LICENSE_CMD:
            ret_data["status"] = RazberrySAPICmd.ZME_LIC_STATUS_PROTOCOL_ERROR
            return ret_data
        ret_data["result"] = answ[4]
        if answ[4] == RazberrySAPICmd.ZME_LIC_RESULT_OK:
            # Команда прошла ждем Response
            resp = self.recvIncomingRequest()
            if resp[0] != 0:
                ret_data["status"] = RazberrySAPICmd.ZME_LIC_STATUS_RESPONSE_ERROR
                return ret_data
            if len(resp[1:]) < RazberrySAPICmd.ZME_LICENSE_CMD_LEN:
                ret_data["status"] = RazberrySAPICmd.ZME_LIC_STATUS_RESPONSE_WRONG_LEN
                return ret_data

            ret_data["raw_response"] = resp[5:]
            #print("RAWDATA:%s"%(splitHexBuff(resp[5:])))
            # Пробуем расшифровать
            d = self.decryptLicResponse(resp[5:], iv)
            if d == None:
                # Не совпала CRC
                ret_data["status"] = RazberrySAPICmd.ZME_LIC_STATUS_RESPONSE_DECRYPT_ERROR
                return ret_data
            else:
                ret_data["response"] = d
        else:
            ret_data["status"] = RazberrySAPICmd.ZME_LIC_STATUS_INTERNAL_ERROR

        return ret_data

    def getNonce(self):
        r = self.licCmd([])
        if r["status"] != RazberrySAPICmd.ZME_LIC_STATUS_OK:
            return r
        r["nonce"] = r["response"][2:2+RazberrySAPICmd.ZME_LICENSE_NONCE_LEN]
        return r
    def syncWithController(self, max_wait = 2.0):
        start = time.time()
        try:
            old_timeout = self.port.getReadTimeout()
            self.port.setReadTimeout(0.1)
        #if self.port.inWaiting() > 0:
        #    data = self.port.Read(self.port.inWaiting())
        #    self.sendAck()
            req = self.recvIncomingRequest()
            logging.info("INCOMING REQ:%s"%(splitHexBuff(req)))
            while (time.time() - start) < max_wait:
                info = self.getControllerInfo()
                if info[0] == SerialAPICommand.RECV_OK:
                    self.port.setReadTimeout(old_timeout)
                    return True
            self.port.setReadTimeout(old_timeout)
        except:
            return False
        return False
    def getHomeID(self):
        answ = self.sendCommandUnSz(0x20,[])
        if answ[0] != SerialAPICommand.RECV_OK:
           return None 
        md = {"home_id":answ[4:4+4],"node_id":answ[8]}
        return md   
      
    def setupTxPower(self, dbm, base_dbm = 0, no_reset = False):
        answ = self.sendCommandUnSz(0x0B,[0x04, dbm, base_dbm])
        if answ[0] != SerialAPICommand.RECV_OK:
           return False 
        if not no_reset:
            self.softReset()
        return True
    def getTxPower(self):
        answ = self.sendCommandUnSz(0x0B,[0x08])
        if answ[0] != SerialAPICommand.RECV_OK:
           return False, None
        return True, answ[0x5]
    def setupStaticMode(self, on_off):
        answ = self.sendCommandUnSz(0xF8,[0x04, 0x01, on_off & 0x01])
        if answ[0] != SerialAPICommand.RECV_OK:
           return False 
        return True
    def setupUARTBaudrate(self, baudrate):
        answ = self.sendCommandUnSz(0xF8,[RazberrySAPICmd.ZME_FUNC_TYPE_SETUP_ULTRA_USART] + zme_int_toarr(baudrate, 4) )
        if answ[0] != SerialAPICommand.RECV_OK:
           return False 
        return True
    def setupPTI(self, pti_on, baud_rate):
        # data = usapi.sendProgCmd(usapi.FUNC_ID_ZME_SERIAL_API_OPTIONS, [usapi.ZME_FUNC_TYPE_SETUP_PTI_ZNIFFER, usapi.ZME_FUNC_TYPE_SETUP_PTI_ZNIFFER_SET, mode] + zme_aux.zme_int_toarr(230400, 0x4))
        mode = 0x00
        if pti_on:
            mode = 0x01
        answ = self.sendCommandUnSz(0xF8,[RazberrySAPICmd.ZME_FUNC_TYPE_SETUP_PTI_ZNIFFER, 0x01, mode] + zme_int_toarr(baud_rate, 4) )
        if answ[0] != SerialAPICommand.RECV_OK:
           return False 
        return True
    # data = usapi.sendProgCmd(usapi.FUNC_ID_ZME_SERIAL_API_OPTIONS, [usapi.ZME_FUNC_TYPE_SETUP_ULTRA_USART] + list(intToBytearrayLsbMsb(new)))
        
    def getStaticMode(self):
        answ = self.sendCommandUnSz(0xF8,[0x04, 0x02])
        if answ[0] != SerialAPICommand.RECV_OK:
           return False, None
        return True, answ[6]
    def getPti(self):
        answ = self.sendCommandUnSz(0xF8,[RazberrySAPICmd.ZME_FUNC_TYPE_SETUP_PTI_ZNIFFER, 0x02])
        if answ[0] != SerialAPICommand.RECV_OK:
           return False, None
        return True, answ[6:]
    def getForSupportGet(self):
        answ = self.sendCommandUnSz(0xF8,[0x0D, 0x02])
        if answ[0] != SerialAPICommand.RECV_OK:
           return False, None
        return True, answ[6:]
    def getBoardInfo(self):
        info = {"status":RazberrySAPICmd.ZME_LIC_STATUS_OK}
        r = self.readNVM(RazberrySAPICmd.ZME_RAZ_INFOADDR, RazberrySAPICmd.ZME_RAZ_INFOLEN)
        #print(r)
        if(len(r) > 28):
            info["core_version"] = zme_costruct_int(r[4:4+2],2, False)
            info["build_seq"] = zme_costruct_int(r[6:6+4],4, False)
            info["build_ts"] = zme_costruct_int(r[10:10+4],4, False)
            info["hw_revision"] = zme_costruct_int(r[14:14+2],2, False)
            info["sdk_version"] = zme_costruct_int(r[16:16+4],4, True)
            info["chip_uuid"] = zme_costruct_int(r[20:20+8], 8, False)
            info["sn_raw"] = r[28:44]
            info["bootloader_version"] = zme_costruct_int(r[44:48], 4, False)
            info["bootloader_crc32"] = zme_costruct_int(r[48:52], 4, False)
            info["lock_status"] = r[52]
            if(len(r) > 53):
                info["se_version"] = zme_costruct_int(r[53:57], 4, False)
            if(len(r) >= 59):
                info["family"] = zme_costruct_int(r[57:58], 1, False)
                info["chip"] = zme_costruct_int(r[58:59], 1, False)
            if(len(r) >= 63):
                info["crc_key"] = zme_costruct_int(r[59:63], 4, False)
        else:
            info["status"] = RazberrySAPICmd.ZME_LIC_STATUS_WRONG_INFO_LENGTH
        return info
        
    def createMsgPacket(self, subcmd, d):
        pak = [subcmd] + d
        pak += [0xFF]*(RazberrySAPICmd.ZME_LICENSE_CMD_LEN - len(pak) - 2)
        pak += zme_int_toarr(calcSigmaCRC16(0x1D0F, pak, 0, len(pak)), 2)
        return pak

    def getLicense(self):
        license = {"status": RazberrySAPICmd.ZME_LIC_STATUS_OK}
        nonce = self.getNonce()

        license["ivX"] = nonce
        if not ("nonce" in nonce):
            license["status"] = RazberrySAPICmd.ZME_LIC_STATUS_NONCE_FAILED
            return license
        #print("Nonce:%s"%(splitHexBuff(nonce["nonce"])))
        #print("Response:%s"%(splitHexBuff(nonce["response"])))
        
        ivX = bytearray(nonce["nonce"])
        raw_msg = self.createMsgPacket(RazberrySAPICmd.ZME_LICENSE_GET_SUBCMD, [])
        IvY = uuid.uuid4().bytes[:8]
        Iv = ivX + IvY
        #print("ivLen:%s"%(len(Iv)))
        crypted = self.cryptData(raw_msg, Iv)
        r = self.licCmd(crypted + list(IvY), Iv)
        if r["status"] != RazberrySAPICmd.ZME_LIC_STATUS_OK:
           return  r
        r["license"] = r["response"]
        return r
    def setLicense(self, pack):
        res = {"status": RazberrySAPICmd.ZME_LIC_STATUS_OK}
        nonce = self.getNonce()
        res["ivX"] = nonce
        if not ("nonce" in nonce):
            res["status"] = RazberrySAPICmd.ZME_LIC_STATUS_NONCE_FAILED
            return res
        raw_msg = self.createMsgPacket(RazberrySAPICmd.ZME_LICENSE_SET_SUBCMD, list(pack))
        ivX = bytearray(nonce["nonce"])
        IvY = uuid.uuid4().bytes[:8]
        Iv = ivX + IvY
        crypted = self.cryptData(raw_msg, Iv)
        r = self.licCmd(crypted + list(IvY), Iv)
        if r["status"] != RazberrySAPICmd.ZME_LIC_STATUS_OK:
           res["status"] = r["status"]
           return  res
        if r["response"][0] != RazberrySAPICmd.ZME_LICENSE_SET_SUBCMD:
           res["status"] = RazberrySAPICmd.ZME_LIC_STATUS_PROTOCOL_ERROR
           return  res
        if r["response"][1] != RazberrySAPICmd.ZME_LIC_STATUS_OK:
           res["status"] = RazberrySAPICmd.ZME_LIC_STATUS_WRONG_LICENSE
           res["err_code"] = r["response"][1]
        return res
    def setupPrcHandler(self, handler):
        self._prc_handler = handler
    def writeDataToNVM(self, addr, bin_data, offset):
        nvmaddr = addr
        data_remains 	= len(bin_data) - offset
        data_quant 		= 128
        data_writed     = 0
        while(data_remains):
            if self._prc_handler != None:
                self._prc_handler((data_writed * 100.0) / (len(bin_data)))
            #printStatus("Writing NVM data", (data_writed * 100.0) / (len(ret_data))) 
            len_send = data_quant
            if(data_remains < data_quant):
                len_send = data_remains
            buff = []
            buff += bin_data[offset:offset+len_send]
            if(len(buff) == 1):
                buff += [0xFF]
            res = self.writeNVM(nvmaddr, buff)
            if(res[0] != SerialAPICommand.RECV_OK):
                return False
            offset 			+= len_send
            data_remains 	-= len_send
            data_writed 	+= len_send
            nvmaddr			+= len_send
        return True
    def writeFileToNVM(self, addr, filename, offset=0):
        bin_data = loadFWFile(filename)
        if bin_data == None:
            return False, bin_data
        return self.writeDataToNVM(addr, bin_data, offset), bin_data

    def reflashBootloader(self, bootloaderimagefile, addr = 0x3a000):
        res, data = self.writeFileToNVM(addr, bootloaderimagefile)
        if not res:
            return False,-1
        answ = self.sendCommandUnSz(0xF4, [], True)
        if (answ[0] != 0):
            return False,-2
        resp = self.recvIncomingRequest()
        return ((resp[0] == 0) and (resp[5] == 0)), resp[5]
    def reflashFirmware(self,fwimagefile, addr = 0x3a000):
        res, data = self.writeFileToNVM(addr, fwimagefile)
        if not res:
            return False
        self.softReset()
        return True
    def __del__(self):
        logging.info("Razberry SAPI destructor")
        if not self._binded_interface:
            self.port.Close()
    
def printRazberryBoardInfo(info):
    print("\n\tFIRMWARE:")
    print("\t\tZME CORE VERSION: \t%04x"%(info["core_version"]))
    print("\t\tBUILD SEQUENCE: \t%08d"%(info["build_seq"]))
    build_ts  = datetime.datetime.fromtimestamp(float(info["build_ts"])).strftime("%Y-%m-%dT%H:%M:%S")
    print("\t\tBUILD DATETIME: \t%s"%(build_ts))
    print("\t\tSDK VERSION: \t\t%08x"%(info["sdk_version"]))
    if "se_version" in info and info["se_version"] != 0x0:
        print("\t\tSE VERSION: \t\t%08x"%(info["se_version"]))
    print("\t\tBOOTLOADER VERSION: \t%08x"%(info["bootloader_version"]))
    print("\t\tBOOTLOADER CRC32: \t%08x"%(info["bootloader_crc32"]))
    if "crc_key" in info:
        print("\t\tKEY CRC32: \t\t%08x"%(info["crc_key"]))
    if "family" in info and "chip" in info:
        family_name, chip_name = programmer.sign.ZMEProgSign._get_chip_family_int_to_str(info["family"], info["chip"])
        if family_name != None:
            print("\t\tFAMILY: \t\t%s"%(family_name))
        if chip_name != None:
            print("\t\tCHIP: \t\t\t%s"%(chip_name))
    print("\n\tHARDWARE:")
    print("\t\tREVISION: \t%04x"%(info["hw_revision"]))
    print("\t\tCHIP UUID: \t%016x"%(info["chip_uuid"]))
    if info["lock_status"] in LKTEXT:
        print("\t\tLOCK: \t\t%s"%(LKTEXT[info["lock_status"]]))
    else:
        print("\t\tLOCK:UNKNOWN")
    print("\n\tSN:")
    devsn = ZMEDeviceSn(info["sn_raw"])
    print("\t\tRAW:%s"%(splitHexBuff(info["sn_raw"])))
    print(devsn.toText())

if __name__ == "__main__":
    OPTIONS = { "MODE":{"VALUES":["STATIC", "BRIDGE"]}, 
                "REGION":{"VALUES":RazberrySAPICmd.ZME_FREQ_TABLE.keys()}}
    logging.basicConfig(format='%(levelname)-8s [%(asctime)s]  %(message)s', level=logging.DEBUG,
                    filename='%s/ZMERaz7-%s.log' % (getScriptPath(), strftime("%Y-%m-%d", gmtime())))
    LKTEXT={RazberrySAPICmd.ZME_RAZ_LOCK_STATUS_UNLOCK:"UNLOCKED",
            RazberrySAPICmd.ZME_RAZ_LOCK_STATUS_DEBUG_LOCK:"DBG_LOCKED",
            RazberrySAPICmd.ZME_RAZ_LOCK_STATUS_APP_UNLOCK:"UNLOCKED",
            RazberrySAPICmd.ZME_RAZ_LOCK_STATUS_FULL:"ERASE_LOCKED"}
    
    def infoFunc(args):
        print("INFO")
        sapi = RazberrySAPICmd(args.device)
        if sapi.port.Open():
            sync = sapi.syncWithController(10.0)
            if not sync:
                printError("Can't sync with controller")
                return
            info = sapi.getBoardInfo()
            if(info["status"] == RazberrySAPICmd.ZME_LIC_STATUS_OK):
                print("\n\t\t\t\tBOARD INFORMATION")
                printRazberryBoardInfo(info)
            else:
                print("Error: Can't extract board information!")
            controller_info = sapi.extractControllerInfo()
            if controller_info != None:
                print("\n\tCONTROLLER INFORMATION:")
                print("\t\tSAPI VERSION: \t%d.%d"%((controller_info["version"] >> 8) & 0xFF, controller_info["version"] & 0xFF))
                print("\t\tVENDOR: \t%04x (%s)"%(controller_info["vendor"], controller_info["vendor_name"]))
                print("\t\tPRODUCT_TYPE: \t%04x"%(controller_info["product_type"]))
                print("\t\tPRODUCT_ID: \t%04x"%(controller_info["product_id"]))
                print("\t\tREGION: \t%s"%(sapi.getControllerRegion()))
                
            md = sapi.getHomeID()
            if md != None:
                print("\t\tHOME_ID:\t%s"%(splitHexBuff(md["home_id"]).strip()))
                print("\t\tNODE_ID:\t%s"%(md["node_id"]))
            res, m = sapi.getTxPower()
            if res:
                print("\t\tPOWER TX:\t0x%02X"%(m))
            lic = sapi.getLicense()
            if lic["status"] == RazberrySAPICmd.ZME_LIC_STATUS_OK:
                print("\n\tLICENSE:")
                print("\t\tRAW:\t   %s"%(splitHexBuff(lic["license"][2:2+32], 64)))
                parsed_lic = license.LicenseClassRazberry()
                print(parsed_lic.toText(lic["license"][2:2+32]))
                lic_svc = ZMELicenseService()
                brd_uuid = "%x"%(info["chip_uuid"])
                web_lic = lic_svc.getCurrentLicense(brd_uuid)
                if web_lic != None:
                    if 'license' in web_lic:
                        lic_text = web_lic['license']
                        print("\t\tYour current WEB license: %s"%(lic_text))
                print("\t\tYou can purchase a license for your device by following the link: %s"%(lic_svc.webUIURL(brd_uuid)))
            print("\n\tOPTIONS:")
            res, m = sapi.getStaticMode() 
            if res:
                mode_str = "UNKNOWN"
                if m == 0x01:
                    mode_str = "STATIC"
                elif m == 0x00:
                    mode_str = "BRIDGE"
                #print("M:%d"%(m))
                print("\t\tMODE:    %s"%(mode_str))
            res, m = sapi.getPti()
            if res:
                if m[0x0] == 0x1:
                    num = zme_costruct_int(m[1:1+4],4)
                    status = "ENABLED "
                else:
                    num = 0x0
                    status = "DISABLED"
                print("\t\tPTI:     %s|%d"%(status, num))
                pass
            res, m = sapi.getForSupportGet()
            if res:
                if m[0x0] == 0x1:
                    status = "ENABLED "
                else:
                    status = "DISABLED"
                count = (m[0x2] << 0x8 )| m[0x1]
                print("\t\tSUPPORT: %s|0x%02X"%(status, count))
                pass
            sapi.port.Close()
    def licFunc(args):
        sapi = RazberrySAPICmd(args.device)
        if sapi.port.Open():
            sapi.recvIncomingRequest() # из-за нужно
            res = sapi.setLicense(bytearray.fromhex(args.package))
            if res["status"] != RazberrySAPICmd.ZME_LIC_STATUS_OK:
                print("Error. Status:%d"%(res["status"] ))
            sapi.port.Close()
    def NVMPrcHandler(percentage):
        printCurrStatusProgress(percentage)
    def bootFunc(args):
        sapi = RazberrySAPICmd(args.device)
        printStatus("Opening port")
        if sapi.port.Open():
            finallizeStatus()
            sapi.setupPrcHandler(NVMPrcHandler)
            a = int(args.address, 0)
            printStatus("Writing BL. IMG")
            ok, code = sapi.reflashBootloader(args.filename, a)
            if ok:
                finallizeStatus()
            else:
                finallizeStatus("FAILED ERR:%02x"%(code))
            sapi.port.Close()
        else:
            finallizeStatus("FAILED")
    def incFunc(args):
        sapi = RazberrySAPICmd(args.device)
        if sapi.port.Open():
            sapi.startInclusion()
            sapi.port.Close()

    def FWFunc(args):
        sapi = RazberrySAPICmd(args.device)
        printStatus("Opening port")
        if sapi.port.Open():
            sapi.setupPrcHandler(NVMPrcHandler)
            a = int(args.address, 0)
            printStatus("Writing FW. IMG")
            if sapi.reflashFirmware(args.filename, a):
                finallizeStatus()
            else:
                finallizeStatus("FAILED")
            sapi.port.Close()
        else:
            print("Can't open port! %s"%(args.device))
    def optFunc(args):
        sapi = RazberrySAPICmd(args.device)
        if not sapi.port.Open():
            print("Can't open port:%s"%(args.device))
            return 
        for o in args.options:
            parts = o.split("=")
            if len(parts) == 2:
                if not (parts[0] in OPTIONS):
                    print("Unknownk option \"%s\""%(parts[0])) 
                    continue
                if not (parts[1] in OPTIONS[parts[0]]["VALUES"]):
                    print("Wrong option \"%s\" value:%s"%(parts[0], parts[1])) 
                    continue
                if parts[0] == "MODE":
                    val = 0
                    if parts[1] == "STATIC":
                        val = 1
                    sapi.setupStaticMode(val)
                if parts[0] == "REGION":
                    if not (parts[1] in RazberrySAPICmd.ZME_FREQ_TABLE):
                        print("Wrong region:%s"%(parts[1]))
                        continue
                    sapi.setControllerRegion(parts[1])
            else:
                print("WRONG option format:%s. The right one is OPTION=VALUE"%(o))
                continue
        sapi.port.Close()
    
    '''
    def calibrateRadio(self):
        prod = self.cfg["production_db"]["products"][self.session_md["target_product"]]
        self.lcd.printString("CONNECTING", LCD1602.LCD_LINE_1)
        self.powerOnRazberry(True)
        sapi = RazberrySAPICmd(self.cfg["device"]["serial_dev"])
        if not sapi.port.Open():
            self.showMessage("UART. ERROR.", ["CODE:%d"%(ZMERaz7Stand.TEST_RESULT_UART_PORTOPENERR),"CAN'T OPEN SERIAL"], self.cfg["ui"]["error_delay"], ZMERaz7Stand.STATE_WAITIING_SESSION, self.cfg["ui"]["error_blinker_times"], True)
            return
        self.startAnimation(16, 0.25)
        sync = sapi.syncWithController(20.0)
        self.stopAnimation()
        if not sync:
            self.showMessage("UART. ERROR.", ["CODE:%d"%(ZMERaz7Stand.TEST_RESULT_UART_NOSYNC),"CAN'T SYNC WITH CONTROLLER", "CHECK UART PINS." , "DEVICE FAILED!"], self.cfg["ui"]["error_delay"], ZMERaz7Stand.STATE_WAITIING_SESSION, self.cfg["ui"]["error_blinker_times"], True)
            return
        info = sapi.getBoardInfo() 
        info["cap"] = sapi.extractControllerInfo()
        info["freq"] = sapi.getControllerRegion()
        info["node_info"] = sapi.getHomeID()
        home_id = info["node_info"]["home_id"]
        self.lcd.printString("SETUP RX POWER", LCD1602.LCD_LINE_1)
        if not sapi.setupTxPower(prod["base_power"]):
            self.showMessage("DEVICE. ERROR.", ["CODE:%d"%(ZMERaz7Stand.TEST_RESULT_CANT_SET_RXP),"RX POWER SETUP."], self.cfg["ui"]["error_delay"], ZMERaz7Stand.STATE_WAITIING_SESSION, self.cfg["ui"]["error_blinker_times"], True)
            return
        sync = sapi.syncWithController(20.0)
        if info["freq"] != self.session_md["freq"]:
            self.lcd.printString("(TEST)FREQ->%s"%(self.session_md["freq"]), LCD1602.LCD_LINE_1)
            sapi.setControllerRegion(self.session_md["freq"])
            self.startAnimation(16, 0.25)
            sync = sapi.syncWithController(20.0)
            self.stopAnimation()
            if not sync:
                self.showMessage("DEVICE. ERROR.", ["CODE:%d"%(ZMERaz7Stand.TEST_RESULT_UART_NOSYNC_TESTFREQ),"CAN'T SYNC WITH CONTROLLER",], self.cfg["ui"]["error_delay"], ZMERaz7Stand.STATE_WAITIING_SESSION, self.cfg["ui"]["error_blinker_times"], True)
                return
        self.lcd.printString("RADIO TEST CL.", LCD1602.LCD_LINE_1)
        logging.info("RADIO CALIBRATION HOMEID:%s FREQ:%s POWER:%d"%(splitHexBuff(home_id), self.session_md["freq"], prod["base_power"]))
        self.zniffer.resumeZ()
        while 1:
            start_ct = time.time()
            rssi_min = 1000
            rssi_max = -1
            rssi_avg = 0
            rssi_n = 0
            for i in range(self.cfg["zniffer"]["test_frames_count"]):
                sapi.sendTestNIFFrame(i)
                time.sleep(0.05)
            #logging.info("RADIO CALIBRATION START: MIN:%d MAX:%d AVG:%2.1f (N=%d) elapsed:%2.3f"%(rssi_min, rssi_max, rssi_avg, rssi_n, time.time() - start_ct))
            
            time.sleep(0.5)
            radio_frames = self.zniffer.read_frames(self.last_zniff_seq)
            if len(radio_frames) != 0:
                self.last_zniff_seq = radio_frames[len(radio_frames)-1]["zniffer_seq"]+1
            #print("RF FRAME BUFF LEN:%s LAST:%d"%(len(radio_frames), self.last_zniff_seq))
            for f in radio_frames:
                if f["home_id"] == home_id:
                    if rssi_min > f["rssi"]:
                        rssi_min = f["rssi"]
                    if rssi_max < f["rssi"]:
                        rssi_max = f["rssi"]
                    rssi_avg += f["rssi"]
                    rssi_n += 1
            if rssi_n != 0:
                rssi_avg /= rssi_n
            logging.info("RADIO CALIBRATION RESULTS: MIN:%d MAX:%d AVG:%2.1f (N=%d) elapsed:%2.3f"%(rssi_min, rssi_max, rssi_avg, rssi_n, time.time() - start_ct))
            self.lcd.printString("%02d %02d %2.1f %2d"%(rssi_min, rssi_max, rssi_avg, rssi_n), LCD1602.LCD_LINE_2)
            if self.btn_thread.checkEvent(zmeButton.EVENT_BTN_CLICK) or self.term.wasStopped():
                self.zniffer.pauseZ()
                self.translateState(ZMERaz7Stand.STATE_WAITIING_SESSION)
                self.powerOnRazberry(False)
                break
    '''
    def rebootFunc(args):
        baud = int(args.baudrate, 10)
        print("Reboot")
        sapi = RazberrySAPICmd(args.device, baud)
        if sapi.port.Open():
            sapi.softReset()
            sapi.port.Close()
    def niftestFunc(args):
        sapi = RazberrySAPICmd(args.device)
        printStatus("Opening port")
        if not sapi.port.Open():
            printError("Can't open port:%s"%(args.device))
            return 
        finallizeStatus()
        printStatus("Syncing with controller")
        sync = sapi.syncWithController(20.0)
        if not sync:
            printError("Can't sync with controller")
        finallizeStatus()
        printStatus("Setup TX power")
        main_v = int(args.power, 0)
        base_v = int(args.base_power, 0)
        sapi.setupTxPower(main_v,base_v)
        sync = sapi.syncWithController(20.0)
        if not sync:
            printError("Can't sync with controller after power setup")
        finallizeStatus()
        printStatus("Sending Test frames",0)
        num = int(args.number_of_packets)
        for i in range(num):
            total = i*100.0 / num
            printCurrStatusProgress(total)
            sapi.sendTestNIFFrame(i)
            time.sleep(0.05)
        printStatus("Closing port")
        sapi.port.Close()
        finallizeStatus()

    def dummyFunc(args):
        print("*** Platform: %s Version: %s ***"%(platform.system(), MY_VERSION))
    def Main():
        logging.debug("\nStarting on %s.\nARGS:%s\nVERSION:%s MD5:%s" % (
            platform.system(), ' '.join(sys.argv), MY_VERSION, "-"))
        parser = argparse.ArgumentParser(description='ZWave>ME Programmer tool for 7th generation. \n Welcome :)')

        parser.set_defaults(func=dummyFunc)
        subparsers = parser.add_subparsers()

        parserInfo = subparsers.add_parser('info', help="Prints board information")
        parserInfo.add_argument('-d', '--device', help="Device file (UNIX) or COM-port (WINDOWS)", required=True)
        parserInfo.set_defaults(func=infoFunc)
        parserLic = subparsers.add_parser('lic', help="Setups license from given package")
        parserLic.add_argument('package', help="Hexadecimal license package")
        parserLic.add_argument('-d', '--device', help="Device file (UNIX) or COM-port (WINDOWS)", required=True)
        parserLic.set_defaults(func=licFunc)
        parserBoot = subparsers.add_parser('boot', help="Upgrades board bootloader")
        parserBoot.add_argument('filename', help="Device file (UNIX) or COM-port (WINDOWS)")
        parserBoot.add_argument('-a', '--address', default="0x3a000", help="Address to store image in NVM. Use leading 0x to specify hexadecimal value.")
        parserBoot.add_argument('-d', '--device', help="Device file (UNIX) or COM-port (WINDOWS)", required=True)
        parserBoot.set_defaults(func=bootFunc)
        parserFirmware = subparsers.add_parser('firmware', help="Upgrades main baord firmware")
        parserFirmware.add_argument('filename', help="Device file (UNIX) or COM-port (WINDOWS)")
        parserFirmware.add_argument('-a', '--address', default="0x3a000" ,help="Address to store image in NVM. Use leading 0x to specify hexadecimal value.")
        parserFirmware.add_argument('-d', '--device', help="Device file (UNIX) or COM-port (WINDOWS)", required=True)
        parserFirmware.set_defaults(func=FWFunc)
        '''
        parserInc = subparsers.add_parser('inc_test', help="Inclusion test")
        parserInc.add_argument('-d', '--device', help="Device file (UNIX) or COM-port (WINDOWS)", required=True)
        parserInc.set_defaults(func=incFunc)
        '''
        parserReboot = subparsers.add_parser('reboot', help="Reboots board via SAPI")
        parserReboot.add_argument('-d', '--device', help="Device file (UNIX) or COM-port (WINDOWS)", required=True)
        parserReboot.add_argument('-b', '--baudrate', help="UART baudrate, default == 115200 for SAPI", default="115200")
        parserReboot.set_defaults(func=rebootFunc)
        
        parserOptions = subparsers.add_parser('config', help="Controls additional settings")
        parserOptions.add_argument('-d', '--device', help="Device file (UNIX) or COM-port (WINDOWS)", required=True)
        parserOptions.add_argument('-o', '--options', default = [], action="append", help="setups option")
        parserOptions.set_defaults(func=optFunc)
        parserNIFTest = subparsers.add_parser('radio_test', help="Sends a number of test frames using selected power settings")
        parserNIFTest.add_argument('-d', '--device', help="Device file (UNIX) or COM-port (WINDOWS)", required=True)
        parserNIFTest.add_argument('-p', '--power', default = "20",  help="Max power value in 10th of dBms")
        parserNIFTest.add_argument('-b', '--base_power', default = "0",  help="Base power value in 10th of dBms")
        parserNIFTest.add_argument('-n', '--number_of_packets', default = "10",  help="Number of test packets")
        parserNIFTest.set_defaults(func=niftestFunc)
        
        args = parser.parse_args()

        args.func(args)

    Main()
    


