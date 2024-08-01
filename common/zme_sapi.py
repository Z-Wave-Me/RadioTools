#!/usr/bin/python
# -*- coding: utf-8 -*-
import platform
import logging
import time
from common.zme_serialport import Port
from common.zme_aux import * 

class SerialAPICommand:
    port = None
    seqNo = 1


    SOF_CODE = 0x01
    NACK_CODE = 0x15
    CAN_CODE = 0x18
    ACK_CODE = 0x06
    REQUEST_CODE = 0x00
    RESPONSE_CODE = 0x01

    SUCCESS_CODE = 0x31
    FAIL_CODE = 0x30

    WRITECYCLE_OK_CODE = 0x0D

    RECV_OK = 0x00
    RECV_NOACK = 0x01
    RECV_INVALIDDATALEN = 0x02
    RECV_INVALIDCRC = 0x03
    RECV_WRONGDATA = 0x04
    RECV_NOSOF = 0x05
    RECV_INVALIDDATALEN_EXT = 0x06

    ADDITIONAL_SIZE = 3
    

    def __init__(self, mport, baud = 230400, dtr = True):
        if baud == -1:
            baud = 115200
        self.port = Port(mport, baud, dtr=dtr)
        self.rcv_sof_timeout = 3.5
        self._port_name = mport
        self._port_baud = baud
        self._port_dtr = dtr
        self._use_ext_api = False
        self._send_quant_size = 240

    def setRcvSofTimeout(self, timeout:float) -> None:
        self.rcv_sof_timeout = timeout
    def getRcvSofTimeout(self) -> float:
        return (self.rcv_sof_timeout)
    def setBaudOnTheGo(self, new_baudrate):
        if self.port.isOpened():
            self.port.Close(False, True)
        self.port = Port(self._port_name, new_baudrate, dtr=self._port_dtr)
        self._port_baud = new_baudrate
        self.port.Open(True)
    def enableExtAPI(self, en = True):
         self._use_ext_api = en
    def setDataQuantum(self, sz):
        self._send_quant_size = sz
    def _getQuantumSize(self):
        if (self._send_quant_size > 240) and (not self._use_ext_api):
            return 240
        return self._send_quant_size
    def setPortExcPolicy(self, bRaise):
        self.port._raise_exception = bRaise
    def sendAck(self):
        logging.debug(">> ACK")
        self.port.Write([self.ACK_CODE])
        self.port.Flush()
    def sendNack(self):
        logging.debug(">> NACK")
        self.port.Write([self.NACK_CODE])
        self.port.Flush()
    def waitSOF(self):
        sof_timeout = time.time() + self.rcv_sof_timeout
        #self.port.setReadTimeout(0.01)
        while sof_timeout>time.time():
            if self.port.inWaiting() > 0:
                logging.debug(">> SOF RD")
                sof = self.port.Read(1)
                if len(sof) < 1:
                    continue
                if sof[0] == self.SOF_CODE:
                    return True
            else:
                time.sleep(0.0005)
        #self.port.setReadTimeout(0.5)
        return False

    def recvIncomingRequest(self):
        if not self.waitSOF():
            return [self.RECV_NOSOF]
        len_data = self.port.Read(1)
        if (len(len_data) < 1):
            return [self.RECV_NOSOF]
        len_data = len_data[0]
        if len_data == 0x0:
            if (self._use_ext_api):
                len_data = self.port.Read(2)
                if (len(len_data) != 2):
                    self.sendNack()
                    return [self.RECV_INVALIDDATALEN_EXT]
                out = [self.RECV_OK] + [0x0] + list(len_data)
                len_data = (len_data[0x0] << 0x8) | len_data[0x1]
                if (len_data < 3):
                    self.sendNack()
                    return [self.RECV_INVALIDDATALEN_EXT]
                len_data = len_data - 0x1
                buff_data = self.port.Read(len_data)
                if (len(buff_data) != len_data):
                    self.sendNack()
                    return [self.RECV_INVALIDDATALEN_EXT]
                crc16 = calcSigmaCRC16(0xCC9C, buff_data, 0, len(buff_data) - 0x2)
                if crc16 != ((buff_data[len(buff_data) - 0x2] << 0x8) | buff_data[len(buff_data) - 0x1]):
                    self.sendNack()
                    return [self.RECV_INVALIDCRC]
                self.sendAck()
                out = out + buff_data[:len(buff_data) - 0x2]
                # print(splitHexBuff(out))
                return out
        buff_data = self.port.Read(len_data)
        test_buff = [self.SOF_CODE, len_data]
        test_buff += buff_data
        printBuffHex("<< ", test_buff)
        if (len(buff_data) != len_data):
            self.sendNack()
            return [self.RECV_INVALIDDATALEN]
        check_sum = Checksum([len_data] + buff_data[0:len_data - 1])
        if (check_sum != buff_data[len_data - 1]):
            self.sendNack()
            return [self.RECV_INVALIDCRC]
        self.sendAck();
        return [self.RECV_OK] + [len_data] + buff_data[0:len_data - 1]
    def sendData(self, cmd, databuff, have_callback=False):
        data_len = len(databuff) + self.ADDITIONAL_SIZE
        if (have_callback):
            data_len += 1
        if (data_len > 255): 
            if (self._use_ext_api):
                # 16-ти битный режим
                #data_len += 2 # отдельно 2-ва байта под длину
                crc_data =   [0x00] + [self.REQUEST_CODE] + [cmd] + databuff
                final_data = [0x00] + [(data_len >> 8)& 0x0FF] + [data_len & 0x0FF] + [self.REQUEST_CODE] + [cmd] + databuff
                if (have_callback):
                    final_data += [self.seqNo]
                crc16 = calcSigmaCRC16(0x1D0F, crc_data, 0, len(crc_data))
                final_data = [self.SOF_CODE] + final_data + [(crc16 >> 8) & 0xFF] + [(crc16) & 0xFF]
                printBuffHex(">> (E):", final_data)
                # print(splitHexBuff(final_data))
                self.port.Write(final_data)
                self.seqNo += 1
                self.seqNo &= 0XFF  # 1 byte
                return 
        
        final_data = [data_len & 0x0FF] + [self.REQUEST_CODE] + [cmd] + databuff
        if (have_callback):
            final_data += [self.seqNo]
        crc = Checksum(final_data)
        final_data = [self.SOF_CODE] + final_data + [crc]
        self.seqNo += 1
        self.seqNo &= 0XFF  # 1 byte
        printBuffHex(">> ", final_data)
        # print(splitHexBuff(final_data))
        self.port.Write(final_data)
        self.port.Flush()
    def sendCommandUnSz(self, cmd, databuff, enabled_callback=False, add_retcode = False, retries = 3):
        # Чистим результаты всех предыдущих действий
        if(self.port.inWaiting() != 0):
            rbuff = self.port.Read(self.port.inWaiting())
        #timeout = time.time() + 3.0
        while 1:
            self.sendData(cmd, databuff, enabled_callback)
            rbuff = self.port.Read(1)
            if (len(rbuff) == 0):
                logging.debug("NO ACK")
                return [self.RECV_NOACK]
            if rbuff[0] == self.ACK_CODE:
                break

            if rbuff[0] == self.CAN_CODE:
                logging.warning("!!!CANCODE")
                result = self.recvIncomingRequest()
                retries -= 1
                if retries > 0:
                    continue
            if rbuff[0] == self.NACK_CODE:
                logging.debug("<< NACK")
                retries -= 1
            if retries > 0:
                continue
            return [self.RECV_NOACK]
        logging.debug("<< ACK")
        result = self.recvIncomingRequest()
        if(add_retcode):
            result = [0] + result
        return result



    def readNVM(self, addr, size):
        return self.sendCommandUnSz(0x2A, [(addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF, (size >> 8) & 0xFF,
                                           size & 0xFF], False);

    def writeNVM(self, addr, buff):
        size = len(buff)
        return self.sendCommandUnSz(0x2B, [(addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF, (size >> 8) & 0xFF,
                                           size & 0xFF] + buff, False);

    def softReset(self):
        return self.sendCommandUnSz(0x08, [], False);
    def checkBootImage(self, addr=0x3a000):
        return self.sendCommandUnSz(0x08, [0x04] + zme_int_toarr(addr, 3, bInv=True), False);
    def eraseDevNVM(self):
        return self.sendCommandUnSz(0x08, [0x05], False);
    def rescueInit(self):
        return self.sendCommandUnSz(0x08, [0x0A], False);
    def rescueLearnMode(self, timeout, security):
        return self.sendCommandUnSz(0x08, [0x07, timeout & 0xFF, security & 0xFF], False);
    def rescueSetEventOutput(self, on):
        return self.sendCommandUnSz(0x08, [0x09, on & 0xFF], False);
    def rescueSendData(self, src_node_id, dst_node_id, tx_opts, s2_key, data_buff):
        return self.sendCommandUnSz(0x08, [0x08, src_node_id & 0xFF, dst_node_id & 0x0FF, tx_opts & 0x0FF, s2_key & 0xFF] + data_buff, False);

    def pushSketch(self, addr, size, crc16):
        old_sof_to = self.getRcvSofTimeout()
        self.setRcvSofTimeout(10.0)
        res =  self.sendCommandUnSz(0x08, [0x01] + zme_int_toarr(addr, 3, bInv=True)+ zme_int_toarr(size, 2, bInv=True) + zme_int_toarr(crc16, 2, bInv=True), False);
        self.setRcvSofTimeout(old_sof_to)
        return res
    def railTest(self, mode, region, channel, power, timeout):
        return self.sendCommandUnSz(0xF8, [0x0B, mode, region, channel, power] + zme_int_toarr(timeout, 4, bInv=True), False);
    def setReadTimeout(self, value):
        self.port.setReadTimeout(value)
    def freezeSketch(self, retries = 50, retry_func = None):
        sleep_time = 0.01
        if platform.system() == "Windows":
            sleep_time = 0.05 
        self.port.setReadTimeout(0.1)
        while retries:
            rcv = self.sendCommandUnSz(0x08, [0x02], False);
            #rcv = self.recvIncomingRequest()
            if len(rcv)>4:
                if (rcv[0] == self.RECV_OK) and (rcv[3] == 0x08) and (rcv[4] == 0x00):
                    self.port.setReadTimeout(2.0)
                    return True
                #print("BUFF:%s"%(splitHexBuff(rcv)))
            #rbuff = self.port.Read(self.port.inWaiting())
            if retry_func!= None:
                retry_func(retries)
            time.sleep(sleep_time)
            retries -= 1
        self.port.setReadTimeout(2.0)
        return False
        

    def setFrequency(self, freq):
        return self.sendCommandUnSz(0xF2, [freq], False, add_retcode = True);

    def getControllerInfo(self):
        return self.sendCommandUnSz(0x07, [], False);

    def sendNIF(self, node, rxopts, req_num):
        return self.sendCommandUnSz(0x12,[node, rxopts, req_num], False);


g_rtry_text="Syncing with Z-Uno ('RST' btn?)"
def simpRTryFun(rtr):
    global g_rtry_text
    bar = ["*  ", " * ", "  *", " * "]
    indx = len(bar) -1 - rtr%len(bar)
    printStatus("%s [%s]"%(g_rtry_text, bar[indx]))



class SerialAPIUtilities:
    cmdinterface = None
    no_port_oc = False
    last_status_opened = False

    RAIL_MODE_CARRIER = 1
    RAIL_MODE_PN9_STREAM = 2
    RAIL_MODE_10_STREAM = 3
    RAIL_MODE_PKG_STREAM = 4
    RAIL_MODE_MODEM = 5

    RAIL_MODE_CARRIER_STR = "CARRIER"
    RAIL_MODE_PN9_STREAM_STR = "PN9"
    RAIL_MODE_10_STREAM_STR = "B10"
    RAIL_MODE_PKG_STREAM_STR = "PKG"
    RAIL_MODE_MODEM_STR = "MODEM"

    DETECT_MODE_AUTO= 0
    DETECT_MODE_SAPI= 1
    DETECT_MODE_ZUNO= 2
    ZUNO_BAUD = [230400, 230400*2, 230400*4, 115200]
    
    

    def __init__(self, mport, baud=230400):
        self._dev_name = mport
        self.cmdinterface = SerialAPICommand(self._dev_name, baud)
        self.last_status_opened = False
        self.no_port_oc = False
        self._rst_sync_handler = None
        
    def setPortExPolicy(self, bRaise):
        self.cmdinterface.setPortExcPolicy(bRaise)
    def setDeviceRSTActuator(self, handler):
        self._rst_sync_handler = handler
    def loadBinaryFile(filename):
        ret_arr = []
        with open(filename, "rb") as f:
            byte = f.read(1)
            while byte != "":
                # Do stuff with byte.
                ret_arr += [byte]
                byte = f.read(1)
        return ret_arr

    def writeFileToNVM(self, nvmaddr, datafile, data_offset=0, wrsize = None, bCheck=False):

        frm = 'hex'
        if (datafile.endswith(".bin") or datafile.endswith(".gbl")):
            frm = 'bin'
        hex_data = IntelHex()

        try:
            hex_data.fromfile(datafile, format=frm)
        except Exception as e:
            printError("%s while loading the bootloader file:%s " % (e, datafile))
            return False, None

        stt = time.time()
        ret_data = hex_data.tobinarray()[data_offset:]
        data_crc16 = calcSigmaCRC16(0x1D0F, ret_data, 0, len(ret_data))
        offset = 0
        data_remains = len(ret_data) 
        if wrsize != None:
            data_remains = wrsize 

        #data_remains -= data_offset
        if data_remains<0:
            printInfo("Nothing to write!")
        data_quant = self.cmdinterface._getQuantumSize()
        data_writed = 0

        #sum16 = 0x1D0F;
        start_nvm_addr = nvmaddr
        retry_count = 0
        while (data_remains):
            printStatus("Writing NVM data", (data_writed * 100.0) / (len(ret_data)))
            len_send = data_quant
            if (data_remains < data_quant):
                len_send = data_remains
            # buff = self.
            buff = []
            buff += ret_data[offset:offset + len_send]
            #if (len(buff) == 1):
            #    buff += [0xFF]
            #print buff 
            
            divv = len_send % 4
            if divv != 0:
                buff += [0xFF]*(4-divv)
            res = self.cmdinterface.writeNVM(nvmaddr, buff)
            
            #print "SUM:%x"%(sum16)
            #sum16 = calcSigmaCRC16(sum16, buff, 0, len(buff))
            if (res[0] != SerialAPICommand.RECV_OK):
                finallizeStepStatus("Writing NVM data", "FAILED")
                printError("Can't write NVM data! at=%x %s. Device doesn't respond! " % (nvmaddr, splitHexBuff(res)))
                return False, ret_data
            if (len(res) < 5):
                printError("Can't write NVM data! at=%x %s. Wrong reply length!" % (nvmaddr, splitHexBuff(res)))
                return False, ret_data
            if (res[4] != 0x01):
                printError("Can't write NVM data! at=%x %s. Device internal memory error!" % (nvmaddr, splitHexBuff(res)))
                return False, ret_data

            offset += len_send
            data_remains -= len_send
            data_writed += len_send
            nvmaddr += len_send
        stt = time.time() - stt
        finallizeStepStatus("Writing NVM data", "OK")
        printInfo("Elapsed:%2.4f"%(stt))
        if(bCheck):
            in_data = []
            data_remains = len(ret_data) 
            data_read = 0
            nvmaddr = start_nvm_addr
            offset = 0
            while (data_remains):
                len_send = data_quant
                if (data_remains < data_quant):
                    len_send = data_remains
                printStatus("Reading back NVM data", (data_read * 100.0) / (len(ret_data)))
                rs = self.cmdinterface.readNVM(nvmaddr, len_send)
                if (rs == None) or (rs[0] != 0):
                    printError("Can't read NVM data! at=%x. Device internal memory error!" % (nvmaddr))
                    return False, ret_data
                in_data += rs[4:]
                offset += len_send
                data_read += len_send
                data_remains -= len_send
                nvmaddr += len_send
            finallizeStepStatus("Reading back NVM data", "OK")
            printStatus("Checking CRC")
            data_crc16i = calcSigmaCRC16(0x1D0F, in_data, 0, len(in_data))
            if(data_crc16i != data_crc16):
                printError("Wrong data in device NVM! CRC mismatches (Expected:%16x got:%16x)!" % (data_crc16, data_crc16i))
                df = zme_arrayDiff(ret_data, in_data)
                print("______________DATA DIFFF DUMP______________")
                print("ADDRESS   WROTE   READ")
                print("___________________________________________")
                print(zme_formatArrayDiff(df))
                return False, ret_data
            else:
                finallizeStepStatus("Checking CRC", "OK")
        return True, ret_data
    def backupNVM(self, datafile, addr, size, save_offset=0):
        frm = 'hex'
        if(datafile.endswith(".bin")):
            frm = 'bin'
        fw_data = []
        data_remains = size
        data_quant   = 64
        #printStatus("Openning port")
        #self.cmdinterface.port.Open()
        finallizeStepStatus("Openning port","OK")
        first = True
        curr_addr = addr
        data_readed = 0
        while data_remains:
            printStatus("Reading NVM data", (data_readed * 100.0) / (size)) 
            curr_size = data_quant
            if(curr_size > data_remains):
                curr_size = data_remains
            info = []
            info = self.cmdinterface.readNVM(curr_addr, curr_size)
            if(len(info) > 4):  
                fw_data.extend(info[4:])
            if(first):
                first = False
            data_readed     += curr_size
            curr_addr       += curr_size
            data_remains    -= curr_size
        
        self.cmdinterface.port.Close()
        finallizeStepStatus("Reading NVM data","OK")

        printStatus("Saving data")

        hex_data = IntelHex()

        if save_offset>0:
            fw_data =  [0x00]*save_offset + fw_data #array('B',[0x00]*save_offset) + np.asarray(fw_data)
        hex_data.frombytes(fw_data)
        try:
            hex_data.tofile(datafile, format = frm)
        except:
            raise ProgrammerError("Can't write firmware file \"%s\""%datafile, -2)

        finallizeStepStatus("Saving data","OK")

    def writeArrayToNVM(self, nvmaddr, array, data_offset=0):

        '''
        ret_data  = loadBinaryFile(datafile)
        '''
        ret_data = array
        offset = data_offset
        data_remains = len(ret_data) - data_offset
        data_quant = 128
        data_writed = 0

        while (data_remains):
            printStatus("Writing NVM data", (data_writed * 100.0) / (len(ret_data)))
            len_send = data_quant
            if (data_remains < data_quant):
                len_send = data_remains
            # buff = self.
            buff = []
            buff += ret_data[offset:offset + len_send]
            if (len(buff) == 1):
                buff += [0xFF]
            #print buff 
            res = self.cmdinterface.writeNVM(nvmaddr, buff)
            if (res[0] != SerialAPICommand.RECV_OK):
                raise ProgrammerError("Can't write NVM data! at=%x" % (nvmaddr + offset), -1)

            offset += len_send
            data_remains -= len_send
            data_writed += len_send
            nvmaddr += len_send

        finallizeStepStatus("Writing NVM data", "OK")

        return ret_data 

    def cleanNVM(self, nvmaddr, size, value = 0xFF, seg_name = ""):

        offset          = 0#nvmaddr
        data_remains    = size
        data_quant      = 128
        data_writed     = 0

        saved_nvm_addr  = nvmaddr

        status = "Cleaning %s NVM"%(seg_name)
        while(data_remains):
            printStatus(status, (data_writed * 100.0) / (size)) 
            len_send = data_quant
            if(data_remains < data_quant):
                len_send = data_remains
            buff = [value]*len_send
            if(len(buff) == 1):
                buff += [value]
            res = self.cmdinterface.writeNVM(nvmaddr, buff)
            if(res[0] != SerialAPICommand.RECV_OK):
                raise ProgrammerError("Can't clean NVM data! at=%x"%(nvmaddr + offset), -1)
            offset          += len_send
            data_remains    -= len_send
            data_writed     += len_send
            nvmaddr         += len_send 

        finallizeStepStatus(status,"OK")

    def getLastStatusOpened(self) -> bool:
        return (self.last_status_opened)

    def setLastStatusOpened(self, status:bool) -> None:
        self.last_status_opened = status


    def openPort(self, forced_open = False):
        if((not self.no_port_oc) or (forced_open)):
            if self.cmdinterface.port.isOpened():
                self.cmdinterface.port.Close(b_close_conn=False)
            printStatus("Openning port")
            if self.cmdinterface.port.Open():
                self.last_status_opened = True
                finallizeStepStatus("Openning port", "OK")
            #else:
            #    finallizeStepStatus("Openning port", "Failed")
        if(forced_open):
            self.no_port_oc = True
        return self.cmdinterface.port.isOpened()
        
    def closePort(self, forced_close = False, b_silent = False):
        if(forced_close):
            self.no_port_oc = False 
        if(not self.no_port_oc):
            if not b_silent:
                printStatus("Closing port")
            try:
                if self.cmdinterface.port != None:
                    self.cmdinterface.port.Close(b_silent,True)
            except:
                pass
            if not b_silent:
                finallizeStepStatus("Closing port","OK")    
            

    def reflashFirmware(self, fwimagefile, addr):
        try:
            self.openPort()
        except Exception as e:
            printError("Can't open port:%s"%(self.cmdinterface.port._dev_name))
            return
        

        offset = 0
        if(addr > 0x10000):
            offset = 0x1800
        self.writeFileToNVM(addr+offset, fwimagefile, 0x1800)

        printStatus("Setting update flag")
        self.cmdinterface.writeNVM(addr - 2, [0x00, 0x01])
        finallizeStepStatus("Setting update flag", "OK")

        self.cmdinterface.readNVM(addr - 2, 2)

        printStatus("Reseting chip")
        self.cmdinterface.softReset()
        finallizeStepStatus("Reseting chip", "OK")

        printStatus("Waiting for update (DO NOT UPLUG Z-UNO!)")
        time.sleep(40.0);
        finallizeStepStatus("Waiting for update", "OK")

        self.closePort()        

    def rebootChip(self):
        self.openPort()     
        printStatus("Reseting chip")
        self.cmdinterface.softReset()
        finallizeStepStatus("Reseting chip", "OK")
        self.closePort()



    def freezeUserSketch(self):
        self.openPort()     
        printStatus("Stoping the user code")
        # Останавливаем пользовательский скетч
        self.cmdinterface.freezeSketch()

        finallizeStepStatus("Stoping the user code","OK")
        
        self.closePort()
    def _resyncZunoPort(self, baud=230400):
        is_win = (platform.system() == "Windows")
        self.closePort(True)
        #if is_win:
        time.sleep(0.25) # Время нужное на перезарядку конденсатора на линии DTR
        self.cmdinterface = SerialAPICommand(self._dev_name, baud)
        #self.cmdinterface.port.setBaudrate(baud)
        if not self.openPort(True):
            return False  
        if self._rst_sync_handler != None:
            self._rst_sync_handler()
        if is_win:
            time.sleep(0.5)  
        while True:
            l = self.cmdinterface.recvIncomingRequest()
            if (len(l) != 0) and (l[0] == self.cmdinterface.RECV_OK):
                return True 
            if self.cmdinterface.port.inWaiting() == 0x0:
                return False
        return True
    def syncWithDevice(self, retries = 50, baud=230400, bNoABD = False, bNoReset=False):
        baud_arr = SerialAPIUtilities.ZUNO_BAUD
        if(baud < len(baud_arr)):
            baud = baud_arr[baud]
        if not baud in baud_arr:
            baud = baud_arr[0]
        baud_sync_map = 0
        target_baud = baud
        sync_text = "Syncing with Z-Uno"
        printStatus(sync_text)
        b_sync = False
        if not bNoReset:
            for i in range(len(baud_arr)):
                printStatus(sync_text+" [trying %d] (press RST)"%(baud))
                if self._resyncZunoPort(baud):
                    b_sync = True
                    break
                if bNoABD:
                    break # Используем только заданную частоту - не пытаемся ничего подбирать
                baud_sync_map |= (1 << baud_arr.index(baud))
                ii1 = findMapAvIndex(baud_sync_map, len(baud_arr))
                if(ii1 == -1):
                    break
                baud = baud_arr[ii1]
            if(not b_sync):
                printError("Can't sync with Z-Uno") 
                return False
            if baud != target_baud:
                printStatus(sync_text+" [setup new baudrate: %d] "%(target_baud))
                # Нужно установить новую частоту
                rcv = self.cmdinterface.sendCommandUnSz(0x08, [0x02], False);
                if len(rcv)<4:
                    finallizeStepStatus(sync_text, "FAILED")
                    printError("Can't start system mode (1)") 
                    return False
                self.applyPrams({"uart_baud":target_baud})
                # Еще раз открываем порт
                if not self._resyncZunoPort(target_baud): 
                    finallizeStepStatus(sync_text, "FAILED")
                    printError("Can't sync after baudrate modification")
                    return False
            finallizeStepStatus(sync_text, "OK")
        if not self.cmdinterface.freezeSketch(retries, retry_func=simpRTryFun):
            finallizeStepStatus(sync_text, "FAILED")
            printError("Can't sync with Z-Uno bootloader. It doesn't respond!") 
            return False
        finallizeStepStatus(sync_text, "OK")
        return True
    def setCustomFreq(self, freq_code):
        if not self.syncWithDevice():
            self.closePort(True)
            return
        status_text = "Setting up frequency code:%02x"%(freq_code)
        printStatus(status_text)
        result = self.cmdinterface.setFrequency(freq_code)
        if len(result) == 0:
            finallizeStepStatus(status_text,"FAILED")
        else:
            finallizeStepStatus(status_text,"OK")
        self.closePort(True)
    def waitForBootPacket(self, status, timeout = 30, bUUART=False):
        start_tm = time.time()
        printStatus(status)
        text_prog = ["*  "," * ", "  *", " * "]
        i = 0
        while((time.time() - start_tm) < timeout):
            printStatus(status+"[%s]"%(text_prog[i%len(text_prog)]))
            if(self.cmdinterface.port.inWaiting() > 0):
                printStatus(status)
                result = self.cmdinterface.recvIncomingRequest()
                if(bUUART and (result != None)):
                    finallizeStatus("OK")
                    return 0, 1
                if len(result) < 6:
                    finallizeStatus("WRONG LEN")
                    return -2, 0
                if result[3] != 0x08:
                    finallizeStatus("WRONG REQ")
                    return -3, result[3] 
                if result[5] != 0x01:
                    finallizeStatus("ERROR_CODE%02x"%(result[5]))
                    return -3, result[5]
                finallizeStatus("OK") 
                return 0, result[5]
            i += 1
            time.sleep(0.1)
        printStatus(status)
        finallizeStatus("TIMEOUT")    
        return -1, 0

    def uploadBootloader(self, filename, bSync=True, addr = 0x3A000, bTest=False, UUARTBaud=0, bNoAB=False):
        #if(UUARTBaud != 0):
        #    if not self.reconnectToUUART(UUARTBaud):
        #        return False
        if bSync:
            if not self.syncWithDevice(baud=UUARTBaud, bNoABD=bNoAB):
                self.closePort(True)
                return False
        status_text = "Loading image"
        printStatus(status_text)
        res, sk_data = self.writeFileToNVM(addr, filename, 0, bCheck=bTest)
        ret = True
        if res:
            finallizeStepStatus(status_text,"OK")
            status_text = "Rebooting Chip"
            printStatus(status_text)
            result = self.cmdinterface.checkBootImage(addr)
            finallizeStepStatus(status_text,"OK")
            res,opt_code = self.waitForBootPacket("Checking image")
            if res == 0:
                res,opt_code = self.waitForBootPacket("Waiting for bootloader", bUUART=((UUARTBaud!=0) and (UUARTBaud!=230400)))
            else:
                printError("Selected bootloader image doesn't fit to your board!")
                printInfo("Don't worry! Maybe you have already install the latest one.")
                printInfo("Z-Wave SDK 7.19+ doesn't support downgrading or image reloading. Only the newer version will succeed.")
                self.rebootChip()
                ret = False
        else:
            finallizeStepStatus(status_text,"FAILED")
            ret = False
        self.closePort(True)
        return ret
    def _parseHWRevCode(self, hw_rev, md):
        md["product_type"] = "Unknown"
        md["product_variant"] = "Unknown"
        md["chip_type"] = "Unknown"
        md["schematic_variant"] = hw_rev & 0x0F
        product_type =      (hw_rev >> 12) & 0x0F
        chip_type =         (hw_rev >> 8) & 0x0F
        product_variant =   (hw_rev >> 4) & 0x0F
        if product_type in HWREV_PRODUCT_TYPE:
            v = HWREV_PRODUCT_TYPE[product_type]
            md["product_type"] = v[0]
            if product_variant in v[1]:
                md["product_variant"] = v[1][product_variant]
            if chip_type in HWREV_CHIPTYPE:
                md["chip_type"] = HWREV_CHIPTYPE[chip_type]
        return md
    def detectBaud(self, baud):
        device = self.cmdinterface._port_name
        common_baud_list = [115200, 230400, 460800, 921600]
        if baud == 0:
            baud = 115200
        baud_list = [baud]
        if baud == -1:
            baud_list = common_baud_list
        else:
            for b in common_baud_list:
                if not (b in baud_list):
                    baud_list += [b]
        for b in baud_list:
            logging.info("Trying baudrate:%s"%(b))
            self.cmdinterface.port = Port(device, b)
            if self.openPort(True):
                logging.info("Port opened")
                info = self.cmdinterface.readNVM(0xFFFF00, 0x40)
                logging.info("Result:%s"%(info))
                if info[0] == 0:
                    return info, b
                self.closePort(True)
        return None, None
    def extractProductInfo(self, mode = DETECT_MODE_AUTO, baud = 0):
        md = {}
        device = self.cmdinterface._port_name
        current_baud = self.cmdinterface._port_baud
        info = []
        if mode == SerialAPIUtilities.DETECT_MODE_AUTO:
            info, baud = self.detectBaud(baud)
            if info == None:
                # Возможно это Razberry и она залипла в состоянии модема -  попробуем ее ресетнуть 
                #self.cmdinterface.softReset()
                #self.closePort(True)
                if platform.system() == "Windows":
                    time.sleep(0.1)    
                # ZUno
                self.cmdinterface.port = Port(device, 230400)
                if not self.syncWithDevice(50, current_baud):
                    self.closePort(True)
                    self.cmdinterface.port = Port(device, current_baud)
                    return -1, None
                baud = 230400
                info = self.cmdinterface.readNVM(0xFFFF00, 0x01)
        elif mode == SerialAPIUtilities.DETECT_MODE_SAPI:
            #self.cmdinterface.port = Port(device, 115200)
            #self.openPort(True)
            info, baud = self.detectBaud(baud)
            if info == None:
                return -11, None
            info = self.cmdinterface.readNVM(0xFFFF00, 0x40)
            if info[0] != 0:
                return -1, None
        elif mode == SerialAPIUtilities.DETECT_MODE_ZUNO:
            #info, baud = self.detectBaud(baud)
            self.cmdinterface.port = Port(device, 230400)
            if not self.syncWithDevice(50, current_baud):
                return -1, None
            info = self.cmdinterface.readNVM(0xFFFF00, 0x01)
        if len(info) < 12:
            print("info:%s"%(info))
            return -3, md
        bts = info[4:]
        md["version"] = (bts[0] << 8) | (bts[1])
        md["build_number"] = (bts[2] << 24) | (bts[3] << 16) |  (bts[4] << 8) | (bts[5])
        md["build_ts"] = (bts[6] << 24) | (bts[7] << 16) |  (bts[8] << 8) | (bts[9])
        md["hw_rev"] =  (bts[10] << 8) | (bts[11])
        md["uart_baudrate"] = baud
        #md["chip_uid"] =  bts[16+1:16+1+8]
        md = self._parseHWRevCode(md["hw_rev"], md)
        return 0, md

    def readBoardInfo(self, bSync = True, bClose=True, bSketchMD = False, bKeys = True, custom_baud=0, bNoABD = False, bNoRST = False):
        md = {}
        if bSync:
            if not self.syncWithDevice(50, custom_baud, bNoABD, bNoRST):
                self.closePort(True)
                return -1, md
       
        info = self.cmdinterface.readNVM(0xFFFF00, 0x01)
        if len(info) < 10:
            return -3, md
        param_info = self.cmdinterface.readNVM(0xFFE000, 0x09)
        if len(param_info) < 10:
            return -3, md
        bLR = False
        param_info = param_info[4:]
        r = zmeRemapDictVal2Key(FREQ_TABLE_U7, param_info[1])
        if r != None:
            if (r == "US_LR") or (r == "US") or  (r == "US_LR_BK"):
                bLR = True
        bts = info[4:]
        md["version"] = (bts[0] << 8) | (bts[1])
        md["build_number"] = (bts[2] << 24) | (bts[3] << 16) |  (bts[4] << 8) | (bts[5])
        md["build_ts"] = (bts[6] << 24) | (bts[7] << 16) |  (bts[8] << 8) | (bts[9])
        md["hw_rev"] =  (bts[10] << 8) | (bts[11])
        code_sz_shift = 0
        if md["build_number"] > 1116:
            code_sz_shift = 1
            md["code_size"] = zme_costruct_int(bts[12:12+3], 3, False)
        else:
            md["code_size"] =  (bts[12] << 8) | (bts[13])
        md["ram_size"] =  (bts[14+code_sz_shift] << 8) | (bts[15+code_sz_shift])
        md["chip_uid"] =  bts[16+code_sz_shift:16+code_sz_shift+8]
        md["chip_uuid"] = zme_costruct_int(bts[16+code_sz_shift:16+code_sz_shift+8], 8, False)
        md["s2_pub"] =  bts[24+code_sz_shift:24+code_sz_shift+16]
        md["dbg_lock"] =  0xFF
        md["home_id"] = 0
        md["node_id"] = 0
        md["smart_qr"] = ""
        md["custom_code_offset"] = None
        #print("BTS_LEN:%d"%(len(bts)))
        md["ext_nvm"] = 0
        if len(bts) > (44+code_sz_shift):
            md["dbg_lock"] = bts[40+code_sz_shift]
            md["home_id"] = zme_costruct_int(bts[41+code_sz_shift:41+code_sz_shift+4], 4, False)
            md["node_id"] = bts[45+code_sz_shift]
        shift_smrt = 11
        if len(bts) > (46+code_sz_shift):
            if md["build_number"] < 1669:
                shift_smrt = 90
                md["smart_qr"] = bytes(bts[46+code_sz_shift:46+code_sz_shift+90]).decode("ascii",errors='ignore')
            else:
                md["zwdata"] = {    "s2_keys":bts[46+code_sz_shift], 
                                    "device_type":zme_costruct_int(bts[47+code_sz_shift:47+code_sz_shift+2], 2, False),
                                    "device_icon":zme_costruct_int(bts[49+code_sz_shift:49+code_sz_shift+2], 2, False),
                                    "vendor":zme_costruct_int(bts[51+code_sz_shift:51+code_sz_shift+2], 2, False),
                                    "product_type":zme_costruct_int(bts[53+code_sz_shift:53+code_sz_shift+2], 2, False),
                                    "product_id":zme_costruct_int(bts[55+code_sz_shift:55+code_sz_shift+2], 2, False),
                                    "version": md["version"],
                                    "LR":bLR}
                #print("ZW data:%s"%(md["zwdata"]))
                md["smart_qr"] = compile_zwave_qrcode(md["zwdata"], md["s2_pub"], md["version"])
        if len(bts) > (46+shift_smrt+code_sz_shift+4):
            md["custom_code_offset"] = zme_costruct_int(bts[46+code_sz_shift+shift_smrt:46+code_sz_shift+shift_smrt+4], 4, False)
            boot_addr = 0x3a000
            if(md["custom_code_offset"] > 0x36000):
                boot_addr = 0x40000
            md["boot_offset"] = boot_addr
            
        if len(bts) > (46+shift_smrt+code_sz_shift+8):
            prod_shift = 46+code_sz_shift+shift_smrt+4
            md["prod_raw"] = bts[prod_shift:prod_shift+16]
            md["prod_parent_uuid"] = bts[prod_shift:prod_shift+8]
            md["prod_parent_uuid"] = md["prod_parent_uuid"][::-1]
            md["prod_ts"] = zme_costruct_int(bts[prod_shift+8:prod_shift+8+4], 4, True)
            md["prod_sn"] = zme_costruct_int(bts[prod_shift+8+4:prod_shift+8+4+3], 3, True)
            md["prod_crc8"] = bts[prod_shift+8+4+3]
            lic_shift = prod_shift+8+4+4
            md["lic_subvendor"] = zme_costruct_int(bts[lic_shift:lic_shift+2], 2, False)
            #print("CRC:%2x MASK:%s"%(bts[prod_shift+8+4+3], splitHexBuff(bts[lic_shift:lic_shift+2+8])))
            md["lic_flags"] = zme_costruct_int(bts[lic_shift+2:lic_shift+2+8], 8, True)
            lic_bytes = bts[lic_shift:lic_shift+10]
            md["lic_crc16"] = calcSigmaCRC16(0x1D0F, lic_bytes, 0, len(lic_bytes))
            if len(bts) > (lic_shift + 10):
                md["max_default_power"] = bts[lic_shift+10]
            if len(bts) > (lic_shift + 11):
                md["ext_nvm"] = zme_costruct_int(bts[lic_shift+11:lic_shift+11+2], 2, False)
            if len(bts) > (lic_shift + 13):
                md["chip_family"] = bts[lic_shift+13]
                md["chip_type"] = bts[lic_shift+14]
                md["chip_family_name"] = "Unknown"
                md["chip_type_name"] = "Unknown"
                if md["chip_family"] in ZME_CHIP_NAMES:
                    md["chip_family_name"] = ZME_CHIP_NAMES[md["chip_family"]]["name"]
                    if md["chip_type"] in ZME_CHIP_NAMES[md["chip_family"]]["chips"]:
                         md["chip_type_name"] = ZME_CHIP_NAMES[md["chip_family"]]["chips"][md["chip_type"]]
                md["keys_hash"] = zme_costruct_int(bts[lic_shift+15:lic_shift+15+4], 4, False)
                md["se_version"]= zme_costruct_int(bts[lic_shift+15+4:lic_shift+15+4+4], 4, False)
                
        if len(bts) == 1:
            return -3, md
        if bKeys:
            key_info = self.cmdinterface.readNVM(0xFFCCC0, 0x40)
            md["s2_keys_raw"] = key_info[4:]

        if bSketchMD and (md["custom_code_offset"] != None):
            #print("---OFFSET:%08x"%(md["custom_code_offset"]));
            # Проверять Serial0.println((uint32_t)sizeof(ZUNOCodeHeader_t)); 
            nn_info = self.cmdinterface.readNVM(md["custom_code_offset"], 108) # ! Размер структуры хидера

            if len(nn_info) > 10:
                nn_bts = nn_info[4:]
                #print("RAW HEADER:%s"%(splitHexBuff(nn_bts)))
                sign = ""
                if nn_bts[0] != 0xFF:
                    sign = bytearray(nn_bts[:8]).decode('utf-8',"ignore")
                sk_name = ""
                if(nn_bts[54] != 0xFF):
                    sk_name = bytearray(nn_bts[56:56+48]).decode('utf-8',"ignore").replace("\x00","")
                #print("SKETCH RAW:%s"%(splitHexBuff(nn_bts)))
                md["sketch"] = {"sign":sign,
                                     "core_version":zme_costruct_int(nn_bts[8:8+2], 2, False),
                                     "code_size":zme_costruct_int(nn_bts[10:10+2], 2),
                                     "crc16":zme_costruct_int(nn_bts[12:12+2], 2),
                                     "flags":zme_costruct_int(nn_bts[16:16+4], 4),
                                     "fw_id":zme_costruct_int(nn_bts[20:20+2], 2),
                                     "jump_table_offset":zme_costruct_int(nn_bts[24:24+4], 4),
                                     "build_ts":zme_costruct_int(nn_bts[28:28+4], 4),
                                     "console_pin":nn_bts[32],
                                     "console_baud":zme_costruct_int(nn_bts[36:36+4], 4),
                                     "sketch_version":zme_costruct_int(nn_bts[40:40+2], 2),
                                     "ota_extra_fwcount":nn_bts[42],
                                     "ota_descr_addr":zme_costruct_int(nn_bts[44:44+4], 4),
                                     "ota_pincode":zme_costruct_int(nn_bts[48:48+4], 4),                                   
                                     "ota_extra_offset":zme_costruct_int(nn_bts[52:52+4], 4),
                                     "name":sk_name}
            #print("SKETH MD:%s"%(md["sketch"]))
        if bClose:
            self.closePort(True)
        return 0, md
    def dumpNVM(self, addr, size,filename=None, offset=0, baudrate=230400, bNoAB=False):
        if not self.syncWithDevice(baud=baudrate, bNoABD=bNoAB):
            self.closePort(True)
            return
        if filename!=None:
            self.backupNVM(filename, addr, size, offset)
        else:
            if size > 0x80:
                size = 0x80
            info = self.cmdinterface.readNVM(addr, size)
            print("NVM DATA:\n%s"%(splitHexBuff(info[4:])))
        self.closePort(True)
    
    '''
    uint8_t     secure_mode;
	uint8_t     maxLRTxDb;
	uint8_t     flags; 
	uint8_t     ml_interval;

    enum{
	ZUNO_CFGFILE_FLAG_DBG 		= 0x01,
	ZUNO_CFGFILE_FLAG_LED_OFF 	= 0x02,
	ZUNO_CFGFILE_FLAG_RFLOG 	= 0x04
};
    '''
    def applyPrams(self, param_map):
        info = self.cmdinterface.readNVM(0xFFE000, 0x09)
        bts = info[4:]
        min_len = 8
        if len(bts) < min_len:
            bts += [0x00]*(min_len-len(bts))
        if "freq" in param_map:
            bts[1] = param_map["freq"]
            if len(bts)>8:
                bts[8] = param_map["freq"]
        if "sec" in param_map:
            bts[4] = param_map["sec"]
        if "main_pow" in param_map:
            bts[2] = param_map["main_pow"]
        if "adj_pow" in param_map:
            bts[3] = param_map["adj_pow"]
        if "lr_pow" in param_map:
            bts[5] = param_map["lr_pow"]
        if "uart_baud" in param_map:
            if(param_map["uart_baud"]) > 3:
                if not (param_map["uart_baud"] in SerialAPIUtilities.ZUNO_BAUD):
                    param_map["uart_baud"] = 0
                else:
                    param_map["uart_baud"] = SerialAPIUtilities.ZUNO_BAUD.index(param_map["uart_baud"])
            bts[6] &= ~(0x18)
            bts[6] |= ((param_map["uart_baud"])&0x03)<<3
        if "flags" in param_map:
            bts[6] = param_map["flags"]
        if "flag_rflog" in param_map:
            if(param_map["flag_rflog"]):
                bts[6] |= 0x04
            else:
                bts[6] &= ~(0x04)
        if "flag_activity_led" in param_map:
            if(param_map["flag_activity_led"] == 0):
                bts[6] |= 0x02
            else:
                bts[6] &= ~(0x02)
        if "flag_dbg" in param_map:
            if(param_map["flag_dbg"] == 0):
                bts[6] |= 0x01
            else:
                bts[6] &= ~(0x01)
        if "report_interval" in param_map:
            bts[7] = param_map["report_interval"]

        printInfo("DEVICE CFG");
        region = "UNKNOWN"
        r = zmeRemapDictVal2Key(FREQ_TABLE_U7, bts[1])
        if r != None:
            region = r
        printInfo("\tZ-Wave Region:%s"%(region))
        uuart_baud = SerialAPIUtilities.ZUNO_BAUD[((bts[6]&0x18)>>3)]
        printInfo("\tSecurity mode:%02x Freqi:%02x maxTxDb:%02x adjTxDb:%02x LRTxDb:%02x UART:%d extra_flags:%02x" % (bts[4], bts[1], bts[2], bts[3], bts[5], uuart_baud, bts[6]))
        self.cmdinterface.writeNVM(0xFFE000, bts)  
        return True 
    def selectUUARTBaud(self, new_baud):
        crc = new_baud & 0xFF
        crc ^= (new_baud >> 8) & 0xFF
        crc ^= (new_baud >> 16) & 0xFF
        crc <<= 24
        baud_arr = zme_int_toarr(new_baud+crc, 4, bInv=True)
        # Устанавливаем новый baud в специальную переменную-на которую мэппинг в памяти 
        res = self.cmdinterface.writeNVM(0xFFCFA0, baud_arr)
        if(res[0] != SerialAPICommand.RECV_OK):
            return False
        return True
    def reconnectNeededBaud(self, baud):
        # Переоткрываем порт на нужной частоте - этого достаточно для перезагрузки устройства
        self.closePort(True)
        self.cmdinterface.port.setBaudrate(baud)
        return True
    def reconnectToUUART(self, new_baud):
        self.selectUUARTBaud(new_baud)
        self.reconnectNeededBaud(new_baud)
        return self.syncWithDevice()
    def eraseDeviceNVM(self, baudrate=230400, bNoAB=False):
        if not self.syncWithDevice(baud=baudrate, bNoABD=bNoAB):
            self.closePort(True)
            return False
        result = self.cmdinterface.eraseDevNVM()
        self.closePort(True)
        return True
    def writeDeviceNVM(self, addr, buff, bStart=True, bStop=True, baudrate=230400, bNoAB=False):
        if bStart:
            if not self.syncWithDevice(baud=baudrate, bNoABD=bNoAB):
                self.closePort(True)
                return False
        res = self.cmdinterface.writeNVM(addr, buff)
        if bStop:
            self.closePort(True)
        return res[0] == 0
    def startRailTest(self, mode, region, channel, power, timeout, bSync = True, ultrabaud = 0, bNoAB=False):
        # if ultrabaud != 0:
        #     print("Try UUART setting!")
        #     if not self.reconnectToUUART(ultrabaud):
        #         #self.closePort(True)
        #         return False
        if bSync:
            if not self.syncWithDevice(baud=ultrabaud, bNoABD=bNoAB):
                self.closePort(True)
                return False
        result = self.cmdinterface.railTest(mode, region, channel, power, timeout)
        if(len(result) < 6):
            printError("Can't start railtest.Short packet.")
            self.closePort()
            return False
        logging.info("RT result:%s"%(result))
        if(result[5] != 0x00):
            printError("Can't start railtest.")
            self.closePort()
            return False
        return True
        
    def reflashUserSketch(self, fwimagefile, addr, param_map={}, filesource = True, maximum_sketch_size = 30*1024, skip_data = 0, bSync = True, UUARTBaud = 0):
        print("--- Sketch addr:%08x"%(addr))
        # if(UUARTBaud != 0):
        #     if not self.reconnectToUUART(UUARTBaud):
        #         return False
        if bSync:
            if not self.syncWithDevice(baud=UUARTBaud):
                self.closePort(True)
                return False
        res = False
        self.applyPrams(param_map)
        if(filesource):
            res, sk_data = self.writeFileToNVM(addr, fwimagefile, skip_data)
        else:
            res, sk_data = self.writeArrayToNVM(addr, fwimagefile)
        if res == True:
            crc16 = calcSigmaCRC16(0x1D0F, sk_data, 0, len(sk_data))
            sk_size = len(sk_data)
            if(sk_size > maximum_sketch_size):
                printError("Can't upload sketch! The sketch is too BIG! The maximum sketch size is %d bytes."%(maximum_sketch_size))
                self.closePort()
                return False
            printInfo("Sketch crc16:%x size:%x (%3.2f kB)" % (crc16, sk_size, sk_size/1024.0))
            printStatus("Pushing sketch")
            result = self.cmdinterface.pushSketch(addr, sk_size, crc16)
            if(len(result) < 5):
                printError("Can't upload sketch! Something went wrong. Bad response.")
                self.closePort()
                return False
            if(result[4] == 0xFE):
                printError("Can't upload sketch! Something went wrong. Bad CRC16 :'( .")
                self.closePort()
                return False
            finallizeStepStatus("Pushing sketch", "OK")
        else:
            return False
        #print "RES:%s"%(result)
        self.closePort(True)
        return True


    def readNVM(self, addr, size):
        self.openPort()     
        info = self.cmdinterface.readNVM(addr, size)
        #request = self.cmdinterface.recvIncomingRequest()
        self.closePort()

        return info


    def writeNVM(self, addr, buff):
        self.openPort()     
        
        info = self.cmdinterface.writeNVM(addr, buff)
        #request = self.cmdinterface.recvIncomingRequest()

        self.closePort()

        return info

    def setFrequency(self, freq):
        self.openPort(True)     
        
        response = self.cmdinterface.setFrequency(freq)

        freq_code = 0xee
        if(len(response) == 6):
            freq_code = response[5]


        #time.sleep(10.0)
        #info = self.cmdinterface.recvIncomingRequest()

        #self.cmdinterface.port.Close()

        self.closePort()


        #print "RESPONSE FREQ:%s"%(response)

        return freq_code
    def __del__(self):
        #logging.info("SAPI destructor")
        self.closePort(True,True)

