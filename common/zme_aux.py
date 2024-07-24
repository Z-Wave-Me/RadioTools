#!/usr/bin/python
# -*- coding: utf-8 -*-
from inspect import trace
from multiprocessing import ProcessError
import sys
import threading
import uuid
import os
import re
import platform
import logging
import shutil
import errno
import subprocess
import hashlib
import time
import shutil
import fnmatch
import traceback
from time import gmtime, strftime
from random import randint
from intelhex import IntelHex, IntelHexError, AddressOverlapError
#import orjson
import json
from zipfile import ZipFile
import zipfile
from tarfile import TarFile
import tarfile
import datetime 
import asyncio
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

LKTEXT={0x00:"UNLOCKED",
        0x01:"DBG_LOCKED",
        0x02:"APP_LOCKED",
        0x03:"ERASE_LOCKED",
        0x04:"UNKNOWN"}

FREQ_TABLE_U7 = { 	"EU": 	0x00, 
					"US": 	0x01,
					"ANZ":	0x02,
					"HK": 	0x03,
					"MY": 	0x04,
					"IN":	0x05,
					"IL": 	0x06,
					"RU": 	0x07,
					"CN": 	0x08,
                    "US_LR":0x09,
                    "US_LR_BK":0x0A,
					"JP": 	   0x20,
					"KR": 	   0x21,
					"FK":   0xFE }

FREQI_LIST_LR = [0x09, 0x0A]

FREQ_ADV_ZIGBEE                         = 0xF5
FREQ_ADV_ZIGBEE_STR                     = "ZIGBEE"
FREQ_ADV_2P4GHZ_ANTDIV_COEX             = 0xF6
FREQ_ADV_2P4GHZ_ANTDIV_COEX_STR         = "2P4GHZ_ANTDIV_COEX"
FREQ_ADV_2P4GHZ_COEX                    = 0xF7
FREQ_ADV_2P4GHZ_COEX_STR                = "2P4GHZ_COEX"
FREQ_ADV_2P4GHZ_ANTDIV                  = 0xF8
FREQ_ADV_2P4GHZ_ANTDIV_STR              = "2P4GHZ_ANTDIV"
FREQ_ADV_2P4GHZ                         = 0xF9
FREQ_ADV_2P4GHZ_STR                     = "2P4GHZ"
FREQ_ADV_BLE_CODED_500KBPS              = 0xFA
FREQ_ADV_BLE_CODED_500KBPS_STR          = "BLE_CODED_500KBPS"
FREQ_ADV_BLE_CODED_125KBPS              = 0xFB
FREQ_ADV_BLE_CODED_125KBPS_STR          = "BLE_CODED_125KBPS"
FREQ_ADV_BLE_2MBPS                      = 0xFC
FREQ_ADV_BLE_2MBPS_STR                  = "BLE_2MBPS"
FREQ_ADV_BLE_1MBPS                      = 0xFD
FREQ_ADV_BLE_1MBPS_STR                  = "BLE_1MBPS"

FREQ_ADV = {		FREQ_ADV_ZIGBEE_STR:   FREQ_ADV_ZIGBEE,
					FREQ_ADV_2P4GHZ_ANTDIV_COEX_STR:   FREQ_ADV_2P4GHZ_ANTDIV_COEX,
					FREQ_ADV_2P4GHZ_COEX_STR:   FREQ_ADV_2P4GHZ_COEX,
					FREQ_ADV_2P4GHZ_ANTDIV_STR:   FREQ_ADV_2P4GHZ_ANTDIV,
					FREQ_ADV_2P4GHZ_STR:   FREQ_ADV_2P4GHZ,
					FREQ_ADV_BLE_CODED_500KBPS_STR:   FREQ_ADV_BLE_CODED_500KBPS,
					FREQ_ADV_BLE_CODED_125KBPS_STR:   FREQ_ADV_BLE_CODED_125KBPS,
					FREQ_ADV_BLE_2MBPS_STR:   FREQ_ADV_BLE_2MBPS,
					FREQ_ADV_BLE_1MBPS_STR:   FREQ_ADV_BLE_1MBPS,
					}		
FREQ_TABLE_U7_EXT = dict(FREQ_TABLE_U7)
FREQ_TABLE_U7_EXT.update(FREQ_ADV)

HWREV_PRODUCT_TYPE = { 0x00:["Z-Uno", {   0x00:"STD",
                                        0x01:"Module u.fl", 
                                        0x02:"Module wire", 
                                        0x03:"Module trace"}], 
                        0x01:["SAPI",{0x00:"Razberry STD", 
                                                 0x01:"Razberry PRO", 
                                                 0x02:"WirenBoard", 
                                                 0x03:"mPCIE Board", 
                                                 0x04:"UZB"}],
                        0x02:["ProgBoard",{   0x00:"Z-Uno HW", 
                                                    0x01:"Flasher"  }],
                        0x0F:["SAPI",{   0x0F:"Razberry STD"}],
                        }
HWREV_CHIPTYPE = {0x05:"ZM5101", 0x07:"ZGM130S"}   

ZME_CHIP_FAMILY_ZGM13					    = 0x00
ZME_CHIP_ZGM130S037HGN						= 0x01
ZME_CHIP_ZGM130S037HGN1						= 0x02

ZME_CHIP_FAMILY_ZGM23						= 0x02
ZME_CHIP_ZGM230SA27HGN						= 0x01
ZME_CHIP_ZGM230SA27HNN						= 0x02
ZME_CHIP_ZGM230SB27HGN						= 0x03
ZME_CHIP_ZGM230SB27HNN						= 0x04

ZME_CHIP_FAMILY_EFR32ZG23					= 0x04
ZME_CHIP_EFR32ZG23A010F512GM40				= 0x01
ZME_CHIP_EFR32ZG23A010F512GM48				= 0x02
ZME_CHIP_EFR32ZG23A020F512GM40				= 0x03
ZME_CHIP_EFR32ZG23A020F512GM48				= 0x04
ZME_CHIP_EFR32ZG23B010F512IM40				= 0x05
ZME_CHIP_EFR32ZG23B010F512IM48				= 0x06
ZME_CHIP_EFR32ZG23B011F512IM40				= 0x07
ZME_CHIP_EFR32ZG23B020F512IM40				= 0x08
ZME_CHIP_EFR32ZG23B020F512IM48				= 0x09
ZME_CHIP_EFR32ZG23B021F512IM40				= 0x0A



ZME_CHIP_NAMES = { 
        ZME_CHIP_FAMILY_ZGM13:{
            "name":"ZGM13 Module",
            "chips":{
                ZME_CHIP_ZGM130S037HGN:"ZGM130S037HGN",
                ZME_CHIP_ZGM130S037HGN1:"ZGM130S037HGN1"
            }
        },
        ZME_CHIP_FAMILY_ZGM23:{
            "name":"ZGM23 Module",
            "chips":{
                ZME_CHIP_ZGM230SA27HGN:"ZGM230SA27HGN",
                ZME_CHIP_ZGM230SA27HGN:"ZGM230SA27HGN",
                ZME_CHIP_ZGM230SB27HGN:"ZGM230SB27HGN",
                ZME_CHIP_ZGM230SB27HNN:"ZGM230SB27HNN"
            }
        },
        ZME_CHIP_FAMILY_EFR32ZG23:{
            "name":"EFR32ZG23 SOC",
            "chips":{
                ZME_CHIP_EFR32ZG23A010F512GM40:"EFR32ZG23A010F512GM40",
                ZME_CHIP_EFR32ZG23A010F512GM48:"EFR32ZG23A010F512GM48",
                ZME_CHIP_EFR32ZG23A020F512GM40:"EFR32ZG23A020F512GM40",
                ZME_CHIP_EFR32ZG23A020F512GM48:"EFR32ZG23A020F512GM48",
                ZME_CHIP_EFR32ZG23B010F512IM40:"EFR32ZG23B010F512IM40",
                ZME_CHIP_EFR32ZG23B010F512IM48:"EFR32ZG23B010F512IM48",
                ZME_CHIP_EFR32ZG23B011F512IM40:"EFR32ZG23B011F512IM40",
                ZME_CHIP_EFR32ZG23B020F512IM40:"EFR32ZG23B020F512IM40",
                ZME_CHIP_EFR32ZG23B020F512IM48:"EFR32ZG23B020F512IM48",
                ZME_CHIP_EFR32ZG23B021F512IM40:"EFR32ZG23B021F512IM40"
            }
        }
}

global_error_count = 0
global_errors = []
WITH_BIG_ERROR = False
global_stat = ""
global_cli_on = True
global_progress_handler = None
def cli_Enable(on):
    global global_cli_on
    global_cli_on = on
def cli_setGlobalStatusHandler(handler):
    global global_progress_handler
    global_progress_handler = handler

def printStatus(text, prc=0xff, force_close = False):
    global global_stat, global_cli_on, global_progress_handler
    
    if (len(global_stat) > 0) and (force_close):
        finallizeStatus("OK")
        global_stat = ""
    global_stat = text
    if global_progress_handler != None:
        global_progress_handler(text, prc)
    if (prc == 0xff):
        if global_cli_on:
            sys.stdout.flush()
            sys.stdout.write('\r%-40s %s' % (text, '.' * 30))
            sys.stdout.flush()
        logging.info("Status: %s" % text)
    else:
        bar_count = int(prc / 2) + 1
        if global_cli_on:
            sys.stdout.write('\r%-40s [%s>%s] (%d%%)' % (text, '=' * (bar_count - 1), ' ' * (50 - bar_count), prc))
            sys.stdout.flush()
        if (prc == 0):
            logging.info("Status: %s Started" % text)
        elif (prc == 100):
            logging.info("Status: %s Finished" % text)

def findMapAvIndex(mapvalue, n):
    for i in range(n):
        if (mapvalue & (1<<i)) == 0:
            return i
    return -1
def printCurrStatusProgress(prc):
    global global_stat
    printStatus(global_stat, prc)
def initStepStatus(text):
    printStatus(text, 0, True)

def finallizeStepStatus(text, stat_text):
    global global_stat
    global_stat = ""
    if global_cli_on:
        sys.stdout.write('\r%-40s %s' % (text, '.' * 30))
        sys.stdout.flush()
        sys.stdout.write('%30s\n' % (stat_text))
def finallizeStatus(stat = "OK"):
    global global_stat
    finallizeStepStatus(global_stat, stat)

def printNL():
    if global_cli_on:
        sys.stdout.write("\n")


def printOpCode(text):
    if global_cli_on:
        sys.stdout.write('%30s\n' % (text))


def printInfo(text):
    lines = text.split("\n")
    if global_cli_on:
        for l in lines:
            print("%s%s" % (" " * 10, l))
    logging.info(text)

def printError(text):
    global global_error_count, global_errors
    global global_stat
    if len(global_stat) > 0:
        finallizeStatus("FAILED")
        global_stat = ""

    if (WITH_BIG_ERROR):
        print(" \n\n")
        print("\t\t\t ****    ****     ****      ****    ****    * ")
        print("\t\t\t *       *   *    *   *    *    *   *   *   * ")
        print("\t\t\t *       *   *    *   *    *    *   *   *   * ")
        print("\t\t\t ****    ***      ***      *    *   ***     * ")
        print("\t\t\t *       *  *     *  *     *    *   *  *      ")
        print("\t\t\t ****    *   *    *   *     ****    *   *   * ")
        print("\n\n")

    err_str = "%2d\t %s" % (global_error_count, text)
    if global_cli_on:
        print("\nError %s" % (err_str))

    global_errors += [err_str]
    logging.error(err_str)
    global_error_count += 1

def printBuffHex(name, buff):
    logging.debug("%s%s" % (name, splitHexBuff(buff)))

def formatHexInput(hexstr):
    comm_list = hexstr.split()
    val_list = []
    for bt in comm_list:
        try:
            while (len(bt) >= 2):
                vl_bt = bt[:2]
                bt = bt[2:]
                val_list += [int(vl_bt, 16)]
            if (len(bt) != 0):
                val_list += [int(bt, 16)]
        except:
            pass
    return val_list
def formatDict(d):
    text = ""
    for k in d:
        text += "%s:%s"%(k, d[k])
    return text
def splitHexBuff(buff, format_row=32, column_shift="", no_ss=False):
    if (buff == None):
        return "NONE"
    str_h = ''
    buff_count = len(buff) // format_row
    rest = len(buff) % format_row
    if (buff_count > 0 ) and (not no_ss):
        str_h = '\n'+column_shift
    for line in range(0, buff_count):
        str_h += ''.join(' %02X' % b for b in buff[line * format_row:(line + 1) * format_row])
        if rest or (line != (buff_count-1)):
            str_h += '\n'+column_shift
    if (rest):
        str_h += ''.join(' %02X' % b for b in buff[buff_count * format_row:buff_count * format_row + rest])
    return str_h
def formatBuff2JS(buff):
    text = "/JS/Run/zway.ZMELicenseSet(["
    i = 0
    for b in buff:
        text += "0x%02x"%(b)
        if i < (len(buff)-1):
            text += ", "
        i += 1
    text += "])"
    return text



def executeExternalSubprocess(arg_list, path, file2Output=None, env_list = None, full_output = False, err_file = None, xshell=False, no_output=False):
    ret_code = -1000
    output_descr = subprocess.PIPE
    output_text = ""
    try:
        #print( "\n\tSubprocess args:%s\n"%(arg_list))
        if(not os.path.isfile(arg_list[0])):
            return -1, "Unknown file"
        if(file2Output != None):
            output_descr = open(file2Output, "w")
        env = os.environ.copy() 
        if(env_list != None):
            for env_entry in env_list:
                if len(env_entry) > 2:
                    if(env_entry[1] == "+"):
                        env[env_entry[0]] += env_entry[2]
                else:
                    env[env_entry[0]] = env_entry[1]

        #if(DUMP_ARGS):      
        #print( "\n\tSubprocess args:%s\n"%(arg_list))

        #proc = subprocess.Popen(arg_list, cwd=path, stdout=output_descr, stderr = subprocess.PIPE, env = env)
        # subprocess.PIPE
        if(full_output):
            proc = subprocess.Popen(arg_list, cwd=path, env = env, shell = xshell, stderr = sys.stdout)
        else:
            err_descr = output_descr
            if(err_file != None):
                err_descr = open(err_file, "w")
            proc = subprocess.Popen(arg_list, cwd=path, stdout=output_descr, stderr = err_descr, env = env, shell = xshell)
            
        proc.wait()
        
        if(file2Output != None and (not no_output)):
            output_descr.close()
            with open(file2Output, "r") as f:
                output_text = f.read()
        ret_code = proc.returncode
        #logging.debug(" >>> %s\nreturns: %s\nworking dir: %s" % (' '.join(arg_list), ret_code, path))

    except Exception as e1:

        logging.error("Exception:%s"%(e1))
        traceback.print_exc()
        ret_code -2, "%s"%(e1)
    return ret_code, output_text

def getAllSubDirs(dirname):
    full_list = []
    dir_list = dirname
    #print("WALK:%s"%(dirname))
    if isinstance(dirname, str):
        dir_list = []
        dir_list += [dirname]
    for dn in dir_list:
        #print("--->WALK:%s"%(dn))
        dirdata = next(os.walk(dn))
        sub_dirs = dirdata[1]
        full_path = dirdata[0]
        for d in sub_dirs:
            full_list += [full_path + os.sep +d]
    return full_list
def searchForFileInDirs(dirs_list, filename):
    filename = filename.lower()
    for dirname in dirs_list:
        for fn in os.listdir(dirname):
            if fn.lower() == filename:
                return dirname + os.sep +  fn
    return None
def getAllFiles(dirname, exp = None):
    full_list = []
    dirdata = next(os.walk(dirname))
    sub_files = dirdata[2]
    full_path = dirdata[0]
    for f in sub_files:
        if(exp):
            if re.search(exp, f):
                full_list += ["%s%s%s"%(full_path, os.sep, f)]
        else:
            full_list += ["%s%s%s"%(full_path, os.sep, f)]

    return full_list
def copyFilesBySet(filelist, dstfolder, exclude_list = []):
    copied_list = []
    for filename in filelist:
        if not (filename in exclude_list):
            if(baseDirectoryPath(filename) != dstfolder):
                shutil.copy2(filename, dstfolder + os.sep)    
            copied_list += [filename]
    return copied_list

def filename_extract(path):
    head, tail = os.path.split(path)
    return tail or os.path.basename(head)

def baseDirectoryPath(filename):
    head, tail = os.path.split(filename)
    return head

def loadSourceFile(filename, by_lines = True):
    logging.debug("Loading source file:%s"%(filename))
    source_lines = []
    with open(filename, "r", encoding='utf-8', errors='ignore') as f:
        if(by_lines):
            source_lines = f.readlines()
        else:
            source_lines = f.read()
    return source_lines
def loadBinaryFile(filename):
    logging.debug("Loading binary file:%s"%(filename))
    source_lines = []
    with open(filename, "rb") as f:
        source_data = f.read()
    return source_data


def saveTextFile(text_filename, string_data):
    with open(text_filename, 'w', encoding='utf-8', errors='ignore') as the_file:
        the_file.write(string_data)

def compareAndSaveTextFile(text_filename, string_data):
    if (os.path.isfile(text_filename)):
        prev_text = "%s"%(loadSourceFile(text_filename, by_lines = False))
        if prev_text == string_data:
            return
    saveTextFile(text_filename, string_data) 

def Checksum(buf):
    ret = 0xff
    for i in range(0, len(buf)):
        ret = ret ^ buf[i]
    return ret
CRC_POLY = 0x1021
def calcSigmaCRC16(crc, data, offset, llen):
    bin_data = data
    while (llen != 0):
        llen -= 1
        if (offset >= len(bin_data)):
            wrk_data = 0xFF
        else:
            wrk_data = bin_data[offset]  # hex_data[offset]

        offset += 1
        bit_mask = 0x80
        while (bit_mask != 0):
            a = 0
            b = 0
            if ((wrk_data & bit_mask) != 0):
                a = 1
            if ((crc & 0x8000) != 0):
                b = 1

            new_bit = a ^ b
            crc <<= 1
            crc = crc & 0xffff
            if (new_bit == 1):
                crc ^= CRC_POLY
            bit_mask >>= 1
    return crc

def getScriptPath():
    if (os.path.isfile(os.path.realpath(__file__))):
        return baseDirectoryPath(os.path.realpath(__file__))
    return baseDirectoryPath(os.path.abspath(sys.argv[0]))

def auxfileTimestamp(filename):
    if not os.path.isfile(filename):
        return 0
    if platform.system() == 'Windows':
        return os.path.getmtime(filename)
    else:
        stat = os.stat(filename)
        return stat.st_mtime
    return 0

def stripFWData(bindata):
    index = len(bindata)-1
    while index > 0:
        if bindata[index] != 0xFF:
            break
        index -= 1
    return bindata[:index+1]


def loadFWFile(filename, data_offset=0, add_startaddr=False):
    frm = 'bin'
    start_addr = 0
    if (filename.endswith(".hex")):
        frm = 'hex'
    hex_data = IntelHex()
    try:
        hex_data.fromfile(filename, format=frm)
    except Exception as e:
        printError("%s while loading the firmware file:%s " % (e, filename))
        return None
    if frm == "hex":
        start_addr = hex_data.minaddr()
    ret_data = hex_data.tobinarray()[data_offset:]
    if add_startaddr:
        return ret_data, start_addr
    return ret_data
def saveFWFile(filename, data):
    frm = 'bin'
    if (filename.endswith(".hex")):
        frm = 'hex'
    hex_pages   = IntelHex()
    hex_pages.frombytes(data)
    try:
        hex_pages.tofile(filename, format = frm)
    except:
        return False
    return True
    
def aux_extract_extention(filename):
    dot_index = filename.rfind(".")
    if dot_index == -1:
        return ""
    return filename[dot_index:]
def filterFileList(fl, fl_re):
    nfl = []
    for f in fl:
        if f.startswith("__"):
            continue
        if f.startswith(".DS_Store"):
            continue
        if fl_re != None:
            if fl_re.match(f):
                continue
        nfl += [f]
    return nfl
def extractArchive(filename, dest_folder, stash_upper = True, progress_cbk = None, filter_re = None):
    with ZipFile(filename, 'r') as zipObj:
        if stash_upper:
            overall_size = 0
            current_sum = 0
            if progress_cbk != None:
                for info in zipObj.infolist():
                    overall_size += info.file_size
            filelist = zipObj.namelist()
            filelist = filterFileList(filelist, filter_re)
            base_dir = os.path.commonprefix(filelist)
            #print("***BASE:%s"%(base_dir))
            if (base_dir.find('/') == -1) and (base_dir.find('\\') == -1):
                base_dir = ""
            for fl in filelist:
                sub_dir = fl.replace(base_dir,"")
                filename = os.path.basename(fl)
                file_path = os.path.join(dest_folder, sub_dir)
                base_path = baseDirectoryPath(file_path)
                # Make needed path
                if not os.path.exists(base_path):
                    os.makedirs(base_path, exist_ok=True)
                if not filename:
                    if not os.path.exists(file_path): 
                        os.makedirs(file_path, exist_ok=True)
                    # skip directories
                    continue
                source = zipObj.open(fl)
                target = open(file_path, "wb")
                with source, target:
                    shutil.copyfileobj(source, target)
                    if progress_cbk != None:
                        current_sum += zipObj.getinfo(fl).file_size
                        progress_cbk(current_sum, overall_size)

        else:
            zipObj.extractall(dest_folder)
def calcDirectorySize(start_path = '.'):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # skip if it is symbolic link
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size

def name2ArchMode(filename):
    if filename.endswith(".tar.xz"):
        return ":xz"
    if filename.endswith(".tar.gz"):
        return ":gz"
    if filename.endswith(".tar.bz2"):
        return ":bz2"
    return ":gz"
my_tar_mode =0o777
def tarModeFilter(tarinfo):
    global my_tar_mode
    tarinfo.mode = my_tar_mode
    tarinfo.uid = tarinfo.gid = 0
    tarinfo.uname = tarinfo.gname = "root"
    return tarinfo
def packArchive(src_folder, dstname, filter=None, progress_cbk = None, fix_acess_map = 0o777, common_prefix = ""):
    total_size = 0
    sum_size = 0
    global my_tar_mode
    if progress_cbk != None:
        total_size = calcDirectorySize(src_folder)
    zip_mode = False
    if dstname.endswith(".zip"):
        zipObj = ZipFile(dstname, 'w', zipfile.ZIP_DEFLATED)
        zip_mode = True
        #zipObj.open(dstname, 'w')
    else:
        compression_mode = name2ArchMode(dstname)
        zipObj = tarfile.open(dstname, "x"+compression_mode)
        if fix_acess_map != None:
            my_tar_mode = fix_acess_map
        #zipObj.open(dstname, "x"+compression_mode)

    # Iterate over all the files in directory
    for folderName, subfolders, filenames in os.walk(src_folder):
        if folderName.find(".DS_Store") != -1:
            continue
        for filename in filenames:
            #create complete filepath of file in directory
            filePath = os.path.join(folderName, filename)
            # Add file to zip
            arch_path = filePath.replace(src_folder, "")
            if common_prefix != None:
                #print("COMMON PREFIX:%s"%(common_prefix))
                arch_path = common_prefix + arch_path #os.path.join(common_prefix, arch_path)
            if zip_mode:
                with open(filePath, "rb") as f:
                    bytes = f.read()
                #print("arch_path:%s"%(arch_path))
                info = zipfile.ZipInfo.from_file(filePath, arch_path)
                if fix_acess_map != None:
                    info.external_attr |= fix_acess_map << 16  # give full access to included file
                    info.compress_type = zipObj.compression
                #print("ZIP")
                zipObj.writestr(info, bytes)
            else:
                if fix_acess_map != None:
                    zipObj.add(filePath, arch_path, filter=tarModeFilter)
                else:
                    zipObj.add(filePath, arch_path)
            if progress_cbk != None:
                sum_size += os.path.getsize(filePath)
                progress_cbk(sum_size, total_size)
    zipObj.close()

def calcSHA256(filename):
    readable_hash = None
    with open(filename,"rb") as f:
        bytes = f.read() # read entire file as bytes
        readable_hash = hashlib.sha256(bytes).hexdigest();
    return readable_hash

def fastIntConv(s):
    if s.startswith("0x"):
        return int(s,16)
    return int(s)

def conv2Decimal(buff, separator="-"):
    text = ""
    for i in range(len(buff)//2):
        v = buff[ (i * 2)]
        v <<= 8
        v += buff[ (i * 2) + 1]
        if(i != 0):
            text += separator
        text += "%05d"%(v)
    return text

def compile_zwave_qrcode(product_data, dsk, version):
    text = "%03d"%(product_data["s2_keys"])
    text += conv2Decimal(dsk,"")
    #ProductType
    text += "0010%05d%05d"%(product_data["device_type"], product_data["device_icon"])
    #ProductID
    text += "0220%05d%05d%05d%05d"%(product_data["vendor"], product_data["product_type"], product_data["product_id"], version)
    # Supported Protocols
    protocol_map = 0x01 
    if ("LR" in  product_data) and (product_data["LR"]):
        protocol_map |= 0x02
    text += "0803%03d"%(protocol_map)
    # MaxInclusionInterval
    text += "0403005" # ==5*128=640
    hash_object = hashlib.sha1(text.encode())
    hex_str = hash_object.hexdigest()
    hex_dig = int(hex_str[:4],16)
    header = "9001%05d"%(hex_dig)
    return header + text

def compile_zwave_qrcode_verify(product_data:dict) -> bool:
    if not "s2_keys" in product_data:
        return (False)
    if not "device_type" in product_data:
        return (False)
    if not "device_icon" in product_data:
        return (False)
    if not "vendor" in product_data:
        return (False)
    if not "product_type" in product_data:
        return (False)
    if not "product_id" in product_data:
        return (False)
    return (True)

def find_seq_in_buff(buff, seq, fr= 0, all_matches=False, exclude_block = None):
    index_seq = 0
    offset = fr
    offset_list = []
    while(True):
        if(offset >= len(buff)):
            if(not all_matches):
                return -1
            else:
                return offset_list  
        if(exclude_block != None):
            if(offset >= exclude_block[0] and offset <= exclude_block[1]):
                offset += 1
                continue

        if(buff[offset] == seq[index_seq]):
            index_seq +=1   
        else:
            offset -= index_seq
            index_seq = 0
                
        if(index_seq == len(seq)):
            if(not all_matches):
                return offset - len(seq) + 1
            else:
                offset_list += [offset - len(seq) + 1]
                index_seq = 0   

        offset += 1
    return offset_list
'''
  ZWaveMeFlashLockStausUnlock = 0,
  ZWaveMeFlashLockStausDebugLock,
  ZWaveMeFlashLockStausAppUnlock,
  ZWaveMeFlashLockStausFull,

'''
ZGM_PORT_NUMBERS = {0:"A", 1:"B", 2:"C", 3:"D", 5:"F"}
ZUNO_VALID_SIGN = 'ZMEZUNOC'

ZUNO_LIC_FLAGS_NAMES = { "PTI":{"bit":0, "description":"Provides Packet Trace Interface (PTI) capabilities. Turns ZUno to advanced sniffer."}, 
                         "KEY_DUMP":{"bit":1, "description":"Enables Z-Wave network key dump using Z-Uno."},
                         "CUSTOM_VENDOR":{"bit":2, "description":"Use custom vendor code intead of 0115 (ZME)."},
                         "MODEM":{"bit":3, "description":"ZUno works as direct transmitter. "},
                         "MAX_POWER":{"bit":4, "description":"User is able to use the maximum power of radio amplifier. "},
                         "LONG_RANGE":{"bit":5, "description":"Enables Z-Wave LongRange technology support. "},

                        }

def zmePrintFlagsMask(legend, val):
    text = ""
    for f in legend:
        if not ("bit" in legend[f]):
            continue
        if val & (1 << legend[f]["bit"]):
            text += f + " "
    return text.strip()
def zmeCheckFlagByName(legend, val, flag):
    if not flag in legend:
        return False
    bit_num = legend[flag]["bit"]
    return (val &  (1 << bit_num)) != 0
def printZGMPort(portpin):
    port_number = portpin >> 4
    if not port_number in  ZGM_PORT_NUMBERS:
        return "UNKNOWN(%02x)"%(portpin)
    return ZGM_PORT_NUMBERS[port_number] + "%d"%(portpin&0x0F)
def formatHexVersion2b(v):
    return "%02d.%02d"%(v>>8, v&0x0ff)

def printBoardInfo(md, devv = False):
    column_len = 84
    title = "Z-Uno board information"
    adv_len = (column_len-len(title))//2
    printInfo("-"*column_len)
    printInfo("%s%s"%(" "*adv_len, title))
    printInfo("-"*column_len)
    printInfo("\nFIRMWARE\n")
    build_datetime =  datetime.datetime.fromtimestamp(float(md["build_ts"])).strftime("%Y-%m-%dT%H:%M:%S(MSK)")
    printInfo("\t VERSION:\t\t%s"%(formatHexVersion2b(md["version"])))
    printInfo("\t BUILD_SEQUENCE:\t%08d"%(md["build_number"]))
    printInfo("\t BUILD_DATETIME:\t%s"%(build_datetime))
    printInfo("\t SUPPORTED_HWREV:\t%04x"%(md["hw_rev"]))
    if("keys_hash" in md):
        printInfo("\t KEY HASH:\t\t%08x"%(md["keys_hash"]))
    if("se_version" in md):
        printInfo("\t SE VERSION:\t\t%08x"%(md["se_version"]))
    printInfo("\nLIMITS\n")
    printInfo("\t CODE:\t%5d Bytes"%(md["code_size"]))
    printInfo("\t RAM:\t%5d Bytes"%(md["ram_size"]))
    printInfo("\nHARDWARE\n")
    if("chip_type" in md):
        printInfo("\t CHIP_FAMILY:\t %s (%02x)"%(md["chip_family_name"], md["chip_family"]))
        printInfo("\t CHIP_TYPE:\t %s (%02x)"%(md["chip_type_name"], md["chip_type"]))
    printInfo("\t CHIP_UID:\t%s"%(splitHexBuff(md["chip_uid"])))
    if ("prod_crc8" in md) or (devv):
        prod_datetime =  datetime.datetime.fromtimestamp(float(md["prod_ts"])).strftime("%Y-%m-%dT%H:%M:%S(MSK)")
        if (Checksum(md["prod_raw"]) == 0) or (devv):
            if(devv):
                printInfo("\t PROD_RAW:\t%s"%(splitHexBuff(md["prod_raw"])))
                printInfo("\t PROD_CHIP_UID:\t%s"%(splitHexBuff(md["prod_parent_uuid"])))
                prod_str = [0x00]*8
                prod_str[0] = md["chip_uid"][7]
                prod_str[1] = md["chip_uid"][6]
                prod_str[2] = md["chip_uid"][5] #md["prod_ts"] & 0xFF
                prod_str[3] = md["chip_uid"][4] #(md["prod_ts"] >> 8) & 0xFF
                prod_str[4] = md["prod_sn"] & 0xFF
                prod_str[5] = (md["prod_sn"] >> 8) & 0xFF
                prod_str[6] = md["prod_parent_uuid"][7]
                prod_str[7] = md["prod_parent_uuid"][6]
                printInfo("\t PROD_STR:\t%s"%(splitHexBuff(prod_str)))
            printInfo("\t PROD_TIME:\t %s"%(prod_datetime))
            printInfo("\t PROD_SN:\t %d"%(md["prod_sn"]))             
    dbg_access_status = "UNKNOWN"
    if md["dbg_lock"] in LKTEXT:
        dbg_access_status = LKTEXT[md["dbg_lock"]]
    printInfo("\t LOCK:\t\t %s"%(dbg_access_status))
    printInfo("\t EXT NVM:\t %s"%(md["ext_nvm"]))
    if "lic_flags" in md:
        printInfo("\nLICENSE\n")
        printInfo("\t SUB_VENDOR:\t%04X"%(md["lic_subvendor"]))
        printInfo("\t BITMASK:\t%016X"%(md["lic_flags"]))
        printInfo("\t FEATURES:\t[%s]"%(zmePrintFlagsMask(ZUNO_LIC_FLAGS_NAMES, md["lic_flags"])))
        printInfo("\t CRC16:\t\t%04x"%(md["lic_crc16"]))
        
    printInfo("\nNETWORK\n")
    printInfo("\t HOMEID:\t%08x"%(md["home_id"]))
    printInfo("\t NODEID:\t%d"%(md["node_id"]))
    printInfo("\nSECURITY\n")
    printInfo("\tS2 DSK:\t\t%s"%(conv2Decimal(md["s2_pub"])))
    printInfo("\t       \t\t_____")
    printInfo("\tS2 PIN:\t\t%05d"%(zme_costruct_int(md["s2_pub"], 2, False)))
    printInfo("\tQR-Code:\t%s"%(md["smart_qr"]))
    printInfo("-"*column_len)
    if "sketch" in md:
        printInfo("\nSKETCH\n")
        if(md["sketch"]["sign"] != ZUNO_VALID_SIGN):
            printInfo(" -- NO VALID SKETCH -- ")
            return
        sketch_build_datetime =  datetime.datetime.fromtimestamp(float(md["sketch"]["build_ts"])).strftime("%Y-%m-%dT%H:%M:%S(MSK)")
        printInfo("\t NAME:\t\t\t%s"%(md["sketch"]["name"]))
        printInfo("\t BUILD_DATETIME:\t%s"%(sketch_build_datetime))
        printInfo("\t VERSION:\t\t%s"%(formatHexVersion2b(md["sketch"]["sketch_version"])))
        printInfo("\t SIZE:\t\t\t%d Bytes"%(md["sketch"]["code_size"]))
        printInfo("\t CRC16:\t\t\t%04x"%(md["sketch"]["crc16"]))
        printInfo("\t FLAGS:\t\t\t%08x"%(md["sketch"]["flags"]))
        printInfo("\t CORE_VERSION:\t\t%s"%(formatHexVersion2b(md["sketch"]["core_version"])))
        printInfo("\t OTA_FW_ID:\t\t%04x"%(md["sketch"]["fw_id"]))
        printInfo("\t OTA_CUSTOM_FW_COUNT:\t%02d"%(md["sketch"]["ota_extra_fwcount"]))
        printInfo("\t OTA_PINCODE:\t\t%08x"%(md["sketch"]["ota_pincode"]))
        printInfo("\t OTA_OFFSET:\t\t%08x"%(md["sketch"]["ota_extra_offset"]))
        console_pin = "N/A"
        if md["sketch"]["console_pin"] != 0xFF:
            if md["sketch"]["console_pin"] == 0xFE:
                console_pin = "DEFAULT (TX0)"
            else:
                console_pin = printZGMPort(md["sketch"]["console_pin"])
        printInfo("\t DBG_CONSOLE_PIN:\t%s"%(console_pin))
        printInfo("-"*column_len)
        


def loadJSONData(filename):
    if os.path.isfile(filename):
        ts = time.time()
        text = loadSourceFile(filename, False)
        #md = orjson.loads(text)
        md = json.loads(text)
        logging.info("*** JSON %s load elapsed:%3.3f"%(filename, time.time() - ts))
        return md
    return None 
def dumpJSONData(filename, metadata, sort=True):
    try:
        #text = orjson.dumps(metadata).decode('utf-8')
        text = json.dumps(metadata)
        saveTextFile(filename, text)
    except:
        path, key  = zmefindNonStringKey(metadata)
        if path != None:
            print("NON STR KEY in JSON!")
        zmeProcessException("ORJSON>DUMP")
        
def find_nth_line(s, n):
    index = 0
    line = 0
    for symb in s:
        if symb == '\n':
            line += 1
            if line == n:
                return index
        index += 1 
    return -1
def addLines2Text(lines, nl = ""):
    text = ""
    for l in lines:
        text += l + nl
    return text

g_commented_code = False
def drop_comments_inside_line(line):
    index_start = line.find("/*")
    index_stop = line.find("*/")
    if index_start != -1 and index_stop != -1:
        line = line[:index_start] + line[index_stop+2:]
        #print("***1cmt:%s"%(line))
        return drop_comments_inside_line(line)
    elif index_start != -1:
        return 1, line[:index_start]
    elif index_stop != -1:
        return 2, line[index_stop+1:]
    return 0, line
def start_comment_filter(mode):
    global g_commented_code
    g_commented_code = mode
def filter_comments(context, line):
    type, line = drop_comments_inside_line(line)
    if context:
        #print("*** commented: type:%d %s"%(type, line))
        if type == 2:
            context = False
            return line
        else:
            return ""
    elif type == 1:
        context = True
    return line
def zme_costruct_int(arr, n, inv = True):
    val =0
    for i in range(n):
        val <<= 8
        indx = i
        if inv:
            indx = n-1-i
        if (indx < len(arr)) and (indx >= 0):
            val += arr[indx]
    return val

def zme_int_toarr(val, n, bba = False, bInv = False):
    a = []
    for i in range(n):
        if bInv:
            a = [val & 0xFF] + a
        else:
            a += [val & 0xFF]
        val >>= 8
    if bba:
        a = bytearray(a)
    return a
def zme_multibyte_inc(data, n=4):
    for i in range(n):
        t = data[n-1-i] + 1 
        data[n-1-i] = t & 0xFF
        # перенос?
        if t <= 0xFF:
            break # Нет переноса
    return data
def zme_loadSiTokenFile(filename):
    lines = loadSourceFile(filename)
    data = {}
    for l in lines:
        l = l.strip()
        if l.startswith("#"):
            continue
        ll = l.split(":")
        if len(ll) == 2:
            data[ll[0].strip()] = ll[1].strip()
    return data
def encryptAESBlock(b, key):
    aes = AES.new(bytearray(key), AES.MODE_ECB)
    ret = list(aes.encrypt(bytearray(b)))
    return ret
def calcAESCMAC(key, message):
    cobj = CMAC.new(bytearray(key), ciphermod=AES)
    cobj.update(bytearray(message))
    return list(cobj.digest())
def xorBuff(a,b, count = None):
    o = []
    if count == None:
        count = len(a)
    for i in range(count):
        o += [a[i] ^ b[i]]
    return o
def encryptOFB(d, key, iv):
    aes = AES.new(key, AES.MODE_ECB)
    offset = 0
    # Используется OFB
    ret = [0xFF]*len(d)
    while offset < len(d):
        iv = aes.encrypt(iv)
        for i in range(len(iv)):
            ret[offset + i] = d[offset + i] ^ iv[i]
        offset += len(iv)
    return ret
def list2ba(l):
    if isinstance(l, list):
        return bytearray(l)
    return l
def makeS0Keys(key):
    key = list2ba(key)
    aes = AES.new(key, AES.MODE_ECB)
    Ka = aes.encrypt(bytearray([0x55]*16))
    Ke = aes.encrypt(bytearray([0xAA]*16))
    return Ka, Ke
    
def calcS0MACCode(d, key, iv):
    key = list2ba(key)
    iv = list2ba(iv)
    aes = AES.new(key, AES.MODE_ECB)
    iv = aes.encrypt(iv)
    padded_len = len(d)
    rest = len(d) % 16
    if (rest) != 0:
        padded_len += 16 - rest
    i = 0
    while i<padded_len:
        iv_l = list(iv)
        for j in range(16):
            index = i+j
            b = 0
            if index < len(d):
                b = d[index]
            iv_l[j] ^= b 
        iv = aes.encrypt(bytearray(iv_l))
        i += 16
    return list(iv[:8])
def decryptS0Data(d, key, iv):
    key = list2ba(key)
    iv = list2ba(iv)
    aes = AES.new(key, AES.MODE_ECB)
    padded_len = len(d)
    rest = len(d) % 16
    if (rest) != 0:
        padded_len += 16 - rest
    i = 0
    res = [0xFF]*len(d)
    while i<padded_len:
        iv = aes.encrypt(iv)
        for j in range(16):
            index = i+j
            if index >= len(d):
                break
            res[index] = d[index] ^ iv[j]
        i += 16
    return res
    '''
    memcpy(g_encrypt_buff, iv, AES_DATA_LENGTH);
    for (i=0; i < padded_len; i+= AES_DATA_LENGTH) {
        ZMESC_AES_ECB(key, g_encrypt_buff, g_encrypt_buff);
        
        for (j=0; j<AES_DATA_LENGTH; j++) {
            BYTE index = i + j;
            if (index >= len)
                break;
            output[index] = input[index] ^ g_encrypt_buff[j];
        }   
    }
    '''

def zme_findHubPort(hub_path, prefix, dev_path):
    if(not os.path.exists(hub_path)):
        return None
    for filename in os.listdir(hub_path):
        fname = os.path.basename(filename)
        if fname.find(prefix) != -1:
            return dev_path + fname
    return None

def zme_findHubPortMD(md):
    if md["usb_directmode"]:
        return md["usb_directpath"] 
    hub_path = md["usb_hub"]
    prefix = md["usb_port"]
    dev_path = md["usb_prefix"]
    if(not os.path.exists(hub_path)):
        return None
    for filename in os.listdir(hub_path):
        fname = os.path.basename(filename)
        if fname.find(prefix) != -1:
            return dev_path + fname
    return None
def zmeCheckRefIntervalValue(val_name, dataset, refset):
    if not (val_name in dataset):
        return None
    if not (val_name in refset):
        return None
    val = dataset[val_name]
    mn = refset[val_name][0]
    mx = refset[val_name][1]
    return (val >= mn) and (val <= mx)

def zmeCheckRefIntervalSet(dataset, refset):
    res_map = 0
    i = 0
    for v_name in dataset:
        r = zmeCheckRefIntervalValue(v_name, dataset, refset)
        if r != None:
            if not r:
                res_map |= 1 << i
        i += 1
    return res_map
def zmecallDictByPath(element, d, bNone = True, value=None):
    keys = element.split('.')
    rv = d
    num = 0
    for key in keys:
        if isinstance(rv, list):
            key = int(key, 0)
            if(bNone):
                if (key >= len(rv)) or (key < 0):
                    return None
        else:
            if(bNone):
                if not (key in rv):
                    return  None
            elif not (key in rv):
                if num == len(keys)-1:
                    if value.isdigit():
                        value = int(value, 0) 
                    rv[key] = value
                else:
                    rv[key] = {}

        rv = rv[key]
        num+=1
    return rv
def addDPath(p, k):
    np = p
    if (len(p) > 0) and not(p.endswith(".")):
        np += "."
    np += k
    return np
def makePathFromArr(arr):
    p = ''
    for a in arr:
        p = addDPath(p, a)
    return p
def compileFullPathList(element, d):
    pl = []
    keys = element.split('.')
    rv = d
    current_path = ""
    i = 0
    for key in keys:
        if key.startswith("[") and key.endswith("]"):
            vla = key[1:-1].split(",")
            for v in vla:
                v = v.strip()
                #print("**V:%s"%(v))
                lp = addDPath(current_path, v)
                if v in rv:
                    #print("<>");
                    rp = makePathFromArr(keys[i+1:])
                    #print("rp:%s"%(rp))
                    llist = compileFullPathList(rp, rv[v])
                    for l in llist:
                        pl += [addDPath(lp, l)]
            return pl
        if key == "*":
            for k in rv:
                lp = addDPath(current_path, k)
                llist = compileFullPathList(makePathFromArr(keys[i+1:]),  rv[k])
                for l in llist:
                    pl += [addDPath(lp, l)]
            return pl
        if not(key in rv):
            #print("---")
            return []
        rv = rv[key]
        i += 1
        current_path = addDPath(current_path, key)
    pl = [current_path]
    return pl
def zmePatchJSON(data, patch_data):
    for ref in patch_data:
        xrf = compileFullPathList(ref, data)
        #print("PATHLIST:%s"%(xrf))
        for r in xrf:
            sd = zmecallDictByPath(r, data)
            if sd != None:
                #print("ref=%s patch:%s"%(ref, patch_data[ref]))
                sd.update(patch_data[ref]["patch"])
    return data
ZME_FORMAT_TYPES = ["FPOINT", "HEXBUFF"]
def zmeFormatFunc(val, param_list, d):
    if len(param_list) < 1:
        return "%s"%(val)
    type = param_list[0]
    if not type in ZME_FORMAT_TYPES:
        return "%s"%(val)
    if type == "FPOINT":
        if len(param_list) < 2:
            return "%s"%(val)
        point_pos = 0
        p = param_list[1]
        if p.startswith("@"):
            p = p[1:]
            dv = zmecallDictByPath(p,d)
            if dv != None:
                point_pos = dv
        else:
            point_pos = int(p,0)
        if point_pos != 0:
            divd = 1
            while point_pos:
                divd *= 10
                point_pos -= 1
            return ("%d.%d"%(val//divd,val % divd))
        return "%d"%(val)
    elif type == "HEXBUFF":
        return splitHexBuff(val)
    return "%s"%(val)
def zmeFormatDict(fmt_str, d):
    indx = 0
    ret = str(fmt_str)
    while 1:
        indx = fmt_str.find("$(",indx)
        if indx == -1:
            break
        indx_end = fmt_str.find(")",indx)
        if indx_end == -1:
            break
        sf = fmt_str[indx:indx_end+1]
        s = fmt_str[indx+2:indx_end]
        vl = s.split(",")
        data = zmecallDictByPath(vl[0],d)
        if data == None:
            ret = ret.replace(sf, "")
        else:
            if len(vl) > 1:
                if vl[1] == "ZME_FMT":
                    str_vl = zmeFormatFunc(data, vl[2:], d)
                    ret = ret.replace(sf, str_vl)
                else:
                    f = "%"+vl[1]
                    ret = ret.replace(sf, f%(data))
            else:
                ret = ret.replace(sf, "%s"%(data))
        indx = indx_end
    return ret
def zmeStrListFromIntList(l):
    sl = []
    for el in l:
        sl += "%d"%(el)
    return sl
def zmeFilterListAsSet(l):
    new_l = []
    st = {}
    for el in l:
        if not (el in st):
            st[el] = 1
            new_l += [el]
    return new_l
def zmeMaxKey(d):
    res = None
    for k in d:
        if (res == None) or (res < k):
            res = k
    return res
def zmeDictVal2Key(d, val):
    for k in d:
        if d[k] == val:
            return k
    return None

def zmeSyncEventLoop():
    loop = None
    try:
        loop = asyncio.get_event_loop()
    except:
        loop = None
    if loop == None:
        logging.error("*** (Thread:%s) New event loop:%s"%(threading.current_thread, traceback.format_stack()))
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop
def zmeSyncPushToBuff(lk, buff, data):
    loop = zmeSyncEventLoop()
    loop.run_until_complete(zmeAsyncPushToBuff(lk, buff, data))
def zmeSyncBuffSize(lk, buff):
    loop = zmeSyncEventLoop()
    return loop.run_until_complete(zmeAsyncBuffSize(lk, buff))
def zmeSyncClearBuff(lk, buff):
    loop = zmeSyncEventLoop()
    loop.run_until_complete(zmeAsyncClearBuff(lk, buff))
def zmeSyncPopFromBuff(lk, buff, sz = 1, timeout = 2.0):
    res = None
    t = time.time() + timeout
    while True:
        if zmeSyncBuffSize(lk, buff) >= sz:
            loop = zmeSyncEventLoop()
            return loop.run_until_complete(zmeAsyncPopFromBuff(lk, buff, sz))
        time.sleep(0.01)
        if time.time() > t:
            return None
        
async def zmeAsyncBuffSize(lk, buff):
    async with lk:
        return len(buff)
async def zmeAsyncClearBuff(lk, buff):
    async with lk:
        buff.clear()
async def zmeAsyncPushToBuff(lk, buff, data):
    async with lk:
        buff += data
async def zmeAsyncPopFromBuff(lk, buff, sz = 1):
    async with lk:
        if len(buff) >= sz:
            res = list(buff[:sz])
            count = sz
            while count:
                buff.pop(0)
                count -= 1
            return res
    return None
    
FILTER_RULE_IN = 0
FILTER_RULE_NOT_IN = 1
FILTER_RULE_GREATER = 2
FILTER_RULE_LESS=3
FILTER_RULE_IN_RANGE = 4
FILTER_RULE_NOT_IN_RANGE = 5

FILTER_RULE_TYPES = [FILTER_RULE_IN, FILTER_RULE_NOT_IN, FILTER_RULE_GREATER, FILTER_RULE_LESS, FILTER_RULE_IN_RANGE, FILTER_RULE_NOT_IN_RANGE]
FILTER_MODIFICATOR_NONE = 0
FILTER_MODIFICATOR_LIST2INT = 1

def zme_applymodificator(val, m):
    if m == None:
        return val
    type = m[0]
    if type == FILTER_MODIFICATOR_NONE:
        return val
    if type == FILTER_MODIFICATOR_LIST2INT:
        start = m[1]
        size = m[2]
        return zme_costruct_int(val[start:], size, False)
    return val
def zme_extract_filter_expression(fieldname, ruletype, expressions):
    index = 0
    for e in expressions:
        name = e[0]
        type = e[2]
        if fieldname == name and ruletype == type:
            return e, index
        index += 1
    return None, -1
def zme_dictfilter(d, expressions):
    filtered = False
    for e in expressions:
        field_name = e[0]
        modificator = e[1]
        rule_type = e[2]
        arg = e[3]
        dv = zmecallDictByPath(field_name, d)
        if dv == None:
            continue         
        dv = zme_applymodificator(dv, modificator)
        if dv == None:
            continue
        if not (rule_type in FILTER_RULE_TYPES):
            continue
        if rule_type == FILTER_RULE_IN:
            if not (dv in arg):
                return True
        elif rule_type == FILTER_RULE_NOT_IN:
            if (dv in arg):
                return True
        elif rule_type == FILTER_RULE_LESS:
            if (dv > arg):
                return True
        elif rule_type == FILTER_RULE_GREATER:
            if (dv < arg):
                return True
        elif rule_type == FILTER_RULE_IN_RANGE:
            if (dv < arg[0]) or (dv > arg[1]):
                return True
        elif rule_type == FILTER_RULE_NOT_IN_RANGE:
            if (dv >= arg[0]) and (dv <= arg[1]):
                return True
    return filtered

class ZMETimeMeasureBot:
  def __init__(self, name, bPrint = True, bLog = True, handler = None):
    self._name = name
    self._bPrint = bPrint
    self._bLog = bLog
    self._handler = handler
    self._marks = {}
    self._start = time.time()
    print("Bot:%s StartTime:%s"%(name, self._start))
    self.time_func = time.time
    self._old_sleepfunc = time.sleep
    self._my_thread = threading.current_thread()
    time.sleep = self.customSleep
    self._sleep_time = 0.0
    self._ext_sleep_time = 0.0
  def customSleep(self, val):
    #print("Sleep:%s"%(val))
    self._old_sleepfunc(val)
    if threading.current_thread() == self._my_thread:
        self._sleep_time += val
    else:
        self._ext_sleep_time += val
        
  def addMark(self, mark_name):
    self._marks[mark_name] = time.time() - self._start
  def __del__(self):
    time.sleep = self._old_sleepfunc
    stop_time = self.time_func()
    elapsed = stop_time - self._start
    mark_text = ""
    i = 0
    for m in self._marks:
        if i!=0:
            mark_text += ", "
        mark_text += "%s: %5.3f"%(m, self._marks[m])
        i += 1
    main_text = "*** TimeBot:%s Elapsed:%5.3fs {%s} Sleeped:%5.3fs ExtSleep:%5.3fs"%(self._name, elapsed, mark_text, self._sleep_time, self._ext_sleep_time)
    if self._bPrint:
        print(main_text)
    if self._bLog:
        logging.info(main_text)
        
def zmeProcessException(name=""):
    exc_text = "***Exception %s:%s"%(name, traceback.format_exc())
    #print(exc_text)
    logging.error(exc_text)

def zme_open_explorer(path):
    if platform.system() == "Windows":
        os.startfile(path)
    elif platform.system() == "Darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])

def zmefindNonStringKey(d, path=""):
    if not isinstance(d, dict):
        return None, None
    for k in d:
        if not isinstance(k, str):
            print("*** Non string key:%s.%s"%(path, k))
            return path, k
        if isinstance(d[k], dict):
            ret_path, ret_key  = zmefindNonStringKey(d[k], path + "."+k)
            if ret_path != None:
                return ret_path, ret_key
    return None, None

def zmeUserStoragePath(sub_path = None):
    path = os.path.expanduser("~")+os.sep+"ZMEStorage"+ os.sep
    if sub_path != None:
        if not sub_path.endswith(os.sep):
            sub_path += os.sep
        path += sub_path
    if not os.path.isdir(path):
        os.makedirs(path)
    return path
def zmeSetupLogging(name, bVerbose=True, bNoStdOutput=False):
    if 'ZME_LOGPATH' in os.environ:
        log_path = os.environ['ZME_LOGPATH']
        if not os.path.isdir(log_path):
            os.makedirs(log_path)
    else:
        log_path = zmeUserStoragePath()
    fn =  '%s/%s-%s.log' % (log_path, name, strftime("%Y-%m-%d", gmtime()))
    format_str = '%(levelname)-8s [%(asctime)s]  %(message)s'
    lev = logging.WARNING
    if bVerbose:
        lev = logging.DEBUG
    logging.basicConfig(format=format_str, level=lev, filename=fn)
    if not bNoStdOutput:
        print("--- HANDLER ----")
        root = logging.getLogger()
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(format_str)
        handler.setFormatter(formatter)
        handler.setLevel(lev)
        root.addHandler(handler)
def zmeRemapDictVal2Key(d, val):
    for k in d:
        if d[k] == val:
            return k
    return None
def zmeFixByteArray(arr):
    fl = []
    i = 0
    for i in range(len(arr)):
        a = arr[i]
        if a > 0xff:
            print('Greater then byte[%d]=%d'%(i, a))
            a &= 0xFF
        fl += [a]
    return fl
def zme_arrayVal(a, i, d = 0xFF):
    if i < len(a):
        return a[i]
    return d
def zme_arrayDiff(a,b):
    rs = []
    l = len(a)
    if len(b) > l:
        l = len(b)
    for i in range(l):
        v_a = zme_arrayVal(a, i)
        v_b = zme_arrayVal(b, i)
        if v_a != v_b:
           rs += [i, v_a, v_b]
def zme_formatArrayDiff(arr_diff):
    text = ""
    for e in arr_diff:
        text += "%8x %02x %02x\n"%(e[0], e[1], e[2])
    return text
class ZMEIOException(Exception):
    pass