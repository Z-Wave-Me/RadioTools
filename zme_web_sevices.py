import sys
import random
import datetime
from threading import Thread
from common.zme_aux import *
import requests
import traceback


class ZUnoOnlineFWUpdater:
    # http://z-uno.z-wave.me/files/z-uno2/zuno_md_beta.json
    def __init__(self, repo_table={"stable":"https://z-uno.z-wave.me/files/z-uno2/zuno_md.json","beta":"https://z-uno.z-wave.me/files/z-uno2/zuno_md_beta.json"}):
        self._minimal_version = 0
        self._repos = repo_table
        self._fw_table = {}
        self._tmp_dir = os.path.expanduser("~") + "/ZMEStorage/fw_update/ZUno/"
        self._tmp_dir = self._tmp_dir.replace("/",os.sep)
        self._progress_handler = None
    def setProgressHandler(self, handler):
        self._progress_handler = handler
    def setMinimalVersion(self, version):
        self._minimal_version = version
    def updateList(self):
        self._fw_table = {}
        for r in self._repos:
            version_suffix = r
            url = self._repos[r]
            base_url = url[:url.rfind('/')+1]
            core_url = base_url + "cores/"
            response = requests.get(url)
            if response.status_code == 200:
                md = response.json()
                if "cores" in md:
                    for filename in md["cores"]:
                        dt = md["cores"][filename]["build_time"]
                        file_url = core_url + filename
                        sv = 0
                        if len(md["cores"][filename]["version_digits"]) > 3:
                            sv = md["cores"][filename]["version_digits"][3]
                        version = "%s-%02d.%02d.%02d.%02d"%(version_suffix, 
                                                            md["cores"][filename]["version_digits"][0],
                                                            md["cores"][filename]["version_digits"][1],
                                                            md["cores"][filename]["version_digits"][2],
                                                            sv)
                        self._fw_table[version] = {"url":file_url, "timestamp":dt}
        return  list(self._fw_table)
    def versionList(self, minimal_version = None):
        l = []
        for v in self._fw_table:
            if minimal_version == None:
                l += [v]
            else:
                ii = v.find("-")
                nv = v[ii+1:]
                if nv >= minimal_version:
                    l += [v]
        return  l
    def _extract_prghandler_proxy(self, current, overall):
        if self._progress_handler != None:
            self._progress_handler("Ectracting", int((100.0*current) / (overall)))
    def prepareFileForUpgrade(self, hwrev, version, b_clean = False):
        if not (version in self._fw_table):
            return None
        try:
            output_dir = self._tmp_dir + version + os.sep
            if b_clean and os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            output_file = output_dir + os.sep + version + ".zip"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                url = self._fw_table[version]["url"]
                response = requests.get(url, stream=True)
                if response.status_code == 200:
                    total_size_in_bytes= int(response.headers.get('content-length', 0))
                    block_size = 1024 #1 Kibibyte
                    sz  =0
                    with open(output_file, 'wb') as file:
                        for data in response.iter_content(block_size):
                            file.write(data)
                            sz += len(data)
                            if self._progress_handler != None:
                                self._progress_handler("Downloading %s"%(url), int((100.0*sz) / (total_size_in_bytes)))
                else:
                    return None

            bootloders_dir =  output_dir+"bootloaders"
            if not os.path.exists(bootloders_dir):
                if not os.path.isfile(output_file):
                    shutil.rmtree(output_dir)
                    return None
                extractArchive(output_file, output_dir, progress_cbk=self._extract_prghandler_proxy)
            needed_filename = bootloders_dir + os.sep + "zuno_bootloader_HW%04x.bin"%(hwrev)
            print("*** needed filename:%s"%(needed_filename))
            if not os.path.isfile(needed_filename):
                print("***Wrong filename:%s"%(needed_filename))
                #shutil.rmtree(output_dir)
                return None
            return needed_filename
        except Exception as e:
            logging.error("prepareFileForUpgrade exception:%s %s"%(e, traceback.format_exc()))  
        return None                
class SAPIOnlineFWUpdater:
    def __init__(self, repo="https://service.z-wave.me/expertui/uzb"):
        self._repo = repo
        self._tmp_dir = os.path.expanduser("~") + "/ZMEStorage/fw_update/SAPI"
        self._progress_handler = None
        self._fw_table = {}
    def setProgressHandler(self, handler):
        self._progress_handler = handler
    def updateList(self, bootloader_version, version_minor, vendor=0x0147, version_major=7):
        self._fw_table = {}
        try:
            req_str = ("%s?vendorId=%d&appVersionMajor=%d&appVersionMinor=%d&bootloaderCRC=%d&token=all&uuid=1")%(self._repo, vendor, version_major, version_minor, bootloader_version)
            response = requests.get(req_str)
            if response.status_code == 200:
                md = response.json()
                print("rewuest:%s md:%s"%(req_str, md))
                if md != None:
                    if "data" in md:
                        for d in md["data"]:
                            #print("d:%s"%(d))
                            version = "SAPI_%s_%04x-%02d.%02d"%(d["type"], vendor, int(d["targetAppVersionMajor"]), int(d["targetAppVersionMinor"]))
                            file_url = self._repo + "/" + d["fileURL"]
                            self._fw_table[version] = {"url":file_url, "type":d["type"]}
        except:
            logging.error("Exception SAPIOnlineFWUpdater.updateList: %s"%(traceback.format_exc()))
        #print("fw list:%s"%(list(self._fw_table)))
        return list(self._fw_table)
    def _extract_prghandler_proxy(self, current, overall):
        if self._progress_handler != None:
            self._progress_handler("Extracting", int((100.0*current) / (overall)))
    def prepareFileForUpgrade(self, version, b_clean = False):
        if not (version in self._fw_table):
            return None
        try:
            output_dir = self._tmp_dir + "/"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            output_file = output_dir + "/" + version + ".glb"
            if b_clean and os.path.isfile(output_file):
                os.remove(output_file)
            if not os.path.isfile(output_file):
                url = self._fw_table[version]["url"]
                response = requests.get(url, stream=True)
                if response.status_code == 200:
                    total_size_in_bytes= int(response.headers.get('content-length', 0))
                    block_size = 1024 #1 Kibibyte
                    sz  =0
                    with open(output_file, 'wb') as file:
                        for data in response.iter_content(block_size):
                            file.write(data)
                            sz += len(data)
                            if self._progress_handler != None:
                                self._progress_handler("Downloading %s"%(url), int((100.0*sz) / (total_size_in_bytes)))
                    return output_file
                else:
                    return None
            else:
                return output_file
        except:
            logging.error("prepareFileForUpgrade exception:%s %s"%(e, traceback.format_exc()))                  
        return None
class ZMELicenseService:
    def __init__(self, url="https://z-wave.me/hardware-capabilities/", extract_url="https://service.z-wave.me/hardware/capabilities/"):
        self._main_url = url
        self._request_url = extract_url
        self._timeout = 0.5
    def webUIURL(self, uuid=None):
        url = self._main_url
        if uuid != None:
            url += "?uuid=%s"%(uuid)
        return url
    def getCurrentLicense(self, uuid):
        if isinstance(uuid, list):
            uuid = splitHexBuff(uuid, 64).replace(" ","")
        try:
            req_str = ("%s?uuid=%s")%(self._request_url, uuid)
            response = requests.get(req_str, self._timeout)
            if response.status_code == 200:
                md = response.json()
                return md
        except:
            logging.error("ZMELicenseService.getCurrentLicense: %s"%(traceback.format_exc()))
        return None
 