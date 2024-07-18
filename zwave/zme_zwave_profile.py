import time
import traceback 
import xml.etree.ElementTree as ET
import argparse
from common.zme_aux import *

MY_VERSION=0.1

def elementToDict(element, mdata, bd=False, vr=False):
    md = {}
    #print("ATTR:%s"%(element.attrib))
    for a in element.attrib:
        if (a != "key") and (a != "version"):
            md[a] = element.attrib[a]
    for child in element:
        b_dict = False
        b_versioned = False
        if "key" in child.attrib:
            b_dict = True
        if b_dict and ("version" in child.attrib):
            b_versioned = True
        if child.tag not in md:
            logging.debug("TAG:%s"%(child.tag))
            if b_dict:
                md[child.tag] = {}
            else:
                md[child.tag] = []
        elementToDict(child, md[child.tag], b_dict, b_versioned)
    if bd:
        key_i = element.attrib["key"]
        if vr:
            vr_key = element.attrib["version"]
            if not (key_i in mdata):
                mdata[key_i] = {}
            mdata[key_i][vr_key] = md
        else:
            mdata[key_i] = md
    else:
        #print("L1:%s l2:%s"%(mdata, md))
        mdata += [md]
    return 0
def loadZWAllianceProfile(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    data = []
    if root.tag != "zw_classes":
        return -1, None
    elementToDict(root, data, False)
    if len(data):
        return 0, data[0]
    return -100, None


def postProcessJSON(d):
    if isinstance(d, dict):
        nd = {}
        for key in d:
            nk = key
            data = d[key]
            if isinstance(key, str):
                numeric = False
                if key.startswith("0x"):
                    numeric = True
                if key.isdigit():
                    numeric = True
                if numeric:
                    nk = int(key,0)
            d1 = postProcessJSON(data)
            nd[nk] = d1
        d = nd
    elif  isinstance(d, list):
        for i in range(len(d)):
            d[i] = postProcessJSON(d[i])
    elif  isinstance(d, str):
        numeric = False
        if d.startswith("0x"):
            numeric = True
        if d.isdigit():
            numeric = True
        if numeric:
            d = int(d,0)

    return d


class ZWaveDataEncoder:
    def __init__(self, profile_name = "zme_zwave_profile.json"):
        self.profile_data = {}
        self.profile_data = loadJSONData(profile_name)
        if self.profile_data != None:
            self.profile_data = postProcessJSON(self.profile_data)
        self._default_spelling = "$(cc_name).$(cmd_name)"
    def extractVersionMapForCC(self, cc):
        if isinstance(cc, str):
            cc = self.CCNameToVal(cc)
        if not cc in (self.profile_data["cmd_class"]):
            return [1]
        l = []
        for v in self.profile_data["cmd_class"][cc]:
            l += [v]
        return l
    def getCCHighestVersion(self, cc):
        vl = self.extractVersionMapForCC(cc)
        vl.sort()
        return vl[-1]
    def getCCLowestVersion(self, cc):
        vl = self.extractVersionMapForCC(cc)
        vl.sort()
        return vl[0]
    def extractCCSListNames(self):
        l = []
        if not "cmd_class" in self.profile_data:
            return l
        for c in self.profile_data["cmd_class"]:
            name = self.profile_data["cmd_class"][c][1]["name"].replace("COMMAND_CLASS_","").strip()
            l += [name]
        return l
    def CCValToName(self, val):
        if (not val in self.profile_data["cmd_class"]):
            return None
        if not (1 in self.profile_data["cmd_class"][val]):
            return None
        return self.profile_data["cmd_class"][val][1]["name"]

    def CCNameToVal(self, name):
        for c in self.profile_data["cmd_class"]:
            ccname = self.profile_data["cmd_class"][c][1]["name"].replace("COMMAND_CLASS_","")
            if ccname == name:
                return c
        return None
    def extractCommandNamesForCC(self, cc, version=1):
        if isinstance(cc, str):
            cc = self.CCNameToVal(cc)
        if not (cc in self.profile_data["cmd_class"]):
            return []
        if not (version in self.profile_data["cmd_class"][cc]):
            return []
        if not ("cmd" in self.profile_data["cmd_class"][cc][version]):
            return []
        l = []
        ccname = self.profile_data["cmd_class"][cc][version]["name"].replace("COMMAND_CLASS_","")
        #print("CCNAME:%s"%(ccname))
        for cmd in self.profile_data["cmd_class"][cc][version]["cmd"]:
            l += [self.profile_data["cmd_class"][cc][version]["cmd"][cmd]["name"].replace(ccname+"_","").strip()]
        return l
    def CCCommandName(self, cc, cmd):
        cc_name = self.CCValToName(cc)
        if cc_name == None:
            return None
        cc_name = cc_name.replace("COMMAND_CLASS_","")
        for version in self.profile_data["cmd_class"][cc]:
            if cmd in self.profile_data["cmd_class"][cc][version]["cmd"]:
                cmd_name = self.profile_data["cmd_class"][cc][version]["cmd"][cmd]["name"]
                cmd_name = cmd_name.replace(cc_name+"_","").strip()
                return "%s.%s"%(cc_name, cmd_name)
        return None
    def CCCommandNameI(self, cc_cmd):
        return self.CCCommandName((cc_cmd >> 8) & 0xFF, cc_cmd & 0xFF)
    def CmdName2ID(self, cc, version, cmd):
        if isinstance(cc, str):
            cc = self.CCNameToVal(cc)
            if cc == None:
                return None
        if not (version in self.profile_data["cmd_class"][cc]):
            return None
        if not ("cmd" in self.profile_data["cmd_class"][cc][version]):
            return None
        ccname = self.profile_data["cmd_class"][cc][version]["name"].replace("COMMAND_CLASS_","")
        for c in self.profile_data["cmd_class"][cc][version]["cmd"]:
            cmdname = self.profile_data["cmd_class"][cc][version]["cmd"][c]["name"].replace(ccname+"_","").strip()
            if cmdname == cmd:
                return c
        return None
    def extractCommandParams(self, cc, cmd, version=1):
        if isinstance(cc, str):
            cc = self.CCNameToVal(cc)
        if isinstance(cmd, str):
            cmd = self.CmdName2ID(cc, version, cmd)
            if cmd == None:
                return None
        if not ("param" in self.profile_data["cmd_class"][cc][version]["cmd"][cmd]):
            return []
        l = []
        for p in self.profile_data["cmd_class"][cc][version]["cmd"][cmd]["param"]:
            l += [self.profile_data["cmd_class"][cc][version]["cmd"][cmd]["param"][p]]
        return l
    def _type2size(self, type):
        if (type == "BYTE") or (type == "STRUCT_BYTE") or (type == "CONST"):
            return 1
        if (type == "WORD"):
            return 2
        if (type == "DWORD"):
            return 4
        return 1
    @staticmethod
    def _extractVarSzFromRAW(variant, d):
        sz_i = variant[0]["paramoffs"]
        if sz_i == 0xFF:
            return -1
        if sz_i >= len(d):
            return -2
        sz = d[sz_i]
        if "sizemask" in variant[0]:
            mask = variant[0]["sizemask"]
            sz &= mask
        if "sizeoffs" in variant[0]:
            sh = variant[0]["sizeoffs"]
            sz >>= sh
        if sz == 3:
            sz = 2
        if (sz > 4) and (sz < 8):
            sz = 4
        return sz
    @staticmethod
    def extractConstValueList(param):
        l = []
        for k in param["const"]: 
            l += [k]
        return k
    @staticmethod
    def extractEnumList(enum):
        l = []
        for en_entity in enum["fieldenum"]:
            l += [en_entity["value"]]
        return l

    def encodeApplication(self, cc, cmd, params, version = 1):
        raw_data = []
        if isinstance(cc, str):
            cc = self.CCNameToVal(cc)
        if isinstance(cmd, str):
            cmd = self.CmdName2ID(cc, version, cmd)
        param_map = self.extractCommandParams(cc, cmd, version)
        raw_data += [cc]
        raw_data += [cmd]
        i = 0
        for p in param_map:
            val = params[i]
            sz = self._type2size(p["type"])
            if p["type"] == "CONST":
                if val[0].isdigit():
                    val = int(val,0)
                else:
                    for k in p["const"]:
                        v = p["const"][k]["flagmask"]
                        if k == val:
                            val = v
                            break
            elif p["type"] == "STRUCT_BYTE":
                # Упаковываем в структуру
                if isinstance(val, list):
                    j = 0
                    tmp_val = 0
                    if "fieldenum" in p:
                        for enum in p["fieldenum"]:
                            if j >= len(val):
                                break
                            en = p["fieldenum"][enum]
                            choices = ZWaveDataEncoder.extractEnumList(en)
                            sv = 0
                            try:
                                sv = choices.index(val[j])
                            except:
                                sv = 0
                                pass
                            if "shifter" in en:
                                sv <<= en["shifter"]
                            if "fieldmask" in en:
                                mask = en["fieldmask"]
                                sv &= mask
                            tmp_val |= sv
                            j += 1
                    if "bitfield" in p:
                        for bf in p["bitfield"]:
                            if j >= len(val):
                                break
                            sv = int(val[j], 0)
                            bd = p["bitfield"][bf]
                            if "shifter" in bd:
                                sv <<= bd["shifter"]
                            if "fieldmask" in bd:
                                mask = bd["fieldmask"]
                                sv &= mask
                            tmp_val |= sv
                            j += 1
                    if "bitflag" in p:
                        for bf in p["bitflag"]:
                            if j >= len(val):
                                break
                            sv = int(val[j], 0)
                            bd = p["bitflag"][bf]
                            flv = bd["flagmask"]
                            if sv != 0: 
                                tmp_val |= flv
                            j += 1
                    val = tmp_val
                else:
                    val = int(val, 0)
            elif p["type"] == "VARIANT":
                sz = ZWaveDataEncoder._extractVarSzFromRAW(p["variant"], raw_data[2:])
                logging.debug("*** VARSIZE for %s = %d"%(p["name"], sz))
                if sz <= 0:
                    sz = 1
                val = int(val,0)
            else:
                val = int(val,0)
            raw_data += zme_int_toarr(val, sz, bInv=True)
            i += 1
            if i>= len(params):
                break
        return raw_data
    # Обрабатываем здесь некоторые "Транспортные" классы команд, 
    # чтобы они смотрелись нагляднее в выводе
    def spellingSTUB(self, d, md):
        spelling = ""
        if md["cc_value"] == 0x41:
            spelling = "ROUTED_ACK"
        md["spelling"] = spelling
        return None

    def decodeApplication(self, d, preffered_versions={}):
        md = {}
        if len(d) < 2:
            return None
       
        if not "cmd_class" in self.profile_data:
            return None
        md["cc_value"] = d[0]
        md["cmd_value"] = d[1]
        md["cc_name"] = ""
        md["cmd_name"] = ""
        cc_key = d[0]
        cmd_key = d[1]
        current_version = 1
        if not (cc_key in self.profile_data["cmd_class"]):
            md["spelling"] = "Unknown Command Class"
            return md
        if d[0] in preffered_versions:
            current_version = preffered_versions[d[0]]
        elif "default_version" in self.profile_data["cmd_class"][cc_key]:
            current_version = self.profile_data["cmd_class"][cc_key]["default_version"]
        else:
            current_version = zmeMaxKey(self.profile_data["cmd_class"][cc_key])
        cc_data = self.profile_data["cmd_class"][cc_key][current_version]
        #print("CC_DATA:%s"%(cc_data))
        md["cc_name"] = cc_data["name"].replace("COMMAND_CLASS_","")
        if not ("cmd" in cc_data):
            #md = self.spellingSTUB(d, md)
            md["spelling"] = "Unknown Command"
            return md
        if not (cmd_key in cc_data["cmd"]):
            md["spelling"] = "Unknown Command"
            #md = self.spellingSTUB(d, md)
            return md
        cmd_data = cc_data["cmd"][cmd_key]
        md["cmd_name"] = cmd_data["name"].replace(md["cc_name"]+"_","")
        md["cc_version"] = current_version
        md["cmd_params"] = []
        param_offset = 2
        if ("param" in cmd_data) and (param_offset < len(d)):
            for param in cmd_data["param"]:
                pd = cmd_data["param"][param]
                p_md = {"name":pd["name"], "type":pd["type"], "size":1, "value":0}
                if (pd["type"] == "BYTE"):
                    if (param_offset) < len(d):
                        p_md["value"] = d[param_offset]
                elif (pd["type"] == "STRUCT_BYTE"):
                    if (param_offset) < len(d):
                        p_md["value"] = d[param_offset]
                    if "fieldenum" in pd:
                        p_md["sub_values"] = []
                        for enum in pd["fieldenum"]:
                            en = pd["fieldenum"][enum]
                            sv = p_md["value"]
                            if "fieldmask" in en:
                                mask = en["fieldmask"]
                                sv &= mask
                            if "shifter" in en:
                                sv >>= en["shifter"]
                            choices = ZWaveDataEncoder.extractEnumList(en)
                            if sv >= len(choices):
                                sv = 0
                            p_md["sub_values"] += [{"name":en["fieldname"], "value":choices[sv]}]
                    if "bitfield" in pd:
                        if not ("sub_values" in p_md):
                            p_md["sub_values"] = []
                        for bf in pd["bitfield"]:
                            sv = p_md["value"]
                            bd = pd["bitfield"][bf]
                            if "fieldmask" in bd:
                                mask = bd["fieldmask"]
                                sv &= mask
                            if "shifter" in bd:
                                sv >>= bd["shifter"]
                            p_md["sub_values"] += [{"name":bd["fieldname"], "value":sv}]
                    if "bitflag" in pd:
                        p_md["flags"] = []
                        for bf in pd["bitflag"]:
                            sv = p_md["value"]
                            bd = pd["bitflag"][bf]
                            flv = bd["flagmask"]
                            if (sv & flv) != 0: 
                                p_md["flags"] += [{"name":bd["flagname"], "value":flv}]
                elif (pd["type"] == "WORD"):
                    p_md["size"] = 2
                    if (param_offset + 2) <= len(d):
                        p_md["value"] = zme_costruct_int(d[param_offset:], 2, False)
                elif (pd["type"] == "DWORD"):
                    p_md["size"] = 4
                    if (param_offset + 4) <= len(d):
                        p_md["value"] = zme_costruct_int(d[param_offset:], 4, False)
                elif (pd["type"] == "VARIANT"):
                    sz = ZWaveDataEncoder._extractVarSzFromRAW(pd["variant"], d[2:])
                    if sz == -1:
                        sz = len(d) - (param_offset + 1)
                    if sz == -2:
                        sz = 1
                    p_md["size"] = sz
                    if (param_offset + sz) <= len(d):
                        if sz <= 4:
                            p_md["value"] = zme_costruct_int(d[param_offset:], sz, False)
                        else:
                            p_md["value"] = d[param_offset:param_offset+sz]
                            #print("***HUGE (%d) field:%s VALUE:%s (CC:%s CMD:%s) RAW:%s"%(sz, pd["name"], splitHexBuff(p_md["value"]), md["cc_name"], md["cmd_name"], splitHexBuff(d)))
                elif (pd["type"] == "CONST"):
                    p_md["value"] = d[param_offset]
                    p_md["value_name"] = "-"
                    if "const" in pd:
                        for k in pd["const"]:
                            v = pd["const"][k]["flagmask"]
                            if v == p_md["value"]:
                                p_md["value_name"] = pd["const"][k]["flagname"]
                    else:
                        logging.debug("No const section for %s.%s %s", md["cc_name"],  md["cmd_name"], pd["name"])
                param_offset += p_md["size"]  
                md["cmd_params"] += [p_md]
                if param_offset >= len(d):
                    break
        if "meta_param" in cmd_data:
            md["meta_params"] = []
            for p in cmd_data["meta_param"]:
                mpd = cmd_data["meta_param"][p]
                p_md = {"name":mpd["name"], "type":mpd["type"], "size":1}
                val = 0
                for r in mpd["ref"]:
                    v1 = d[2+r["index"]]
                    v1 &= r["mask"]
                    v1 >>= r["shift_src"]
                    v1 <<= r["shift_dst"]
                    val += v1
                p_md["value"] = val
                if mpd["type"] == "DEPEND_CONST":
                    key = mpd["dep_const"]["key_i"]
                    key += 2
                    key_val = 0
                    if key < len(d):
                        key_val = d[key]
                    key_val &= mpd["dep_const"]["key_mask"]
                    if "key_shift" in mpd["dep_const"]:
                        key_val >>= mpd["dep_const"]["key_shift"]
                    #print("DEP_META key_i:%d key_val:%d map:%s"%(key, key_val, mpd["dep_const"]["value_map"]))
                    p_md["value_name"] = ""
                    if key_val in mpd["dep_const"]["value_map"]:
                        vm = mpd["dep_const"]["value_map"][key_val]
                        if val in vm:
                            p_md["value_name"] = vm[val]
                md["meta_params"] += [p_md]
        frmt = self._default_spelling
        if "spelling_format" in cmd_data:
            frmt = cmd_data["spelling_format"]
        md["spelling"] = zmeFormatDict(frmt, md)
        return md
def convFunc(args):
    try:
        err, data = loadZWAllianceProfile(args.input)
        if err != 0:
            print("Error during conversion. ErrCode=%d"%(err))
        for p in args.patch:
            print("loading patch-file %s"%(p))
            with open(p, 'r') as fp:
                patch_data = json.load(fp)
            if patch_data != None:
                print("Apllying patch")
                data = zmePatchJSON(data, patch_data)
                print("[OK]")
        dumpJSONData(args.output, data)
        print("[DONE]")
    except Exception as ex:
        print("Exception:%s"%(ex))
        traceback.print_exc()
def addAllianceXMLConverterParser(subparsers):
    parserConv = subparsers.add_parser('convert', help="Converts Z-Wave Alliance XML to ZME JSON file.")
    parserConv.add_argument('input', help="Input XML file",  default="zwave.xml")
    parserConv.add_argument('-p',"--patch", default=[], action='append', help="JSON path file")
    parserConv.add_argument('-o','--output', help="Output JSON file.", default="zme_zwave_profile.json")
    parserConv.set_defaults(func=convFunc)

if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)-8s [%(asctime)s]  %(message)s', level=logging.DEBUG,
                    filename='%s/ZMEProg7-%s.log' % (getScriptPath(), strftime("%Y-%m-%d", gmtime())))

    def dummyFunc(args):
        print("*** Platform: %s Version: %s ***"%(platform.system(), MY_VERSION))
   
    def parseAppFunc(args):
        print("loading profile %s"%(args.profile))
        encoder = ZWaveDataEncoder(args.profile)
        d = encoder.decodeApplication(formatHexInput(args.input)) 
        print("Encoded data:%s"%(d))
    def Main():
        logging.debug("\nStarting on %s.\nARGS:%s\nVERSION:%s MD5:%s" % (
            platform.system(), ' '.join(sys.argv), MY_VERSION, "-"))
        parser = argparse.ArgumentParser(description='ZWave>ME PTI Tracer tool for 7th generation. \n Welcome :)')

        parser.set_defaults(func=dummyFunc)
        subparsers = parser.add_subparsers()

        parserConv = subparsers.add_parser('convert', help="Converts Z-Wave Alliance XML to ZME JSON file.")
        parserConv.add_argument('input', help="Input XML file",  default="zwave.xml")
        parserConv.add_argument('-p',"--patch", default=[], action='append', help="JSON path file")
        parserConv.add_argument('-o','--output', help="Output JSON file.", default="zme_zwave_profile.json")
        parserConv.set_defaults(func=convFunc)

        parserRawApp = subparsers.add_parser('parse', help="Parses raw z-wave application data.")
        parserRawApp.add_argument('-p','--profile', help="JSON profile")
        parserRawApp.add_argument('input', help="Input string")
        parserRawApp.set_defaults(func=parseAppFunc)

        args = parser.parse_args()
        args.func(args)

    Main()