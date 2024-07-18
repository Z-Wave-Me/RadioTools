#!/usr/bin/python
# -*- coding: utf-8 -*-
from common.zme_aux import *
MY_VERSION = "0.1b1"

class ZMEDeviceSn:
    FORMAT_HEXSTR = 0
    FORMAT_BYTEARR = 1
    def __init__(self, raw, format = FORMAT_BYTEARR):
        self._raw_data = raw
        self._md = {}
        # 00 00 01 15 FF 09 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A6 06 B4 43 1D E0 B4 63 1D E0 B4 63 D8 A6 11 1C
        self._md["parent_uuid"] = zme_costruct_int(raw[:8],8)
        self._md["time_stamp"] = zme_costruct_int(raw[8:8+4],4)
        self._md["sequence"] = zme_costruct_int(raw[12:12+3],3)
        self._md["crc8"] = raw[15]
        crc_check = Checksum(raw[:15])
        self._md["is_valid"] = (self._md["crc8"] == crc_check)
    def toText(self):
        text = ""
        text += "\t\tPRG. UUID: \t%016x"%(self._md["parent_uuid"])
        ts = datetime.datetime.fromtimestamp(float(self._md["time_stamp"])).strftime("%Y-%m-%dT%H:%M:%S")
        text += "\n\t\tTIMESATMP: \t%s"%(ts)
        text += "\n\t\tSEQUENCE: \t%06d"%(self._md["sequence"])
        text += "\n\t\tCRC8: \t\t%02x"%(self._md["crc8"])
        if self._md["is_valid"]:
            text += "\n\t\tVALID: \t\tYES"
        else:
            text += "\n\t\tVALID: \t\tNO"
        return text
    def getMetadata(self):
        return self._md 