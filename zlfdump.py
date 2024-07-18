import argparse
import datetime
import platform
import common.zme_aux as zme_aux
import zme_pticlient

class ZlfDump:
	ZLF_DUMP_STATUS_OK										= 0x0
	ZLF_DUMP_STATUS_BAD_FILE								= 0x1
	ZLF_DUMP_STATUS_SMALL_SIZE								= 0x2
	ZLF_DUMP_STATUS_HEADER_CRC								= 0x3
	ZLF_DUMP_STATUS_BAD_FORMAT								= 0x4
	ZLF_DUMP_STATUS_BAD_FRAME								= 0x5
	ZLF_DUMP_STATUS_FRAME_OVERLOW							= 0x6
	ZLF_DUMP_STATUS_FRAME_SMALL								= 0x7
	ZLF_DUMP_STATUS_FRAME_BAD_DATE							= 0x8
	ZLF_DUMP_STATUS_SPEED									= 0x9
	ZLF_DUMP_STATUS_FREQ									= 0xA
	ZLF_DUMP_STATUS_CHANNEL									= 0xB
	ZLF_DUMP_STATUS_FRAME_BAD_DATE_BEAM_START				= 0xC
	ZLF_DUMP_STATUS_FRAME_BAD_DATE_BEAM_END					= 0xD
	ZLF_DUMP_STATUS_FRAME_UNKNOWN							= 0xE
	ZLF_DUMP_STATUS_FRAME_NOT_ENOUGH_DATA					= 0xF
	ZLF_DUMP_STATUS_FRAME_TYPE_UNKNOWN						= 0x10

	ZNIFFER_SOURSE_FLAG										= 0x1

	ZNF_SOZ_FRAME											= 0x21#Start of Zniffer Frame
	ZNF_SOZ_FRAME_TYPE_COMMON								= 0x1
	ZNF_SOZ_FRAME_TYPE_BEAM_START							= 0x4
	ZNF_SOZ_FRAME_TYPE_BEAM_END								= 0x5
	ZNF_SOC_FRAME											= 0x23#Start of Command Frame
	ZNF_SOZ_FRAME_STANDART									= 0x0
	ZNF_SOZ_FRAME_STANDART_BEAM_START						= 0x1
	ZNF_SOZ_FRAME_STANDART_BEAM_END							= 0x2
	ZNF_SOZ_FRAME_OTHER										= 0x3

	ZLF_HEADER_BYTE_SIZE									= 0x800
	ZLF_FRAME_SIZE											= 0xE

	ZLF_FRAME_OFFSET_COUNT									= 0x9
	ZLF_FRAME_END											= 0xFE
	ZLF_FRAME_START_OF_DATA_MARKER							= 0x21
	ZLF_FRAME_START_OF_DATA									= 0x3
	ZLF_FRAME_CHANNEL_MASK									= 0xE0
	ZLF_FRAME_CHANNEL_SHIFT									= 0x5
	ZLF_FRAME_SPEED_MASK									= 0x1F
	ZLF_FRAME_SPEED_SHIFT									= 0x0
	ZLF_FRAME_OFFSET_TIMESTAMP								= 0x0
	ZLF_FRAME_OFFSET_TIMESTAMP_SIZE							= 0x8
	ZLF_FRAME_OFFSET_DATA									= 0xD

	ZLF_TICKS_PER_MILLISECOND								= 10000
	ZLF_TICKS_PER_SECOND									= (ZLF_TICKS_PER_MILLISECOND * 1000)
	ZLF_TICKS_UNIX_EPOCH									= 621355968000000000
	ZLF_LOCAL_MASK											= 0x8000000000000000

	# Старый формат на на sdk на котором работала наша старая зуна там все свои коды регионов в новой же вариации коды используються из Raill используемые с чипом. Они частично пересекаються без конфликта а частично с ним
	# А именно lr но засчет канала это детектиться, но вот если приходит он как us то уже не можем понять что и как. Тоесть как пример IN и US_LR имеют одинаковые значения и тем самым если знифер на US_LR US то не ту способа понять
	# Вобщем их формат в текущем(новом) варианте тупо не делает различий по частоте - может еще обновят. А сейчас jp ch1 и us ch1 - формат не делает различий я про новый знифер - хоть может и pti вариант не имеет таких проблем но не факт
	# В общем будем ждать но формат в текущем виде все же инвалид 

	ZME_RADIOTOOLS_REGION_EU_STR							= "EU"
	ZME_RADIOTOOLS_REGION_US_STR							= "US"
	ZME_RADIOTOOLS_REGION_ANZ_STR							= "ANZ"
	ZME_RADIOTOOLS_REGION_HK_STR							= "HK"
	ZME_RADIOTOOLS_REGION_IN_STR							= "IN"
	ZME_RADIOTOOLS_REGION_JP_STR							= "JP"
	ZME_RADIOTOOLS_REGION_RU_STR							= "RU"
	ZME_RADIOTOOLS_REGION_IL_STR							= "IL"
	ZME_RADIOTOOLS_REGION_KR_STR							= "KR"
	ZME_RADIOTOOLS_REGION_CN_STR							= "CN"
	ZME_RADIOTOOLS_REGION_US_LR1_STR						= "US_LR1"
	ZME_RADIOTOOLS_REGION_US_LR2_STR						= "US_LR2"
	ZME_RADIOTOOLS_REGION_US_END_STR						= "US_LR_END"

	ZNIFFER_REGION_EU										= 0x00
	ZNIFFER_REGION_US										= 0x01
	ZNIFFER_REGION_ANZ										= 0x02
	ZNIFFER_REGION_HK										= 0x03
	ZNIFFER_REGION_IN										= 0x09
	ZNIFFER_REGION_IN_NEW									= 0x05
	ZNIFFER_REGION_IL										= 0x1B
	ZNIFFER_REGION_IL_NEW									= 0x06
	ZNIFFER_REGION_RU										= 0x1A
	ZNIFFER_REGION_RU_NEW									= 0x07
	ZNIFFER_REGION_CN										= 0x1D
	ZNIFFER_REGION_CN_NEW									= 0x08
	ZNIFFER_REGION_JP										= 0x0A
	ZNIFFER_REGION_JP_NEW									= 0x20
	ZNIFFER_REGION_KR										= 0x1C
	ZNIFFER_REGION_KR_NEW									= 0x21
	ZNIFFER_REGION_US_LR									= 0x09
	ZNIFFER_REGION_US_LR_BACKUP								= 0x0A
	ZNIFFER_REGION_US_LR_END_DEVICE							= 0x30

	SPEED_9600												= 0x0
	SPEED_40000												= 0x1
	SPEED_100000											= 0x2
	SPEED_100000_LR											= 0x3

	ZNIFFER_RSSI_SHIFT 										= 90.0

	REGION_MAP												=\
	{
		ZNIFFER_REGION_EU: ZME_RADIOTOOLS_REGION_EU_STR,
		ZNIFFER_REGION_US: ZME_RADIOTOOLS_REGION_US_STR,
		ZNIFFER_REGION_ANZ: ZME_RADIOTOOLS_REGION_ANZ_STR,
		ZNIFFER_REGION_HK: ZME_RADIOTOOLS_REGION_HK_STR,
		ZNIFFER_REGION_IN: ZME_RADIOTOOLS_REGION_IN_STR,
		ZNIFFER_REGION_IN_NEW: ZME_RADIOTOOLS_REGION_IN_STR,
		ZNIFFER_REGION_IL: ZME_RADIOTOOLS_REGION_IL_STR,
		ZNIFFER_REGION_IL_NEW: ZME_RADIOTOOLS_REGION_IL_STR,
		ZNIFFER_REGION_RU: ZME_RADIOTOOLS_REGION_RU_STR,
		ZNIFFER_REGION_RU_NEW: ZME_RADIOTOOLS_REGION_RU_STR,
		ZNIFFER_REGION_CN: ZME_RADIOTOOLS_REGION_CN_STR,
		ZNIFFER_REGION_CN_NEW: ZME_RADIOTOOLS_REGION_CN_STR,
		ZNIFFER_REGION_JP: ZME_RADIOTOOLS_REGION_JP_STR,
		ZNIFFER_REGION_JP_NEW: ZME_RADIOTOOLS_REGION_JP_STR,
		ZNIFFER_REGION_KR: ZME_RADIOTOOLS_REGION_KR_STR,
		ZNIFFER_REGION_KR_NEW: ZME_RADIOTOOLS_REGION_KR_STR,
		ZNIFFER_REGION_US_LR_END_DEVICE: ZME_RADIOTOOLS_REGION_US_END_STR
	}

	REGION_MAP_REVERSE											=\
	{
		ZME_RADIOTOOLS_REGION_EU_STR :ZNIFFER_REGION_EU,
		ZME_RADIOTOOLS_REGION_US_STR :ZNIFFER_REGION_US,
		ZME_RADIOTOOLS_REGION_ANZ_STR :ZNIFFER_REGION_ANZ,
		ZME_RADIOTOOLS_REGION_HK_STR :ZNIFFER_REGION_HK,
		ZME_RADIOTOOLS_REGION_IN_STR :ZNIFFER_REGION_IN,
		ZME_RADIOTOOLS_REGION_IL_STR :ZNIFFER_REGION_IL,
		ZME_RADIOTOOLS_REGION_RU_STR :ZNIFFER_REGION_RU,
		ZME_RADIOTOOLS_REGION_CN_STR :ZNIFFER_REGION_CN,
		ZME_RADIOTOOLS_REGION_JP_STR :ZNIFFER_REGION_JP,
		ZME_RADIOTOOLS_REGION_KR_STR :ZNIFFER_REGION_KR,
		ZME_RADIOTOOLS_REGION_US_LR1_STR:ZNIFFER_REGION_US_LR,
		ZME_RADIOTOOLS_REGION_US_LR2_STR:ZNIFFER_REGION_US_LR_BACKUP,
		ZME_RADIOTOOLS_REGION_US_END_STR:ZNIFFER_REGION_US_LR_END_DEVICE
	}

	SPEED_MAP												=\
	{
		SPEED_9600:9600,
		SPEED_40000:40000,
		SPEED_100000:100000,
		SPEED_100000_LR:100000
	}

	def __init__(self):
		self._file_offset = ZlfDump.ZLF_HEADER_BYTE_SIZE
		self._md_index_soz_standart = 0x0
		self._md = None
		self._new = None
		self.line_num = 0x1
		self.new()
		pass

# // 'Payload Length' value will be in bytes[9].
# // Frame length is 8 + 1 + 1 + 3 + payload_length + 1
# // T_STAMP x 8 | 0x01 | frame->count | 0x00 | 0x00 | 0x00 | frame->bytes | 0xfe
	def _getFrame(self, file_data, size):
		frame = self._frame_cache
		ts = self._ts_cache
		if frame != None:
			self._frame_cache = None
			self._ts_cache = None
			return (ZlfDump.ZLF_DUMP_STATUS_OK, ts, frame)
		while True:
			while True:
				offset = self._file_offset
				if offset == size:
					return (ZlfDump.ZLF_DUMP_STATUS_OK, None, None)
				if (offset + ZlfDump.ZLF_FRAME_SIZE) > size:
					return (ZlfDump.ZLF_DUMP_STATUS_BAD_FORMAT, None, None)
				frame_len = ((file_data[offset + ZlfDump.ZLF_FRAME_OFFSET_COUNT + 0x1] << 0x8) | file_data[offset + ZlfDump.ZLF_FRAME_OFFSET_COUNT])
				count = frame_len + ZlfDump.ZLF_FRAME_SIZE
				if (offset + count) > size:
					return (ZlfDump.ZLF_DUMP_STATUS_BAD_FORMAT, None, None)
				if file_data[offset + count - 0x1] == ZlfDump.ZLF_FRAME_END:
					break
				self._file_offset = offset + count
				pass
			self._file_offset = offset + count
			data = file_data[offset : offset + count]
			frame = data[ZlfDump.ZLF_FRAME_OFFSET_DATA : ZlfDump.ZLF_FRAME_OFFSET_DATA + frame_len]
			ts = zme_aux.zme_costruct_int(data[ZlfDump.ZLF_FRAME_OFFSET_TIMESTAMP :ZlfDump.ZLF_FRAME_OFFSET_TIMESTAMP + ZlfDump.ZLF_FRAME_OFFSET_TIMESTAMP_SIZE], ZlfDump.ZLF_FRAME_OFFSET_TIMESTAMP_SIZE, True)
			return (ZlfDump.ZLF_DUMP_STATUS_OK, ts, frame)
		pass
	def _getStructSoc(self, file_data, size, frame, ts):
		frame_len = len(frame)
		while frame_len < 0x3:
			status, ts, data = self._getFrame(file_data, size)
			if status != ZlfDump.ZLF_DUMP_STATUS_OK:
				return (status, None)
			if data == None:
				return (ZlfDump.ZLF_DUMP_STATUS_FRAME_NOT_ENOUGH_DATA, None)
			frame = frame + data
			frame_len = len(frame)
			pass
		frame_len_must = 0x3 + frame[0x2]
		if frame_len > frame_len_must:
			return (ZlfDump.ZLF_DUMP_STATUS_FRAME_OVERLOW, None)
		while frame_len < frame_len_must:
			status, ts, data = self._getFrame(file_data, size)
			if status != ZlfDump.ZLF_DUMP_STATUS_OK:
				return (status, None)
			if data == None:
				return (ZlfDump.ZLF_DUMP_STATUS_FRAME_NOT_ENOUGH_DATA, None)
			frame = frame + data
			frame_len = len(frame)
			pass
		if frame_len != frame_len_must:
			return (ZlfDump.ZLF_DUMP_STATUS_FRAME_SMALL, None)
		seconds = ((ts & ~ ZlfDump.ZLF_LOCAL_MASK) - ZlfDump.ZLF_TICKS_UNIX_EPOCH) / ZlfDump.ZLF_TICKS_PER_SECOND
		md = {"type_frame": ZlfDump.ZNF_SOC_FRAME}
		md["ts"] = seconds
		md["raw"] = frame
		return (ZlfDump.ZLF_DUMP_STATUS_OK, md)
	def _getStructSoz(self, file_data, size, frame, ts):
		frame_len = len(frame)
		while frame_len < 0x2:
			status, ts, data = self._getFrame(file_data, size)
			if status != ZlfDump.ZLF_DUMP_STATUS_OK:
				return (status, None)
			if data == None:
				return (ZlfDump.ZLF_DUMP_STATUS_FRAME_NOT_ENOUGH_DATA, None)
			frame = frame + data
			frame_len = len(frame)
			pass
		frame_type = frame[0x1]
		if frame_type == ZlfDump.ZNF_SOZ_FRAME_TYPE_BEAM_START:
			frame_len_must = 0xA
			while frame_len < frame_len_must:
				status, ts, data = self._getFrame(file_data, size)
				if status != ZlfDump.ZLF_DUMP_STATUS_OK:
					return (status, None)
				if data == None:
					return (ZlfDump.ZLF_DUMP_STATUS_FRAME_NOT_ENOUGH_DATA, None)
				frame = frame + data
				frame_len = len(frame)
				pass
			if frame[0x9] != 0x0:
				frame_len_must = frame_len_must + 0x1
			while frame_len < frame_len_must:
				status, ts, data = self._getFrame(file_data, size)
				if status != ZlfDump.ZLF_DUMP_STATUS_OK:
					return (status, None)
				if data == None:
					return (ZlfDump.ZLF_DUMP_STATUS_FRAME_NOT_ENOUGH_DATA, None)
				frame = frame + data
				frame_len = len(frame)
				pass
			if frame_len > frame_len_must:
				self._frame_cache = frame[frame_len_must: frame_len_must + (frame_len - frame_len_must)]
				self._ts_cache = ts
				frame = frame[0x0:frame_len_must]
				pass
			seconds = ((ts & ~ ZlfDump.ZLF_LOCAL_MASK) - ZlfDump.ZLF_TICKS_UNIX_EPOCH) / ZlfDump.ZLF_TICKS_PER_SECOND
			md = {"type_frame": ZlfDump.ZNF_SOZ_FRAME}
			md["ts"] = seconds
			md["raw"] = frame
			md["type_frame_sub"] = ZlfDump.ZNF_SOZ_FRAME_STANDART_BEAM_START
			return (ZlfDump.ZLF_DUMP_STATUS_OK, md)
		elif frame_type == ZlfDump.ZNF_SOZ_FRAME_TYPE_BEAM_END:
			frame_len_must = 0x7
			while frame_len < frame_len_must:
				status, ts, data = self._getFrame(file_data, size)
				if status != ZlfDump.ZLF_DUMP_STATUS_OK:
					return (status, None)
				if data == None:
					return (ZlfDump.ZLF_DUMP_STATUS_FRAME_NOT_ENOUGH_DATA, None)
				frame = frame + data
				frame_len = len(frame)
				pass
			if frame_len > frame_len_must:
				self._frame_cache = frame[frame_len_must: frame_len_must + (frame_len - frame_len_must)]
				self._ts_cache = ts
				frame = frame[0x0:frame_len_must]
				pass
			seconds = ((ts & ~ ZlfDump.ZLF_LOCAL_MASK) - ZlfDump.ZLF_TICKS_UNIX_EPOCH) / ZlfDump.ZLF_TICKS_PER_SECOND
			md = {"type_frame": ZlfDump.ZNF_SOZ_FRAME}
			md["ts"] = seconds
			md["raw"] = frame
			md["type_frame_sub"] = ZlfDump.ZNF_SOZ_FRAME_STANDART_BEAM_END
			return (ZlfDump.ZLF_DUMP_STATUS_OK, md)
		elif frame_type == ZlfDump.ZNF_SOZ_FRAME_TYPE_COMMON:
			while frame_len < 0xA:
				status, ts, data = self._getFrame(file_data, size)
				if status != ZlfDump.ZLF_DUMP_STATUS_OK:
					return (status, None)
				if data == None:
					return (ZlfDump.ZLF_DUMP_STATUS_FRAME_NOT_ENOUGH_DATA, None)
				frame = frame + data
				frame_len = len(frame)
				pass
			if frame[0x7] != ZlfDump.ZLF_FRAME_START_OF_DATA_MARKER:
				return (ZlfDump.ZLF_DUMP_STATUS_FRAME_BAD_DATE, None)
			if frame[0x8] != ZlfDump.ZLF_FRAME_START_OF_DATA:
				return (ZlfDump.ZLF_DUMP_STATUS_FRAME_UNKNOWN, None)
			frame_len_must = 0xA + frame[0x9]
			while frame_len < frame_len_must:
				status, ts, data = self._getFrame(file_data, size)
				if status != ZlfDump.ZLF_DUMP_STATUS_OK:
					return (status, None)
				if data == None:
					return (ZlfDump.ZLF_DUMP_STATUS_FRAME_NOT_ENOUGH_DATA, None)
				frame = frame + data
				frame_len = len(frame)
				pass
			if frame_len > frame_len_must:
				self._frame_cache = frame[frame_len_must: frame_len_must + (frame_len - frame_len_must)]
				self._ts_cache = ts
				frame = frame[0x0:frame_len_must]
				pass
			seconds = ((ts & ~ ZlfDump.ZLF_LOCAL_MASK) - ZlfDump.ZLF_TICKS_UNIX_EPOCH) / ZlfDump.ZLF_TICKS_PER_SECOND
			md = {"type_frame": ZlfDump.ZNF_SOZ_FRAME}
			md["ts"] = seconds
			md["raw"] = frame #zme_aux.zmeFixByteArray(frame)
			#zme_aux.zmeFixByteArray(md["raw"])
			md["type_frame_sub"] = ZlfDump.ZNF_SOZ_FRAME_STANDART
			return (ZlfDump.ZLF_DUMP_STATUS_OK, md)
		return (ZlfDump.ZLF_DUMP_STATUS_FRAME_BAD_DATE, None)

	def _getStruct(self, file_data, size):
		status, ts, frame = self._getFrame(file_data, size)
		if status != ZlfDump.ZLF_DUMP_STATUS_OK:
			return (status, None)
		if frame == None:
			return (status, None)
		type_frame = frame[0x0]
		if type_frame == ZlfDump.ZNF_SOZ_FRAME:
			status, md = self._getStructSoz(file_data, size, frame, ts)
			return (status, md)
		elif type_frame == ZlfDump.ZNF_SOC_FRAME:
			status, md = self._getStructSoc(file_data, size, frame, ts)
			return (status, md)
		return (ZlfDump.ZLF_DUMP_STATUS_FRAME_TYPE_UNKNOWN, None)

	def begin(self, file_name):
		self._file_offset = ZlfDump.ZLF_HEADER_BYTE_SIZE
		self._md_index_soz_standart = 0x0
		self._md = None
		try:
			fd = open(file_name, "rb")
			file_data = fd.read()
			fd.close()
			pass
		except:
			return (ZlfDump.ZLF_DUMP_STATUS_BAD_FILE)
			pass
		if len(file_data) < ZlfDump.ZLF_HEADER_BYTE_SIZE:
			return (ZlfDump.ZLF_DUMP_STATUS_SMALL_SIZE)
		crc16 = zme_aux.calcSigmaCRC16(0x1D0F, file_data, 0x0, ZlfDump.ZLF_HEADER_BYTE_SIZE - 0x2)
		if zme_aux.zme_costruct_int(file_data[ZlfDump.ZLF_HEADER_BYTE_SIZE - 0x2 : ZlfDump.ZLF_HEADER_BYTE_SIZE], 0x2, True) != crc16:
			return (ZlfDump.ZLF_DUMP_STATUS_HEADER_CRC)
		size = len(file_data)
		md = []
		while True:
			# if self.line_num == 5570:
			# 	pass
			status, data = self._getStruct(file_data, size)
			if status == ZlfDump.ZLF_DUMP_STATUS_BAD_FORMAT:
				return (status)
			if status != ZlfDump.ZLF_DUMP_STATUS_OK:
				continue
			if data == None:
				break
			md = md + [data]
			# if data["type_frame"] == 33:
			# 	print("Line: %5d"%(self.line_num), end="")
			# 	print(" dump: ", end="")
			# 	print(zme_aux.splitHexBuff(data["raw"], len(data["raw"]) * 2 + len(data["raw"])))
			# 	self.line_num = self.line_num + 0x1
			# 	pass
			pass
		self._md = md
		return (ZlfDump.ZLF_DUMP_STATUS_OK)


    # // Process Zniffer Frames.
    # //
    # // Zniffer Frame:
    # //
    # //  ------------------------------- START OF FRAME
    # //  |  ---------------------------- FRAME TYPE
    # //  |  |  ------------------------- TIMESTAMP
    # //  |  |  |     ------------------- CHANNEL (upper 3 bits) / SPEED (lower 5 bits - 0x00 == 9.6kbps; 0x01 == 40kbps; 0x02 == 100kbps)
    # //  |  |  |     |  ---------------- FREQUENCY
    # //  |  |  |     |  |  ------------- RSSI
    # //  |  |  |     |  |  |  ---------- START OF DATA MARKER
    # //  |  |  |     |  |  |  |  ------- START OF DATA
    # //  |  |  |     |  |  |  |  |  ---- LENGTH (of remaining bytes)
    # //  |  |  |     |  |  |  |  |  |
    # //  v  v  v--v  v  v  v  v  v  v
    # // <21 01 c0 32 02 00 43 21 03 0e ec bf 8b 3d 19 41 06 0e 07 32 01 20 40 ca>
    # //
	def nextSozStandart(self):
		md = self._md
		if md == None:
			return (None)
		index = self._md_index_soz_standart
		index_max = len(md)
		if index >= index_max:
			return (None)
		while index < index_max:
			if md[index]["type_frame"] == ZlfDump.ZNF_SOZ_FRAME:
				type_frame_sub = md[index]["type_frame_sub"]
				if type_frame_sub == ZlfDump.ZNF_SOZ_FRAME_STANDART or type_frame_sub == ZlfDump.ZNF_SOZ_FRAME_STANDART_BEAM_START:
					self._md_index_soz_standart = index + 0x1
					md = md[index]
					raw = md["raw"]
					out = {"ts": md["ts"]}
					out["rssi"] = zme_pticlient.ZWPKGParser._convert1ByteFloat(raw[0x6], 1.0)-ZlfDump.ZNIFFER_RSSI_SHIFT
					out["channeli"] = (raw[0x4] & ZlfDump.ZLF_FRAME_CHANNEL_MASK) >> ZlfDump.ZLF_FRAME_CHANNEL_SHIFT
					speed = (raw[0x4] & ZlfDump.ZLF_FRAME_SPEED_MASK) >> ZlfDump.ZLF_FRAME_SPEED_SHIFT
					if speed in ZlfDump.SPEED_MAP:
						speed = ZlfDump.SPEED_MAP[speed]
					else:
						speed = 0x0
					out["speed"] = speed
					if type_frame_sub == ZlfDump.ZNF_SOZ_FRAME_STANDART:
						out["raw"] = raw[0xA: len(raw)]
					elif type_frame_sub == ZlfDump.ZNF_SOZ_FRAME_STANDART_BEAM_START:
						out["raw"] = raw[0x7: len(raw)]
					out["length"] = len(out["raw"])
					freqi = raw[0x5]
					if out["channeli"] == 0x3 and freqi == ZlfDump.ZNIFFER_REGION_US_LR:
						freq = ZlfDump.ZME_RADIOTOOLS_REGION_US_LR1_STR
					elif out["channeli"] == 0x3 and freqi == ZlfDump.ZNIFFER_REGION_US_LR_BACKUP:
						freq = ZlfDump.ZME_RADIOTOOLS_REGION_US_LR2_STR
					elif freqi in ZlfDump.REGION_MAP:
						freq = ZlfDump.REGION_MAP[freqi]
					else:
						freq = "UNKN"
					out["freq"] = freq
					if type_frame_sub == ZlfDump.ZNF_SOZ_FRAME_STANDART_BEAM_START:
						self._beam_start_freq = out["freq"]
						self._beam_start_speed = out["speed"]
						self._beam_start_channeli = out["channeli"]
						pass
					return (out)
				if type_frame_sub == ZlfDump.ZNF_SOZ_FRAME_STANDART_BEAM_END:
					self._md_index_soz_standart = index + 0x1
					md = md[index]
					raw = md["raw"]
					out = {"raw": raw[0x5: len(raw)]}
					out["ts"] = md["ts"]
					out["rssi"] = zme_pticlient.ZWPKGParser._convert1ByteFloat(raw[0x4], 1.0)-ZlfDump.ZNIFFER_RSSI_SHIFT
					out["freq"] = self._beam_start_freq
					out["speed"] = self._beam_start_speed
					out["channeli"] = self._beam_start_channeli
					out["length"] = len(out["raw"])
					self._beam_start_freq = "UNKN"
					self._beam_start_speed = 40000
					self._beam_start_channeli = 0x0
					return (out)
			index = index + 0x1
			pass
		self._md_index_soz_standart = index_max
		return (None)

	def new(self):
		new = bytearray([0x0] * ZlfDump.ZLF_HEADER_BYTE_SIZE)
		new[0x0] = 0x68#Что бы навернека пусть ласт версия как у них 
		crc16 = zme_aux.calcSigmaCRC16(0x1D0F, new, 0x0, ZlfDump.ZLF_HEADER_BYTE_SIZE - 0x2)
		new[ZlfDump.ZLF_HEADER_BYTE_SIZE - 0x2] = crc16 & 0xFF
		new[ZlfDump.ZLF_HEADER_BYTE_SIZE - 0x1] = crc16 >> 0x8
		self._new = new
		self._frame_cache = None
		self._ts_cache = None
		self._beam_start_freq = "UNKN"
		self._beam_start_speed = 40000
		self._beam_start_channeli = 0x1
		pass

	def save(self, file_name):
		try:
			fd = open(file_name, "wb")
			fd.write(self._new)
			fd.close()
			pass
		except:
			return (ZlfDump.ZLF_DUMP_STATUS_BAD_FILE)
		return (ZlfDump.ZLF_DUMP_STATUS_OK)

	def add(self, md):
		freq = md["freq"]
		if freq in ZlfDump.REGION_MAP_REVERSE:
			freq = ZlfDump.REGION_MAP_REVERSE[freq]
		else:
			return (ZlfDump.ZLF_DUMP_STATUS_FREQ)
		ch = (md["channeli"] << ZlfDump.ZLF_FRAME_CHANNEL_SHIFT) & ZlfDump.ZLF_FRAME_CHANNEL_MASK
		if ch != (md["channeli"] << ZlfDump.ZLF_FRAME_CHANNEL_SHIFT):
			return (ZlfDump.ZLF_DUMP_STATUS_CHANNEL)
		speed = md["speed"]
		if speed == 9600:
			speed = ZlfDump.SPEED_9600
		elif speed == 40000:
			speed = ZlfDump.SPEED_40000
		elif speed == 100000:
			if md["channeli"] == 0x3:
				speed = ZlfDump.SPEED_100000_LR
			else:
				speed = ZlfDump.SPEED_100000
			pass
		else:
			return (ZlfDump.ZLF_DUMP_STATUS_SPEED)
		speed = (speed << ZlfDump.ZLF_FRAME_SPEED_SHIFT) & ZlfDump.ZLF_FRAME_SPEED_MASK
		ts = md["ts"] * ZlfDump.ZLF_TICKS_PER_SECOND + ZlfDump.ZLF_TICKS_UNIX_EPOCH
		ts = int(ts) | ZlfDump.ZLF_LOCAL_MASK
		ts = zme_aux.zme_int_toarr(ts, 8, True)
		payload = bytearray(md["raw"])
		# В Zniffer ТОЛЬКО положительный RSSI - смещаем относительно номального уровня
		rssi = int(md["rssi"] + ZlfDump.ZNIFFER_RSSI_SHIFT) & 0xFF
		if payload[0x0] == 0x55:
			struct = bytearray([ZlfDump.ZLF_FRAME_START_OF_DATA_MARKER, ZlfDump.ZNF_SOZ_FRAME_TYPE_BEAM_START, 0x0, 0x0, (ch | speed), freq, rssi]) + payload
			pass
		elif payload[0x0] == 0x0:
			struct = bytearray([ZlfDump.ZLF_FRAME_START_OF_DATA_MARKER, ZlfDump.ZNF_SOZ_FRAME_TYPE_BEAM_END, 0x0, 0x0, rssi]) + payload
			pass
		else:
			struct = bytearray([ZlfDump.ZLF_FRAME_START_OF_DATA_MARKER, ZlfDump.ZNF_SOZ_FRAME_TYPE_COMMON, 0x0, 0x0, (ch | speed), freq, rssi, ZlfDump.ZLF_FRAME_START_OF_DATA_MARKER, ZlfDump.ZLF_FRAME_START_OF_DATA, len(payload)]) + payload
			pass
		frame = ts + bytearray([ZlfDump.ZNIFFER_SOURSE_FLAG, len(struct), 0x0, 0x0, 0x0]) + struct + bytearray([ZlfDump.ZLF_FRAME_END])
		self._new = self._new + frame
		return (ZlfDump.ZLF_DUMP_STATUS_OK)

	def add_multi(self, md):
		for i in range(len(md)):
			status = self.add(md[i])
			if status != ZlfDump.ZLF_DUMP_STATUS_OK:
				return (status)
		return (ZlfDump.ZLF_DUMP_STATUS_OK)

def traceFunc(args):
	zlf_dump = ZlfDump()
	status = zlf_dump.begin(args.input)
	if status != (ZlfDump.ZLF_DUMP_STATUS_OK):
		print("begin bad 0x%x"%(status))
		return (1)
	zlf_dump.new()#Первый раз можно делать - только потом что бы новый начать с нуля
	array_md = []
	line_num =0x1
	while True:
		md = zlf_dump.nextSozStandart()
		if md == None:
			break
		array_md = array_md + [md]
		# zlf_dump.add(md) #одиночный
		ms = md["ts"] - int(md["ts"])
		dt_text = datetime.datetime.fromtimestamp(md["ts"]).strftime("%H:%M:%S"+".%03d"%(ms*1000))
		print("Line: %5d"%(line_num), end="")
		print(" Date %s"%(dt_text), end="")
		print(" Region %s"%(md["freq"]), end="")
		print(" Speed %5.1fkbps"%(md["speed"]/1000.0), end="")
		print(" RSSI %4.0fdBm"%(md["rssi"]), end="")
		print(" Channel %d"%(md["channeli"]), end="")
		print(" RAW", end="")
		print(zme_aux.splitHexBuff(md["raw"], len(md["raw"]) * 2 + len(md["raw"])))
		line_num = line_num + 0x1
		pass
	zlf_dump.add_multi(array_md)
	zlf_dump.save(args.input + ".zlf")
	return (0)

if __name__ == "__main__":
	def dummyFunc(args):
		print("*** Platform: %s Version: %s ***"%(platform.system(), "MY_VERSION"))
		
	def Main():
		parser = argparse.ArgumentParser(description='ZWave>ME PTI Tracer tool for 7th generation. \n Welcome :)')

		parser.set_defaults(func=dummyFunc)
		subparsers = parser.add_subparsers()

		parserTracer = subparsers.add_parser('trace', help="Trace packages.")
		parserTracer.add_argument('-i', '--input', help="Uses JSON file instead of real PTI-device. Prints packages")
		parserTracer.set_defaults(func=traceFunc)

		args = parser.parse_args()
		args.func(args)

	Main()