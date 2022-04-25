#!/usr/bin/env python3

'''
CRSF client in Python. Works via TCP or UART connections.
Can be used to connect to WiFi module on Crossfire.
It can sniff broadcast frames, receive paramters, etc.
'''

# TODO: figure out why TCP doesn't work with the "menu" option
# TODO: implement commands
# TODO: implement selection
# TODO: implement string input
# TODO: implement numeric input

import sys, time, functools, os, curses
import serial, socket, queue, threading

TCP_HOST = '192.168.4.1'
TCP_PORT = 60950                # this TCP port is used by Fusion

ORIGIN_ADDR = "CRSF.FC_ADDR"

SERIAL_PORT = '/dev/tty.usbserial-AQ00MH7Z'
SERIAL_BAUD = 416666
# TODO: can also use WebSocket if Fusion is needed simultaneously

TICK_SPEED = 20      # Ticks per microsecond (for LOG frames)

SHORT_HIST_SIZE = 451   # 90 s
HIST_SIZE = 10*SHORT_HIST_SIZE

# Text coloring logic
GREEN, RED = 2, 160     # colors
fg = lambda text, color: "\33[38;5;" + str(color) + "m" + text + "\33[0m"
bg = lambda text, color: "\33[48;5;" + str(color) + "m" + text + "\33[0m"

class CRSF:

    SYNC = 0xc8

    # CRSF Device Addresses
    BROADCAST_ADDR = 0x00
    CLOUD_ADDR = 0x0E       # MQTT server
    WIFI_ADDR = 0x12
    REMOTE_ADDR = 0xEA
    RX_ADDR = 0xEC
    TX_ADDR = 0xEE
    FC_ADDR = 0xC8          # flight controller
    VTX_ADDR = 0xCE

    # CRSF Frame Types
    MSG_TYPE_GPS = 0x02
    MSG_TYPE_GPST = 0x03
    MSG_TYPE_BATT = 0x08
    MSG_TYPE_VTX_TEL = 0x10
    MSG_TYPE_LINK_STATS = 0x14
    MSG_TYPE_PPM = 0x16                 # channel values
    MSG_TYPE_PPM3 = 0x17                # CRSF V3 (packed channel values)
    MSG_TYPE_LINK_STATS_RX = 0x1C       # CRSF V3
    MSG_TYPE_LINK_STATS_TX = 0x1D       # CRSF V3
    MSG_TYPE_ATTD = 0x1E
    MSG_TYPE_MADD = 0x1F
    MSG_TYPE_PING = 0x28
    MSG_TYPE_DEVICE_INFO = 0x29
    MSG_TYPE_PARAM_ENTRY = 0x2B
    MSG_TYPE_PARAM_READ = 0x2C
    MSG_TYPE_PARAM_WRITE = 0x2D
    MSG_TYPE_CMD = 0x32
    MSG_TYPE_LOG = 0x34
    MSG_TYPE_REMOTE = 0x3A              # Remote-related frames
    MSG_TYPE_MAVLINK_ENV = 0xAA

    # CRSF menu parameter types
    PARAM_TYPE_UINT8 = 0
    PARAM_TYPE_INT8 = 1
    PARAM_TYPE_UINT16 = 2
    PARAM_TYPE_INT16 = 3
    PARAM_TYPE_UINT32 = 4
    PARAM_TYPE_INT32 = 5
    PARAM_TYPE_FLOAT  = 8
    PARAM_TYPE_TEXT_SELECTION = 9
    PARAM_TYPE_STRING = 10
    PARAM_TYPE_FOLDER = 11
    PARAM_TYPE_INFO = 12
    PARAM_TYPE_COMMAND = 13
    PARAM_TYPE_OUT_OF_RANGE = 127

    # CRSF frame structure (field offsets)
    OFFSET_LENGTH = 1
    OFFSET_MSG_TYPE = 2

# Message type -> human readable name
msg_name = {}
for name in CRSF.__dict__:
    if name.startswith('MSG_TYPE_'):
        msg_name[CRSF.__dict__[name]] = name[9:]
#print(msg_name)        # show known message types
ORIGIN_ADDR = eval(ORIGIN_ADDR)

# Device address -> human readable name
dev_name = {}
for name in CRSF.__dict__:
    if name.endswith('_ADDR'):
        dev_name[CRSF.__dict__[name]] = name[:-5]

class crsf_crc8:

    RESET_VALUE = 0x00
    POLYNOM_1 = 0xD5            # CRC8 DVB-S2 (polynomial used for validating CRSF frames)
    POLYNOM_2 = 0xBA            # custom polynomial used for validating CRSF commands
    MSB_SET = 0x80
    FINISH_VALUE = 0x00

    def __init__(self, poly = None):
        self.val = self.RESET_VALUE
        self.poly = poly if poly is not None else self.POLYNOM_1

    def _calc(self, byte):
        for i in range(8):
            msb_flag = self.val & self.MSB_SET
            self.val <<= 1
            if byte & self.MSB_SET:
                self.val += 1
            byte <<= 1
            if msb_flag:
                self.val ^= self.poly
        self.val &= 0xFF

    def digest(self, data):
        for x in data:
            self._calc(x)

    def finish(self):
        self._calc(self.FINISH_VALUE)
        return self.val

def calc_crc8(data):
    '''Calculate CRC8 as in CRSF frames'''
    crc = crsf_crc8(poly = crsf_crc8.POLYNOM_1)
    crc.digest(data)
    return crc.finish()

class crsf_frame:
    def __init__(self, data):
        self.data = bytes(data)

    @property
    def len(self):
        return self.data[1] + 2

    @property
    def type(self):
        return self.data[2]

    @property
    def bytes(self):
        return self.data

    @property
    def is_extended(self):
        '''Extended CRSF frames include their ORIGIN and DESTINATION'''
        return self.type >= 0x28 and self.type <= 0x96 or self.type == CRSF.MSG_TYPE_MAVLINK_ENV

    @property
    def origin(self):
        return self.data[4] if self.is_extended else None

    @property
    def destination(self):
        return self.data[3] if self.is_extended else None

    @property
    def payload(self):
        return self.data[5 if self.is_extended else 3:-1]

    def parse(self):
        if self.type == CRSF.MSG_TYPE_DEVICE_INFO: 
            delim = self.payload.index(0x00)
            device_name, tail = self.payload[:delim], self.payload[delim+1:]
            device_name = bytes(device_name).decode()
            sn = (tail[0] << 24) | (tail[1] << 16) | (tail[2] << 8) | tail[3]
            hw_id = (tail[4] << 24) | (tail[5] << 16) | (tail[6] << 8) | tail[7]
            sw_id = (tail[8] << 24) | (tail[9] << 16) | (tail[10] << 8) | tail[11]
            param_count = tail[12]
            version = tail[13]
            return device_name, sn, hw_id, sw_id, param_count, version
        else:
            raise ValueError("cannot parse frame of type 0x%02x" % self.type)

    def __str__(self):
        s  = 'SYNC ' if self.bytes[0] == CRSF.SYNC else ('%02x ' % self.bytes[0])
        s += 'L=%d ' % self.len
        s += ('(%s) ' % msg_name[self.type]) if self.type in msg_name else ('(t=%02x) ' % self.type)
        i = 3
        if self.is_extended:
            s += '%s->%s ' % (dev_name.get(self.bytes[i+1], '%02x' % self.bytes[i+1]),
                              dev_name.get(self.bytes[i  ], '%02x' % self.bytes[i  ]))
            i += 2
        s += ' '.join(map(lambda x: "%02x" % x, self.bytes[i:]))
        return s

class crsf_parser:

    def __init__(self, silent):
        self.data = bytearray()
        self.silent = silent

    def digest(self, data):
        '''Digests incoming bytes, yields complete CRSF frames'''
        self.data += bytearray(data)
        #print(len(self.data))
        while len(self.data) >= 4:
            while self.data and self.data[0] != CRSF.SYNC:
                if not self.silent:
                    sys.stderr.write("byte %02x discarded\n" % self.data[0])
                self.data = self.data[1:]
            if len(self.data) > 1:
                frame_len = self.data[1] + 2
                if len(self.data) >= frame_len:
                    crc_byte = self.data[frame_len - 1]
                    calc_crc = calc_crc8(self.data[2:frame_len - 1])
                    if crc_byte == calc_crc:
                        frame, self.data = self.data[:frame_len], self.data[frame_len:]
                        yield crsf_frame(frame)
                    else:
                        if not self.silent:
                            sys.stderr.write("crc mismatch; byte discarded\n")
                        self.data = self.data[1:]
                else:
                    break
            else:
                break

def log_data(header, data):
    print(str(header) + ':', ''.join(map(lambda x: " %02x" % x, data)))

def rle_decode(data):
    '''Decode Run-Length Encoded number'''
    off = 0
    res = 0
    ch = 0x80
    while (ch & 0x80) and off < 6:
        ch = data[off]
        tmp = ch & 0x7F
        res |= (tmp << (7*off))
        off += 1
    
    return (res, off)

def msg_decode(data):
    '''Decode debug message for XLOG frame type'''
    if (data[0] & 0x80) == 0:
        msg = (bytes([data[0] & 0x7F]).decode(), 1)
    else:
        i = data.find(0)
        data = bytearray(data)
        data[0] &= 0x7F
        msg = (bytes(data[:i]).decode(), i+1)
    return msg

bin_byte = lambda x: '{:08b}'.format(x)
ticks_to_us = lambda x: (x - 992)*5//8 + 1500

def ppm_channels_decode(data):
    data = ''.join(map(bin_byte, reversed(data)))
    assert(len(data) % 11 == 0)
    ticks = [int(data[x:x+11], 2) for x in range(len(data)-11, 0, -11)]
    return list(map(ticks_to_us, ticks))

up_lqi_history, down_lqi_history = [], []
def link_stats_decode(data):
    global up_lqi_history, down_lqi_history
    cur_time = time.time()
    up_lqi_history.append((cur_time, data[2]))
    down_lqi_history.append((cur_time, data[8]))
    up_lqi_history = up_lqi_history[-HIST_SIZE:]
    down_lqi_history = down_lqi_history[-HIST_SIZE:]
    s = 'Uplink: RSSI={}/{}'.format(-data[0], -data[1])
    s += ', LQI={:3d}%, SNR={}, Ant.={}'.format(data[2], data[3], data[4])
    s += ', RFmode={}, RFpwr={}'.format(data[5], data[6])
    s += '; Downlink: RSSI={}, LQI={:3d}%, SNR={}'.format(-data[7], data[8], data[9])

    # Show average LQI (both uplink and downlink)
    if len(up_lqi_history) > 1 and len(down_lqi_history) > 1:
        def get_hist_lqi(lqi_hist):
            avg = sum([x[1] for x in lqi_hist])/len(lqi_hist)
            return '{}/{:.1f}'.format(
                fg('100', GREEN) if avg == 100 else fg('{:.2f}'.format(avg), RED),
                (lqi_hist[-1][0] - lqi_hist[0][0])
            )
        short_up = get_hist_lqi(up_lqi_history[-SHORT_HIST_SIZE:])
        long_up = get_hist_lqi(up_lqi_history[-HIST_SIZE:])
        short_down = get_hist_lqi(down_lqi_history[-SHORT_HIST_SIZE:])
        long_down = get_hist_lqi(down_lqi_history[-HIST_SIZE:])
        s += '\n    History: Uplink LQI={}, {}; Downlink LQI={}, {}'.format(short_up, long_up, short_down, long_down)
    return s 

ppm_times = []
last_time = 0
def crsf_log_frame(header, frame):
    '''Print CRSF frame in a partially parsed way'''

    global last_time, ppm_times
    s = str(header) + ': '
    data = frame.bytes
    s += 'SYNC ' if data[0] == CRSF.SYNC else ('%02x ' % data[0])
    s += 'L=%d ' % frame.len
    s += ('(%s) ' % msg_name[frame.type]) if frame.type in msg_name else ('(t=%02x) ' % frame.type)
    i = 3
    if frame.is_extended:
        s += '%s->%s ' % (dev_name.get(data[i+1], '%02x' % data[i+1]),
                         dev_name.get(data[i  ], '%02x' % data[i  ]))
        i += 2
    s += ' '.join(map(lambda x: "%02x" % x, data[i:]))

    # Parse certain kinds of frames
    if frame.type == CRSF.MSG_TYPE_PPM:
        channels = ppm_channels_decode(frame.payload)
        s += '\n  CH1..16: ' + ', '.join(map(str, channels))
        curr = time.time()*1000
        ppm_times = [curr] + ppm_times
        ppm_times = ppm_times[:500]
        s += ' {:.2f} {:.2f}'.format(curr - last_time, 
                                            (ppm_times[0] - ppm_times[-1])/len(ppm_times))
        last_time = curr
    elif frame.type == CRSF.MSG_TYPE_PPM3:
        s += '\n  CRSFv3'
    elif frame.type == CRSF.MSG_TYPE_LINK_STATS:
        s += '\n    ' + link_stats_decode(frame.payload)
    elif frame.type == CRSF.MSG_TYPE_DEVICE_INFO:
        device_name, sn, hw_id, fw_id, param_count, version = frame.parse()
        s += '\n  Device: {name}, S/N=0x{sn:x} HW_ID=0x{hw_id:x}, SW_ID=0x{sw_id:x}, param count={cnt}, v={v}'.format(
                        sn=sn, name=device_name, hw_id=hw_id, sw_id=fw_id, cnt=param_count, v=version)
    elif frame.type == CRSF.MSG_TYPE_PARAM_ENTRY:
        if data[i+3] == CRSF.PARAM_TYPE_INFO:
            name = data[i+4:]
            delim = name.index(0x00)
            name, val = name[:delim], data[i+4+delim+1:]
            val = val[:val.index(0x00)]
            name = bytes(name).decode()
            val = bytes(val).decode()
            s += '\n  ' + name + ': ' + val
    elif frame.type == CRSF.MSG_TYPE_LOG:
        tm = functools.reduce(lambda v,e: v*256 + e, (data[5:9]))
        val = ''
        if data[-2] == 0:
            val = data[9:-2].decode()
        else:
            val = ' '.join(map(lambda x: "%02x" % x, data[9:-1]))
        s += '\n  {ticks} ({ms} ms): {val}'.format(ticks=tm, ms=tm//(TICK_SPEED*1000), val=val)
        
    print(s)

def create_frame(data):
    '''Takes CRSF frame data, sets correct length byte and adds CRC8 byte'''
    frame = bytearray([CRSF.SYNC, 0]) + bytearray(data)
    frame[CRSF.OFFSET_LENGTH] = len(frame) - 1
    frame.append(calc_crc8(frame[2:]))
    return crsf_frame(frame)
                
def create_ping_frame(dest=CRSF.BROADCAST_ADDR, orig=ORIGIN_ADDR):
    '''Create broadcast PING frame from bytes'''
    return create_frame([
        CRSF.MSG_TYPE_PING,         # type
        dest,                       # destination
        orig                        # origin
    ])

def create_param_read_frame(dest, param_num, chunk, orig=ORIGIN_ADDR):
    return create_frame([
        CRSF.MSG_TYPE_PARAM_READ,   # type
        dest,                       # destination
        orig,                       # origin
        param_num,
        chunk
    ])

def create_device_info_frame(dest=CRSF.BROADCAST_ADDR, orig=ORIGIN_ADDR):
    '''Return "fake" device information about Agent Python'''
    name = "Agent Python"
    return create_frame([
        CRSF.MSG_TYPE_DEVICE_INFO,  # type
        dest,                       # destination
        orig,                       # origin
        # Payload
    ] + list(name.encode()) + [     # name of entity
        0x00,                       # NUL to terminate string
        0x12, 0x34, 0x56, 0x78,     # S/N
        0x01, 0x23, 0x45, 0x02,     # HW ID
        0x00, 0x00, 0x11, 0x11,     # FW ID
        0x00,                       # parameter total
        0x01                        # parameter version number
    ])
    

class CRSFConnection:
    def read_crsf(self):
        pass 
    def write_crsf(self, frame):
        pass

class TCPConnection(CRSFConnection):
    '''Class for exchanging CRSF over TCP'''

    TCP_TIMEOUT_MS = 1000
    TCP_RECV = 2048

    def __init__(self, silent):
        self.parser = crsf_parser(silent)
        self.frames = []                # incoming frames that were already parsed
        self.silent = silent

        # Connect via TCP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(TCPConnection.TCP_TIMEOUT_MS)
        self.socket.connect((TCP_HOST, TCP_PORT))

    def read_crsf(self):
        # Receive data from serial
        data = None
        try:
            data = self.socket.recv(TCPConnection.TCP_RECV)
        except socket.timeout:
            if not self.silent:
                sys.stderr.write('Timeout\n')
        except KeyboardInterrupt:
            if not self.silent:
                print('KeyboardInterrup: Quit')
            sys.exit(0)
        except Exception as e:
            if not self.silent:
                sys.stderr.write('ERROR: TCP disconnected\n')
            del self.socket
            raise(e)

        # TODO: move to super
        # Parse data
        if data and len(data):
            #print(len(data))
            for frame in self.parser.digest(data):
                self.frames.append(frame)

        # Return next frame
        return self.frames.pop(0) if self.frames else None

    def write_crsf(self, frame):
        self.socket.send(frame.bytes)

class SerialConnection(CRSFConnection):
    '''Class for exchanging CRSF over UART'''

    SERIAL_SLEEP = 0.001

    def __init__(self, silent):
        self.parser = crsf_parser(silent)
        self.serial = serial.Serial(SERIAL_PORT, baudrate=SERIAL_BAUD)
        self.in_queue = queue.Queue()

        # Receiving thread
        self.thread = threading.Thread(target=self.read_thread)
        self.thread.setDaemon(1)
        self.alive = threading.Event()
        self.alive.set()
        self.thread.start()

    def read_thread(self):
        '''Separate thread for receiving frames asynchronously'''
        while self.alive.isSet():
            # How many bytes are in waiting?
            waiting = self.serial.in_waiting
            data = self.serial.read(waiting if waiting else 1)
            if data and len(data):
                for frame in self.parser.digest(data):
                    self.in_queue.put(frame, block=False)
            time.sleep(SerialConnection.SERIAL_SLEEP)
        print('Exit')

    def read_crsf(self):
        try:
            frame = self.in_queue.get(block=False)
        except queue.Empty:
            frame = None
        return frame

    def write_crsf(self, frame):
        self.serial.write(frame.bytes)

def parse_args():
    '''Parse command line arguments'''
    import argparse, pathlib
    arg_parse = argparse.ArgumentParser()
    arg_parse.add_argument('--tcp', action = 'store_true',
                         help = 'use TCP connection instead of UART' )
    arg_parse.add_argument('--menu', action = 'store_true',
                         help = 'CRSF menu mode (otherwise - logs mode)' )
    opts = arg_parse.parse_args()
    return opts

def get_crsf_connection(use_tcp, silent):
    if not silent:
        print('Connecting with {}...'.format('TCP' if use_tcp else 'UART'))
    if use_tcp:
        return TCPConnection(silent)
    else:
        return SerialConnection(silent)

def log_mode(use_tcp):
    print('Press Ctrl+C to exit')
    last_ping = last_read = 0

    # Outer loop to reconnect on disconnect
    while True:
    
        conn = get_crsf_connection(use_tcp, False)
    
        # Update state machine
    
        while True:
            try:
                frame = conn.read_crsf()
            except Exception as e:
                print("err", e)
                break
        
            # Display data
            if frame:
                crsf_log_frame('Received', frame)

                # Process frame
                if frame.type == CRSF.MSG_TYPE_PING:
                    resp_frame = create_device_info_frame(dest=frame.origin, orig=ORIGIN_ADDR)
                    conn.write_crsf(resp_frame)
        
            # Send ping frame (need to send something periodically so that connection is not reset)
            if time.time() - last_ping > 10:
                last_ping = time.time()
    
                # Send ping frame
                frame = create_ping_frame()
                crsf_log_frame('Sending ping', frame)
                conn.write_crsf(frame)
    
                #frame = create_frame([CRSF.MSG_TYPE_PARAM_READ, CRSF.TX_ADDR, CRSF.CLOUD_ADDR, 1, 0])
                #s.send(frame.bytes)
    
            time.sleep(0.0001)

class CRSFParam:
    '''
    CRSF parameters are, basically, key-value pairs.
    "Key" is the name of the parameter. "Value" is modifiable by user
    (except for INFO type, for which the value is constant).
    '''
    
    # Parameter types determine the type of the value
    TEXT_SELECTION_TYPE = 0x09      # value is uint8_t, with a list of options
    STRING_TYPE = 0x0a              # value is a string, entered by user directly
    FOLDER_TYPE = 0x0b              # no modifiable value; groups other parameters
    INFO_TYPE = 0x0c                # value is constant, CANNOT be modified
    COMMAND_TYPE = 0x0d
    
    # Numeric types (in practice, rarely used)
    UINT8_TYPE = 0
    INT8_TYPE = 1
    UINT16_TYPE = 2
    INT16_TYPE = 3
    UINT32_TYPE = 4
    INT32_TYPE = 5
    FLOAT_TYPE = 8

    def __init__(self, param_num, debug_cb=None):
        # TODO: track if parameter is changing frequently or always stable
        # TODO: poll stable parameters less often
        # TODO: ensure that different chunks are from short time frame
        # TODO: detect changes in chunks, invalidate parameter if some chunk changed
        self.obtained_time = 0      # when was this parameter last refreshed?
        self.num = param_num
        self.parent_folder = None
        self.total_chunks = 0
        self.type = None
        self.name = '...'
        self.chunks = []            # CRSF frames, a list of all chunks
        self.children = None        # children (only for a FOLDER_TYPE)
        self.value = None           # except for FOLDER_TYPE
        self.hidden = False
        self.min = self.default = self.max = None
        self.options = []           # only for TEXT_SELECTION

        self.debug_cb = debug_cb
        self.created_time = time.time()

    def is_folder(self):
        return self.type == self.FOLDER_TYPE

    def is_info(self):
        return self.type == self.INFO_TYPE

    def is_selection(self):
        return self.type == self.TEXT_SELECTION_TYPE

    def is_command(self):
        return self.type == self.COMMAND_TYPE

    def is_number_input(self):
        return self.type in [self.FLOAT_TYPE,
                              self.UINT8_TYPE,  self.INT8_TYPE,
                             self.UINT16_TYPE, self.INT16_TYPE,
                             self.UINT32_TYPE, self.INT32_TYPE]

    def create_param_read_frame(self, origin):
        if self.chunks:
            # Determine if any chunks are missing or need updating
            if None in self.chunks:
                chunk = self.chunks.index(None)
            else:
                self.debug("error 5")
                return None
        else:
            chunk = 0
        frame = create_param_read_frame(origin, self.num, chunk)
        return frame

    def debug(self, txt):
        if self.debug_cb:
            self.debug_cb(txt)

    def process_frame(self, frame):
        '''Parse parameter information frame'''
        if frame.type != CRSF.MSG_TYPE_PARAM_ENTRY:
            self.debug('invalid frame type')
            return
        payload = frame.payload
        param_num, chunks_remain = payload[:2]

        # Handle chunking
        if chunks_remain:
            # More chunks expected.
            if not self.chunks:
                # Assumption! Received first chunk
                self.chunks = [None]*(chunks_remain + 1)
                self.total_chunks = chunks_remain + 1
            self.chunks[-chunks_remain - 1] = frame.payload
            return
        elif self.chunks:
            # Last chunk received. Reassemble payload from chunks.
            self.chunks[-1] = frame.payload
            if None not in self.chunks and \
               list(reversed([x[1] for x in self.chunks])) == list(range(len(self.chunks))) and \
               len([1 for x in self.chunks if x[0] == self.num]) == len(self.chunks):
                payload = self.chunks[0][:2]
                for x in self.chunks:
                    payload += x[2:]
            else:
                self.debug("error: chunks error")
                return
            self.chunks = []
        else:
            # Trivial case: no chunking.
            # CRSF frame contains the parameter entry entirely.
            pass

        parent_folder, data_type = payload[2:4]
        hidden, data_type = data_type & 0x80, data_type & 0x7F
        try:
            nul = 4 + payload[4:].index(0x00)
            name = bytes(payload[4:nul]).decode()
        except:
            # Invalid frame?
            self.debug('frame error: ' + str(frame))
            return

        # Type-specific value
        if data_type == self.FOLDER_TYPE:
            try:
                end = nul + 1 + payload[nul+1:].index(0xFF)
                children = list(payload[nul+1:end])
            except:
                self.debug('frame error 2: ' + str(frame))
                return

            # Folder frame parsed successfully
            if chunks_remain == 0:
                self.children = children
                self.parent_folder = parent_folder
                self.type = data_type
                self.name = name
                self.hidden = hidden
                self.debug("folder %d OK" % param_num)
                self.obtained_time = time.time()
            else:
                self.debug("error: folder %d: multichunk folders not supported" % param_num)
                return
        elif data_type == self.COMMAND_TYPE:
            if chunks_remain == 0:
                self.parent_folder = parent_folder
                self.type = data_type
                self.name = name
                self.hidden = hidden
                self.debug("command %d OK" % param_num)
                self.obtained_time = time.time()
            else:
                self.debug("error: folder %d: multichunk folders not supported" % param_num)
                return
        elif data_type == self.INFO_TYPE:
            try:
                end = nul + 1 + payload[nul+1:].index(0x00)
                value = bytes(payload[nul+1:end]).decode()
            except:
                self.debug('frame error 4: ' + str(frame))
                return
            if chunks_remain == 0:
                self.parent_folder = parent_folder
                self.type = data_type
                self.name = name
                self.hidden = hidden
                self.value = value
                self.debug("info %d OK" % param_num)
                self.obtained_time = time.time()
            else:
                self.debug("error: folder %d: multichunk folders not supported" % param_num)
                return
        elif data_type == self.TEXT_SELECTION_TYPE:
            try:
                end = nul + 1 + payload[nul+1:].index(0x00)
                options = bytes(payload[nul+1:end]).decode()
                options = options.split(';')
            except:
                self.debug('frame error 6: ' + str(frame))
                return
            value, val_min, val_max, val_def = payload[end+1:end+5]
            # TODO: unit
            if chunks_remain == 0:
                self.parent_folder = parent_folder
                self.type = data_type
                self.name = name
                self.hidden = hidden
                self.value = value
                self.options = options
                self.min = val_min
                self.default = val_def
                self.max = val_max
                self.debug("selection %d OK" % (val_max + 1))
                self.obtained_time = time.time()
            else:
                self.debug("error: folder %d: multichunk folders not supported" % param_num)
                return
        else:
            self.debug("error: data_type %d" % data_type)
            self.type = data_type
            if chunks_remain == 0:
                self.obtained_time = time.time()

class CRSFDevice:
    '''Holds all the information obtained from a device'''

    POLL_PERIOD_S = 2.0
    POLL_RESPONSE_SPEED_UP_FACTOR = 0.95
    FOLDER_PERIOD_S = 10
    PARAM_TIMEOUT_S = 120

    class InvalidType(ValueError):
        pass

    def __init__(self, frame, menu_ui, debug_cb=None):
        self.origin = 0                 # network address of this device
        self.last_seen = 0              # when was the last time "device information" was obtained from the device?
        self.last_read_time = 0         # when was the last time "param read" was sent to the device?
        self.last_read_frame = 0

        # Parsed from "device information" frame
        self.name = 0x00
        self.sn = 0x00
        self.hwid = 0x00
        self.fwid = 0x00
        self.param_count = 0
        self.param_version = 0

        if frame and frame.type == CRSF.MSG_TYPE_DEVICE_INFO:
            self.name, self.sn, self.hwid, self.fwid, self.param_count, self.param_ver = frame.parse()
            self.origin = frame.origin
        elif frame:
            raise ValueError("frame of wrong type")

        # List of CRSFParam objects, first object - root folder
        self.menu = [None]*(self.param_count + 1)

        self.menu_ui = menu_ui
        self.debug_cb = debug_cb

    def debug(self, txt):
        if self.debug_cb:
            self.debug_cb(txt)

    def match(self, frame):
        '''Compare device information of this device to "device information" frame'''
        if frame and frame.type == CRSF.MSG_TYPE_DEVICE_INFO:
            return frame.origin == self.origin and \
                frame.parse() == \
                (self.name, self.sn, self.hwid, self.fwid, self.param_count, self.param_ver)
        else:
            raise ValueError("DEVICE_INFO frame expected")

    def poll_params(self, conn, folder):
        '''Periodically send out "param read" frames for the parameters in current folder'''
        if not (0 <= folder < len(self.menu)):
            self.debug('invalid folder %s' % str(folder))
            return
        if time.time() - self.last_read_time < self.POLL_PERIOD_S:
            return
        self.last_read_time = time.time()
    
        if self.menu[folder] is None:
            self.menu[folder] = CRSFParam(folder, debug_cb=self.debug_cb)
        elif self.menu[folder].obtained_time and not self.menu[folder].is_folder():
            raise CRSFDevice.InvalidType('folder type expected')

        # Decide which parameter to load
        frame = None
        if not self.menu[folder].obtained_time or time.time() - self.menu[folder].obtained_time > self.FOLDER_PERIOD_S:
            # Load the current folder itself
            frame = self.menu[folder].create_param_read_frame(self.origin)
        elif self.menu[folder].obtained_time:
            oldest_time, oldest_child = None, None
            for child in self.menu[folder].children:
                if self.menu[child] is None or not self.menu[child].obtained_time and \
                   time.time() - self.menu[child].created_time > self.PARAM_TIMEOUT_S:
                    # Create or recreate parameter to start obtaining it from beginning
                    self.menu[child] = CRSFParam(child, debug_cb=self.debug_cb)
                    frame = self.menu[child].create_param_read_frame(self.origin)
                    break
                elif None in self.menu[child].chunks:
                    frame = self.menu[child].create_param_read_frame(self.origin)
                    break
                elif oldest_time is None or time.time() - self.menu[child].obtained_time > oldest_time:
                    oldest_time = time.time() - self.menu[child].obtained_time
                    oldest_child = child
            if frame is None and oldest_child is not None:
                frame = self.menu[oldest_child].create_param_read_frame(self.origin)
            # TODO: determine the parameter in the current folder which was not updated in the longest time

        if frame:
            # TODO: replace this with two callbacks: menu_id.write_crsf and menu_ui.debug
            self.menu_ui.write_crsf(frame)
            self.last_read_frame = frame.payload[0]

    def process_frame(self, frame):
        '''Process frame from this device'''
        if frame.type == CRSF.MSG_TYPE_PARAM_ENTRY:
            # TODO: process "param entry" frame
            param_num = frame.payload[0]
            if self.last_read_frame == param_num:
                self.last_read_time -= self.POLL_PERIOD_S * self.POLL_RESPONSE_SPEED_UP_FACTOR
            if 0 <= param_num < len(self.menu):
                if isinstance(self.menu[param_num], CRSFParam):
                    self.menu[param_num].process_frame(frame)
            else:
                # TODO: report error: unexpected parameter number
                pass

class CRSFMenu:
    
    QUIT_KEY = 'q'
    UP_KEY = 'A'
    DOWN_KEY = 'B'
    ENTER_KEY = '\n'

    PING_PERIOD_S = 5     
    ONLINE_THRES_S = 30
    IDLE_TIMEOUT_S = 60

    CAPTURE_LOGS = False

    def __init__(self, stdscr, opts):
        # Initialize colors
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_RED)
        curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_WHITE)
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(6, curses.COLOR_CYAN, curses.COLOR_BLACK)
        self.color = {
            'WHITE_BLACK': curses.color_pair(1),
            'WHITE_RED': curses.color_pair(2),
            'WHITE_BLUE': curses.color_pair(3),
            'GREEN_WHITE': curses.color_pair(4),
            'MAGENTA_BLACK': curses.color_pair(5),
            'CYAN_BLACK': curses.color_pair(6),
        }

        self.scr = stdscr
        self.bor = self.scr.subwin(curses.LINES, curses.COLS , 0, 0)
        self.win = self.scr.subwin(curses.LINES-2, curses.COLS-2, 1, 1)
        self.win.nodelay(True)

        # Input events
        self.last_key = ''
        self.last_frame = None
        self.last_sent = None

        # Open a connection for CRSF
        self.conn = get_crsf_connection(opts.tcp, True)

        # Device addr (1-byte number) to CRSFDevice
        # - Common state
        self.debug_txt = None
        self.devices = {}                   # devices which are currently online
        self.menu_pos = 0                   # position in the current menu
        self.menu_pos_stack = []            # history of menu positions

        # - State for the top menu (list of devices)
        self.displayed_devices = []         # devices currently shown in the menu (if not inside a device menu)

        # - State for the device menus
        self.menu_device = None             # currently selected device
        self.menu_folder = 0                # currently selected folder of a device
        self.displayed_params = []          # parameters currently show in the menu (if inside a device menu)

        if self.CAPTURE_LOGS:
            self.log_file = open('log_file.txt','w')

    def debug(self, txt):
        if txt:
            self.debug_txt = txt
            if self.CAPTURE_LOGS:
                self.log_file.write(txt+'\n')

    def write_crsf(self, frame):
        self.conn.write_crsf(frame)
        self.last_sent = frame
        if self.CAPTURE_LOGS:
            self.log_file.write('< ' + str(frame) + '\n')

    def draw_title(self, title, flags=None):
        sup_title = "TBS Agent Python - "
        self.bor.addstr(0,2, sup_title, curses.A_REVERSE)
        self.bor.addstr(0,len(sup_title)+2, title, flags if flags else curses.A_REVERSE)

    def draw_device_info(self, device):
        # TODO: show device information (S/N, HW ID, FW ID, last DEVICE INFO, number of parameters, etc.)
        seen_ago = time.time() - device.last_seen
        flags = self.color['GREEN_WHITE'] if seen_ago <= self.ONLINE_THRES_S else None
 
    def draw_device_menu(self):
        device = self.menu_device
        self.draw_title(device.name)

        # Special case: device with no parameters
        if device.param_count == 0:
            self.bor.addstr(1,2, "This device has no parameters")
            return

        # Check for correctness
        if not (0 <= self.menu_folder < len(device.menu)) or \
           not device.menu[self.menu_folder] or \
           not device.menu[self.menu_folder].is_folder():
            self.menu_folder = 0
        if not device.menu[self.menu_folder] or not device.menu[self.menu_folder].is_folder():
            self.debug("invalid folder {}".format(self.menu_folder))
            return
        folder = device.menu[self.menu_folder]

        # Update internal state
        if self.menu_pos >= len(folder.children):
            self.menu_pos = 0
        elif self.menu_pos < 0: 
            self.menu_pos = len(folder.children) - 1

        # Draw navigation bar
        # TODO: show entire navigation path
        if folder:
            self.bor.addstr(1,1, folder.name + ' >') 

        # Draw folder contents
        # Special case: empty folder
        self.displayed_params = []
        if not folder.children:
            self.bor.addstr(2,2, "This folder is empty")
        for cnt, child in enumerate(folder.children):
            self.bor.move(2+cnt,2)
            sel_color = ((self.color['WHITE_BLUE'] | curses.A_BOLD) if cnt == self.menu_pos else self.color['WHITE_BLACK'])
            key = device.menu[child].name if device.menu[child] and device.menu[child].name else '...'
            if device.menu[child] and not device.menu[child].is_selection():
                self.bor.addstr(key, sel_color)
            else:
                self.bor.addstr(key)
            if device.menu[child]:
                if device.menu[child].is_folder():
                    self.bor.addstr(' >')
                elif device.menu[child].is_info() or device.menu[child].is_selection():
                    if key[-1] != ':':
                        self.bor.addstr(':')
                        key += ':'
                    WIDTH = 17
                    if len(key) < WIDTH:
                        self.bor.addstr(' '*(WIDTH-len(key)))
                    if device.menu[child].is_info():
                        self.bor.addstr(' ' + device.menu[child].value)
                    elif device.menu[child].is_selection():
                        self.bor.addstr(' ')
                        self.bor.addstr('<', sel_color)
                        if device.menu[child].options and \
                           0 <= device.menu[child].value < len(device.menu[child].options): 
                            val = device.menu[child].options[device.menu[child].value]
                        else:
                            val = str(device.menu[child].value)
                        self.bor.addstr(val, sel_color)
                        self.bor.addstr('>', sel_color)
                if device.menu[child].hidden:
                    self.bor.addstr(' (hidden)', self.color['CYAN_BLACK'])
            self.displayed_params.append(device.menu[child])

    def draw_device_list(self):
        '''Encapsulates menu drawing logic'''
        self.draw_title("CRSF Devices")
        self.displayed_devices = []

        # Special case: no devices
        if not self.devices:
            self.bor.addstr(1,2, "No devices found")
            return

        # Items to be displayed
        items = sorted(self.devices.items())

        # Update internal state
        if self.menu_pos >= len(items):
            self.menu_pos = 0
        elif self.menu_pos < 0: 
            self.menu_pos = len(items) - 1
        self.displayed_devices = [x[1] for x in items]

        # Display all devices
        for cnt, addr_device in enumerate(items):
            addr, device = addr_device
            self.bor.move(1 + cnt, 1)
            self.bor.addstr(device.name, self.color['WHITE_BLUE'] if cnt == self.menu_pos else self.color['WHITE_BLACK'])
            self.bor.addstr(' ({:.0f}s)'.format(time.time() - device.last_seen))

    def draw_menu(self):
        '''Encapsulates menu drawing logic'''

        # Remove devices not seen for a long time
        for addr, device in self.devices.items():
            if time.time() - device.last_seen >= self.IDLE_TIMEOUT_S:
                del(self.devices[addr])

        # Check if the current device is still in the list
        if self.menu_device:
            if not [x for x in self.devices if self.devices[x] == self.menu_device]:
                self.menu_device = None

        if self.menu_device:
            self.draw_device_menu()
        else:
            self.draw_device_list()

    def draw_debug(self, info):
        self.bor.addstr(curses.LINES - 5,1, str(info))

    def display(self):
        # clear screen
        self.scr.clear()

        # Draw window
        self.bor.border()

        # Draw debug info
        if self.debug_txt is not None:
            self.draw_debug('Debug: ' + self.debug_txt)
        self.bor.addstr(curses.LINES - 4,1, self.last_key)
        if self.last_frame:
            self.bor.addstr(curses.LINES - 3,1, str(self.last_frame))
        if self.last_sent:
            self.bor.addstr(curses.LINES - 2,1, str(self.last_sent))

        self.draw_menu()
        self.bor.move(curses.LINES - 1, curses.COLS - 1)

        self.bor.refresh()

    def run(self):
        last_ping = 0 
        while True:
            # Process all incoming CRSF frames
            while True:
                frame = None
                try:
                    frame = self.conn.read_crsf()
                    if frame and self.CAPTURE_LOGS:
                        self.log_file.write('> ' + str(frame) + '\n')
                except Exception as e:
                    #print("err", e)
                    break

                # Process an incoming frame
                if frame and frame.type != CRSF.MSG_TYPE_LINK_STATS:
                    if frame.type == CRSF.MSG_TYPE_PING:
                        # Send response to PING
                        resp_frame = create_device_info_frame(dest=frame.origin, orig=ORIGIN_ADDR)
                        self.write_crsf(resp_frame)
                    elif frame.type == CRSF.MSG_TYPE_DEVICE_INFO:
                        device = CRSFDevice(frame, self, self.debug)
                        if frame.origin in self.devices and self.devices[frame.origin].match(frame):
                            self.devices[frame.origin].last_seen = time.time()
                        else:
                            # TODO: notify user that the device has changed?
                            device.last_seen = time.time()
                            self.devices[frame.origin] = device
                    elif frame.type == CRSF.MSG_TYPE_PARAM_ENTRY:
                        if frame.origin in self.devices:
                            self.devices[frame.origin].process_frame(frame)
                        else:
                            pass # TODO: display error: received parameter from unseen/unrequested device
                    # For debug output
                    self.last_frame = frame
                else:
                    break

            # Process keyboard input (if any)
            try:
                key = self.win.getkey()
            except:
                key = None

            if key is not None:
                if key == self.QUIT_KEY:
                    if self.menu_device is None:
                        if self.CAPTURE_LOGS:
                            self.log_file.close()
                        break
                    else:
                        self.menu_pos = self.menu_pos_stack.pop()
                        if not self.menu_pos_stack:
                            # Go to the top menu - the device list
                            self.menu_device = None
                        else:
                            # Go to the parent folder
                            self.menu_folder = self.menu_device.menu[self.menu_folder].parent_folder
                elif key == self.UP_KEY:
                    self.menu_pos -= 1
                elif key == self.DOWN_KEY:
                    self.menu_pos += 1
                elif key == self.ENTER_KEY:
                    if self.menu_device is None:
                        # Enter device menu
                        if 0 <= self.menu_pos < len(self.displayed_devices):
                            self.menu_device = self.displayed_devices[self.menu_pos]
                            self.menu_folder = 0
                            self.menu_pos_stack.append(self.menu_pos)
                            self.menu_pos = 0
                    else:
                        if 0 <= self.menu_pos < len(self.displayed_params):
                            if self.displayed_params[self.menu_pos].is_folder():
                                # Change folder in the device
                                self.menu_folder = self.displayed_params[self.menu_pos].num
                                self.menu_pos_stack.append(self.menu_pos)
                                self.menu_pos = 0
                            else:
                                pass # TODO: execute command?
                        else:
                            self.debug("error: menu_pos")
                else:
                    self.debug("unknown key pressed: " + str(key) + '/' + repr(key))
                    self.last_key = key
        
            # Update screen
            self.display()

            # Regularly send out READ frames to selected device
            if self.menu_device:
                try:
                    self.menu_device.poll_params(self.conn, self.menu_folder)
                except CRSFDevice.InvalidType as e:
                    self.debug(str(e))
                    self.menu_device = None

            # Regularly send out PING frame
            if time.time() - last_ping > self.PING_PERIOD_S:
                last_ping = time.time()
    
                # Send ping frame
                ping_frame = create_ping_frame()
                self.write_crsf(ping_frame)

            # Throttle if there is no user input
            if key is None:
                time.sleep(0.01)

def crsf_menu_mode(stdscr, opts):
    man = CRSFMenu(stdscr, opts)
    man.run()

if __name__ == '__main__':
    basename = os.path.basename(sys.argv[0])
    print('TBS Agent Python ({})\n--------------------------'.format(basename))

    opts = parse_args()
    if opts.menu:
        curses.wrapper(crsf_menu_mode, opts)
    else:
        log_mode(opts.tcp)
