#!/usr/bin/env python3

'''
CRSF client in Python. Works via TCP or UART connections.
Can be used to connect to WiFi module on Crossfire.
It can sniff broadcast frames, receive paramters, etc.
'''

# TODO: figure out why TCP doesn't work with the "menu" option

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
            param_cnt = tail[12]
            version = tail[13]
            return device_name, sn, hw_id, sw_id, param_cnt, version
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
        device_name, sn, hw_id, fw_id, param_cnt, version = frame.parse()
        s += '\n  Device: {name}, S/N=0x{sn:x} HW_ID=0x{hw_id:x}, SW_ID=0x{sw_id:x}, param count={cnt}, v={v}'.format(
                        sn=sn, name=device_name, hw_id=hw_id, sw_id=fw_id, cnt=param_cnt, v=version)
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
    pass

class CRSFDevice:
    '''Holds all the information obtained from a device'''

    def __init__(self, frame):
        self.name = 0x00
        self.sn = 0x00
        self.hwid = 0x00
        self.fwid = 0x00
        self.param_cnt = 0
        self.param_version = 0
        self.last_seen = 0
        self.origin = 0

        if frame and frame.type == CRSF.MSG_TYPE_DEVICE_INFO:
            self.name, self.sn, self.hwid, self.fwid, self.param_cnt, self.param_ver = frame.parse()
            self.origin = frame.origin
        elif frame:
            raise ValueError("frame of wrong type")

        self.menu = {}      # num -> CRSFParam

    def match(self, frame):
        if frame and frame.type == CRSF.MSG_TYPE_DEVICE_INFO:
            return frame.origin == self.origin and \
                frame.parse() == \
                (self.name, self.sn, self.hwid, self.fwid, self.param_cnt, self.param_ver)
        else:
            raise ValueError("DEVICE_INFO frame expected")

class CRSFMenu:
    
    QUIT_KEY = 'q'
    UP_KEY = 'A'
    DOWN_KEY = 'B'
    ENTER_KEY = '\n'

    PING_PERIOD_S = 5     
    IDLE_TIMEOUT_S = 60

    def __init__(self, stdscr, opts):
        # Initialize colors
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_RED)
        curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLUE)
        self.color = {
            'WHITE_BLACK': curses.color_pair(1),
            'WHITE_RED': curses.color_pair(2),
            'WHITE_BLUE': curses.color_pair(3),
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
        self.devices = {}
        self.menu_pos = 0
        self.menu_device = None
        self.displayed_devices = []

    def draw_device_menu(self):
        self.draw_title(self.menu_device.name)

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

    def draw_title(self, title):
        self.bor.addstr(0,2, "TBS Agent Python - " + title, curses.A_REVERSE)

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

    def display(self):
        # clear screen
        self.scr.clear()

        # Draw window
        self.bor.border()

        # Draw debug info
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
                except Exception as e:
                    #print("err", e)
                    break

                # Process an incoming frame
                if frame and frame.type != CRSF.MSG_TYPE_LINK_STATS:
                    if frame.type == CRSF.MSG_TYPE_PING:
                        # Send response to PING
                        resp_frame = create_device_info_frame(dest=frame.origin, orig=ORIGIN_ADDR)
                        self.conn.write_crsf(resp_frame)
                        self.last_sent = resp_frame
                    elif frame.type == CRSF.MSG_TYPE_DEVICE_INFO:
                        device = CRSFDevice(frame)
                        if frame.origin in self.devices and self.devices[frame.origin].match(frame):
                            self.devices[frame.origin].last_seen = time.time()
                        else:
                            # TODO: notify user that the device has changed?
                            device.last_seen = time.time()
                            self.devices[frame.origin] = device
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
                        break
                    else:
                        self.menu_device = None
                elif key == self.UP_KEY:
                    self.menu_pos -= 1
                elif key == self.DOWN_KEY:
                    self.menu_pos += 1
                elif key == self.ENTER_KEY:
                    if self.menu_device is None:
                        # Enter device menu
                        if 0 <= self.menu_pos < len(self.displayed_devices):
                            self.menu_device = self.displayed_devices[self.menu_pos]
                else:
                    self.last_key = key
        
            # Update screen
            self.display()

            # Regularly send out PING frame
            if time.time() - last_ping > self.PING_PERIOD_S:
                last_ping = time.time()
    
                # Send ping frame
                ping_frame = create_ping_frame()
                self.conn.write_crsf(ping_frame)
                self.last_sent = ping_frame

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
