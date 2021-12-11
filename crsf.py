#!/usr/bin/env python3

'''
CRSF client in Python. Work via TCP or UART connections.
Can be used to connect to WiFi module on Crossfire.
It can sniff broadcast frames, receive paramters, etc.
'''

import sys, time, functools
import serial, socket, queue, threading

TCP_CONNECTION = False

TCP_HOST = '192.168.4.1'
TCP_PORT = 60950                # this TCP port is used by Fusion

SERIAL_PORT = '/dev/tty.usbserial-AQ00MH7Z'
SERIAL_BAUD = 416666
# TODO: can also use WebSocket if Fusion is needed simultaneously

TICK_SPEED = 20      # Ticks per microsecond (for LOG frames)

class CRSF:

    SYNC = 0xc8

    # CRSF Device Addresses
    BROADCAST_ADDR = 0x00
    CLOUD_ADDR = 0x0E       # MQTT server
    WIFI_ADDR = 0x12
    VTX_ADDR = 0xCE
    REMOTE_ADDR = 0xEA
    RX_ADDR = 0xEC
    TX_ADDR = 0xEE

    # CRSF Frame Types
    MSG_TYPE_GPS = 0x02
    MSG_TYPE_GPST = 0x03
    MSG_TYPE_BATT = 0x08
    MSG_TYPE_VTX_TEL = 0x10
    MSG_TYPE_LINK_STATS = 0x14
    MSG_TYPE_PPM = 0x16                 # channel values
    MSG_TYPE_PPM3 = 0x17                # CRSF V3 (packed channel values)
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
print(msg_name)

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

class crsf_parser:

    def __init__(self):
        self.data = bytearray()

    def digest(self, data):
        '''Digests incoming bytes, yields complete CRSF frames'''
        self.data += bytearray(data)
        #print(len(self.data))
        while len(self.data) >= 4:
            while self.data and self.data[0] != CRSF.SYNC:
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

def crsf_log_frame(header, frame):
    '''Print CRSF frame in a partially parsed way'''
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
    elif frame.type == CRSF.MSG_TYPE_DEVICE_INFO:
        delim = frame.payload.index(0x00)
        device_name, tail = frame.payload[:delim], frame.payload[delim+5:]
        device_name = bytes(device_name).decode()
        hw_id = (tail[0] << 24) | (tail[1] << 16) | (tail[2] << 8) | tail[3]
        sw_id = (tail[4] << 24) | (tail[5] << 16) | (tail[6] << 8) | tail[7]
        param_cnt = tail[8]
        s += '\n  Device: {name}, HW_ID=0x{hw_id:x}, SW_ID=0x{sw_id:x}, param count={cnt}'.format(
                        name=device_name, hw_id=hw_id, sw_id=sw_id, cnt=param_cnt)
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
    frame = bytearray(data)
    frame[CRSF.OFFSET_LENGTH] = len(frame) - 1
    frame.append(calc_crc8(frame[2:]))
    return crsf_frame(frame)

class CRSFConnection:
    def read_crsf(self):
        pass 
    def write_crsf(self, frame):
        pass

class TCPConnection(CRSFConnection):
    '''Class for exchanging CRSF over TCP'''

    TIMEOUT_MS = 1000

    def __init__(self):
        self.parser = crsf_parser()
        self.frames = []                # incoming frames that were already parsed

        # Connect via TCP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(TCPConnection.TIMEOUT_MS)
        self.socket.connect((TCP_HOST, TCP_PORT))

    def read_crsf(self):
        # Receive data from serial
        data = None
        try:
            data = self.socket.recv(2048)
        except socket.timeout:
            sys.stderr.write('Timeout\n')
        except KeyboardInterrupt:
            print('KeyboardInterrup: Quit')
            sys.exit(0)
        except Exception as e:
            sys.stderr.write('ERROR: TCP disconnected\n')
            del self.socket
            raise(e)

        # TODO: move to super
        # Parse data
        if data and len(data):
            for frame in self.parser.digest(data):
                self.frames.append(frame)

        # Return next frame
        return self.frames.pop(0) if self.frames else None

    def write_crsf(self, frame):
        self.socket.send(frame.bytes)

class SerialConnection(CRSFConnection):
    '''Class for exchanging CRSF over UART'''

    def __init__(self):
        self.parser = crsf_parser()
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
            waiting = self.serial.in_waiting
            data = self.serial.read(waiting if waiting else 1)
            if data and len(data):
                for frame in self.parser.digest(data):
                    self.in_queue.put(frame, block=False)
            time.sleep(0.001)
        print('Exit')

    def read_crsf(self):
        try:
            frame = self.in_queue.get(block=False)
        except queue.Empty:
            frame = None
        return frame

    def write_crsf(self, frame):
        pass
        #self.serial.write(frame.bytes)

if __name__ == '__main__':

    print('Press Ctrl+C to exit')
    last_ping = last_read = 0

    # Outer loop to reconnect on disconnect
    while True:
    
        if TCP_CONNECTION:
            print('Connecting with TCP...')
            conn = TCPConnection()
        else:
            print('Connecting with UART...')
            conn = SerialConnection()
    
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
        
            # Send ping frame (need to send something periodically so that connection is not reset)
            if time.time() - last_ping > 10:
                last_ping = time.time()
    
                # Send ping frame
                frame = create_frame([CRSF.SYNC, 0, CRSF.MSG_TYPE_PING, CRSF.BROADCAST_ADDR, CRSF.CLOUD_ADDR])
                crsf_log_frame('Sending ping', frame)
                conn.write_crsf(frame)
    
                #frame = create_frame([CRSF.SYNC, 0, CRSF.MSG_TYPE_PARAM_READ, CRSF.TX_ADDR, CRSF.CLOUD_ADDR, 1, 0])
                #s.send(frame.bytes)
    
            time.sleep(0.001)