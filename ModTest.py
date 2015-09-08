'''
Created on 2015-7-29
dased on plcscan
@author: qmwang
'''
from struct import pack, unpack
import socket
import struct
import sys

from optparse import OptionGroup, OptionParser
import string
from scapy.utils import hexdump
import time

__FILTER = "".join([' '] + [' ' if chr(x) not in string.printable or chr(x) in string.whitespace else chr(x) for x in range(1,256)])

def StringPrintable(msg):
    return msg.translate(__FILTER)

def status(msg):
    sys.stderr.write(msg[:-1][:39].ljust(39,' ')+msg[-1:])

def get_ip_list(mask):
    try:
        net_addr,mask = mask.split('/')
        mask = int(mask)
        start, = struct.unpack('!L', socket.inet_aton(net_addr))
        start &= 0xFFFFFFFF << (32-mask)
        end = start | ( 0xFFFFFFFF >> mask )
        return [socket.inet_ntoa(struct.pack('!L', addr)) for addr in range(start+1, end)]
    except (struct.error,socket.error):
        return []

def scan(argv):
    parser = OptionParser(
                          usage = "usage: %prog [options] [ip]...",
                          description = "Scan IP range for PLC devices, Support MODBUS and..."
                          )
    parser.add_option("--host-list", dest="hosts_file", help="Scan hosts from file", metavar = "FILE")
    parser.add_option("--ports", dest="ports", help="Scan ports", metavar = "PORTS", default = 502)
    parser.add_option("--timeout", dest="connect_timeout", help="Connection timeout (seconds)", metavar="TIMEOUT", type="float", default=1)
    AddModOptions(parser) #for modbus protocol

    (options, args) = parser.parse_args(argv)

    scan_hosts = []
    if options.hosts_file:
        try:
            scan_hosts = [file.strip() for file in open(options.hosts_file, 'r')]
        except IOError:
            print "Can't open file %s" % options.hosts_file

    for ip in args:
        scan_hosts.extend(get_ip_list(ip) if '/' in ip else [ip])

    scan_ports = options.ports

    if not scan_hosts:
        print "No targets to scan\n\n"
        parser.print_help()
        exit()

    status("Scan start...\n")
    for host in scan_hosts:
        splitted = host.split(':')
        host = splitted[0]
        if len(splitted)==2:
            ports = [int(splitted[1])]
        else:
            ports = scan_ports

        port = ports
        status("%s:%d...\r" % (host, port))
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(options.connect_timeout)
            sock.connect((host,port))
            sock.close()
        except socket.error:
            continue

        if port == 502:
            res = ModScan(host, port, options)
        else:
            print "port not support"
            exit()

        if not res:
            print "%s:%d unknown protocol" % (host, port)


    status("Scan complete\n")


def AddModOptions(parser):
    group = OptionGroup(parser, "Modbus Tester")
    group.add_option("--brute-uid", action="store_true", help="Brute units ID", default=False)
    group.add_option("--modbus-uid", help="Use uids from list", type="string", metavar="UID")
    group.add_option("-f","--modbus-function", help="Use modbus function NOM for discover units", type="int", metavar="NOM")
    group.add_option("-d","--modbus-data", help="Use data for for modbus function", default="", metavar="DATA")
    group.add_option("--modbus-timeout", help="Timeout for modbus protocol (seconds)", default=8, type="float", metavar="TIMEOUT")
    group.add_option("-z", "--func-fuzzing", help="Modbus FunctionCode Fuzzing", default=False, action="store_true")
    group.add_option("-v", "--debug", help="Debug-verbose mode", default=False, action="store_true")
    group.add_option("-i", "--device-info-scan", help="Scan Schneider PLC for more device information", default= False, action="store_true")
    parser.add_option_group(group)

class ModbusProtocolError(Exception):
    def __init__(self, message, packet=''):
        self.message = message
        self.packet = packet
    def __str__(self):
        return "[Error][ModbusProtocol] %s" % self.message

class ModbusError(Exception):
    _errors = {
              0:    "No reply",
              1:    "Illegal Function",
              2:    "Illegal Data Address",
              3:    "Illegal Data Value",
              4:    "Slave Device Failure",
              5:    "Acknowledge",
              6:    "Slave Device Busy",
              7:    "Memory Parity Error",
              0x0A: "Gataway Path Unavailable",
              0x0B: "Gataway Target Device Failed To Respond"
              }
    def __init__(self,  code):
        self.code = code
        self.message = ModbusError._errors[code] if ModbusError._errors.has_key(code) else 'Unknown Error'
    def __str__(self):
        return "[Error][Modbus][%d] %s" % (self.code, self.message)

class ModbusPacket:
    def __init__(self, transactionId=0, unitId=0, functionId=0, data=''):
        self.transactionId = transactionId
        self.unitId = unitId
        self.functionId = functionId
        self.data = data

    def pack(self):
        return pack('!HHHBB',
            self.transactionId,          # transaction id
            0,                           # protocol identifier (reserved 0)
            len(self.data)+2,            # remaining length
            self.unitId,                 # unit id
            self.functionId              # function id
        ) + self.data                    # data

    def unpack(self,packet):
        if len(packet)<8:
            raise ModbusProtocolError('Response too short', packet)

        self.transactionId, self.protocolId, length, self.unitId, self.functionId = unpack('!HHHBB',packet[:8])
        if len(packet) < 6+length:
            raise ModbusProtocolError('Response too short', packet)

        self.data = packet[8:]

        return self

class Modbus:
    def __init__(self, ip, port=502, uid=0, timeout=8):
        self.ip = ip
        self.port = port
        self.uid = uid
        self.timeout = timeout

    def Request(self, functionId, data=''):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        sock.connect((self.ip,self.port))

        sock.send(ModbusPacket(0, self.uid, functionId, data).pack())

        if debug_mode:
            print "\n------------------send package:"
            print hexdump(ModbusPacket(0, self.uid, functionId, data).pack())

        reply = sock.recv(1024)

        if debug_mode:
            print "\n------------------recv package:"
            print hexdump(reply)

        if not reply:
            raise ModbusError(0)

        response = ModbusPacket().unpack(reply)

        if response.unitId != self.uid:
            raise ModbusProtocolError('Unexpected unit ID or incorrect packet', reply)

        if response.functionId != functionId:
            raise ModbusError(ord(response.data[0]))

        return response.data

    def DeviceInfo(self):

        if func_fuzzing:
            #readDeviceId = bytearray([0x01, 0x02, 0x03, 0x04])
            #objectId = bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            for rd in range(4,4+1):
                for ob in range(0x80,0xff+1):
#                     res = self.Request(0x2b, bytes(bytearray(0x0e, str(rd), str(o))))
#                     if res and len(res)>5:
#                         objectCount = ord(res[5])
#                         data = res[6:]
#                         info = ''
#                         for i in range(0, objectCount):
#                             info += data[2:2+ord(data[1])]
#                             info += ' '
#                             data = data[2+ord(data[1]):]
#                             return info
#                         else:
#                             raise ModbusProtocolError('Packet format (reply for device info) wrong', res)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((self.ip, self.port))
                    senddata = bytes(bytearray([0x00,0x00,0x00,0x00,0x00,0x05,0x00,0x2b,0x0e,rd,ob]))
                    print "+++++++++++++++++send"
                    print hexdump(senddata)
                    sock.send(senddata)
                    recv = sock.recv(1024)
                    print "+++++++++++++++++recv"
                    print hexdump(recv)

                    time.sleep(1)

                    if not recv:
                        raise ModbusError(0)

                    resp = ModbusPacket().unpack(recv)

                    if resp.unitId != self.uid:
                        print 'recv.unitId != self.uid'

                    if resp.functionId != 43:
                        print 'recv.functionId != 43'
                        if resp.functionId == 171:
                            print 'Read Device Identification Error, error code:%r' % resp.data[0]
            exit()

        elif di_scan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.ip, self.port))
            senddata = bytes(bytearray([0x00, 0x0f, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x5a, 0x00, 0x20, 0x00, 0x14, 0x00, 0x64, 0x00, 0x00, 0x00, 0xf6, 0x00]))
            print "------------send"
            print hexdump(senddata)
            sock.send(senddata)
            recv = sock.recv(1024)
            print "------------recv"
            print hexdump(recv)
            exit()
        else:
            res = self.Request(0x2b, '\x0e\x01\00')

            if res and len(res)>5:
                objectsCount = ord(res[5])
                data = res[6:]
                info = ''
                for i in range(0, objectsCount):
                    info += data[2:2+ord(data[1])]
                    info += ' '
                    data = data[2+ord(data[1]):]
                    return info
                else:
                    raise ModbusProtocolError('Packet format (reply for device info) wrong', res)

def ScanUnit(ip, port, uid, timeout, function=None, data=''):
    con = Modbus(ip, port, uid, timeout)

    unitInfo = []
    if function:
        try:

            response = con.Request(function, data)
            unitInfo.append("Response: %s\t(%s)" % (StringPrintable(response), response.encode('hex')))
        except ModbusError as e:
            if e.code:
                unitInfo.append("Response error: %s" % e.message)
            else:
                return unitInfo
        exit()
    try:
        deviceInfo = con.DeviceInfo()
        unitInfo.append("Device: %s" % deviceInfo)
    except ModbusError as e:
        if e.code:
            unitInfo.append("Device info error: %s" % e.message)
        else:
            return unitInfo

    return unitInfo

def ModScan(ip, port, options):
    global debug_mode
    global func_fuzzing
    global di_scan

    debug_mode = False
    func_fuzzing = False
    di_scan = False
    res = False
    if options.debug:
        debug_mode = True
    if options.func_fuzzing:
        func_fuzzing = True
    if options.device_info_scan:
        di_scan = True

    try:
        data = options.modbus_data.decode("string-escape") if options.modbus_data else ''

        if options.brute_uid:
            uids = [0,255] + range(1,255)
        elif options.modbus_uid:
            uids = [int(uid.strip()) for uid in options.modbus_uid.split(',')]
        elif options.func_fuzzing:
            uids = [0]
        else:
            uids = [0,255]

        for uid in uids:
            unitInfo = ScanUnit(ip, port, uid, options.modbus_timeout, options.modbus_function, data)
            if unitInfo:
                if not res:
                    print "%s:%d Modbus/TCP" % (ip, port)
                    res = True
                print "Unit ID:%d" % uid
                for line in unitInfo:
                    print "   %s" % line

        return res

    except ModbusProtocolError as e:
        print "%s:%d Modbus protocol error: %s (packet: %s)" % (ip, port, e.message, e.packet.encode('hex'))
        if debug_mode:
            print hexdump(e.packet)
        return res
    except socket.error as e:
        print "%s:%d %s" % (ip, port, e)
        return res


if __name__=="__main__":
    try:
        scan(sys.argv[1:])
    except KeyboardInterrupt:
        status("Scan terminated\n")