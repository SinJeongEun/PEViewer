# -*- coding: utf-8 -*-
"""
PE Viewer
"""
import struct
import sys
import datetime

# from myapp import temp
# path = temp.p

BYTE = 1
WORD = 2 
DWORD = 4
ULONGLONG = 8
BIT = 0

notMzError = '윈도우 실행 파일 포맷이 아닙니다.'
notPeError = 'PE 포맷이 아닙니다.'

countDebug = 0

dllChar = 0 #Optional Header dll Characteristics
dirRva = []
dirSize = []
headerRva = []
headerPToRawData = []
headerSize = []
secName = []

image_rscr_directory_type =[]
rsrc_dir_nameid = []


rsrcIndex = 0
rsrcVirAdress = 0
rsrcString = []
vAlue = []

debugTypeRva = [0]
debugTypeSize = []
debugTypeNumber = []
intRva = 0
iatRva = 0
intRvaList = [[0,0]]
iatRvaList = [[0,0]]
importDllNameRvaList = [0]

delayIntRva = 0
delayIatRva = 0
delayDllNameRvaList = [0]
delayDllFuncRvaList = [0]
delayIatRvaList = [[0,0]]
delayIntRvaList = [[0,0]]

rsrcType = ['', #[0]
            'CURSOR', #[1]
            'BITMAP', #[2]
            'ICON', #[3]
            'MENU', #[4]
            'DIALOG', #[5]
            'STRING', #[6]
            'FONTDIR', #[7]
            'FONT', #[8]
            'ACCELERATOR', #[9]
            'RCDATA', #[10]
            'MESSAGETABLE', #[11]
            'GROUP_CURSOR',#[12]
            '', #[13]
            'GROUP_ICON', #[14]
            '', #[15]
            'VERSION', #[16]
            'DLGINCLUDE', #[17]
            '', #[18]
            'PLUGPLAY', #[19]
            'VXD', #[20]
            'ANICURSOR', #[21]
            'ANICON', #[22]
            'HTML', #[23]
            'MANIFEST' #[24]
            ]

class isNotMZ(Exception):
    def __init__(self):
        super().__init__(notMzError)

class isNotPE(Exception):
    def __init__(self):
        super().__init__(notPeError)

def intTupletoInt(a) :
    if a[0]==0:
        s = a[1]
    else:
        s = a[0] + a[1]*65536
    return int(s)

def byteToInt(a) :
    st = struct.unpack('<HH', a)
    return intTupletoInt(st) 

def rvaToOffset(rva, secStart, pToRawData) :
    return rva - secStart + pToRawData

def timeTrans(timeDateStamp):
    timeStr = '1970-01-01 00:00:00'
    thisTime = datetime.datetime.strptime(timeStr, '%Y-%m-%d %H:%M:%S')
    lastBuildTime = thisTime + datetime.timedelta(seconds=timeDateStamp)
    return lastBuildTime

def getDType():
   if BIT==32:
       return DWORD
   elif BIT==64:
       return ULONGLONG

def pFile(t):
    p = "%08x"%(int(hex(t),16))
    return p.upper()

def bYTE(lower):
    data = "%02x"%(int(lower,16))
    return data.upper()

def wORD(lower):
    data = "%04x"%(int(lower,16))
    return data.upper()

def dWORD(lower):
    data = "%08x"%(int(lower,16) & 0xFFFFFFFF)
    return data.upper()

class DosHeader:
    def __init__(self, t):
        try:
            self.part1 = []
            self.e_magic = data[t:t+WORD]      
            if self.e_magic != b'MZ':
                raise isNotMZ
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Signature', 'IMAGE_DOS_SIGNATURE MZ']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Bytes on Last Page of File', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Pages in File', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Relocations', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Size of Headers in Paragraphs', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Minimum Extra Paragraphs', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Maximum Extra Paragraphs', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Initial (relative) SS', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Initial SP', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Checksum', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Initial IP', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Initial (relative) CS', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Offset to Relocation Table', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Overlay Number', '']); t+=WORD
            for i in range(0, 4):
                self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Reserved', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'OEM Identifier', '']); t+=WORD
            self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'OEM Information', '']); t+=WORD
            for i in range(0, 10):
                self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Reserved', '']); t+=WORD
            self.e_lfanew = data[t:t+DWORD]
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Offset to New Exe Header', '']); t+=DWORD
            self.t=t
        except Exception as e:
            print(e);   sys.exit()
            
    def print(self):
        print('########Dos Header########')
        for i in self.part1:
            print(i[0], i[1], i[2], i[3])

    def getT(self):
        return self.t
    
    def getE_lfanew(self):
        return self.e_lfanew
         
class DosStub:
    def __init__(self, t, d):      
        self.all = data[t:d]

    def print(self):
        print("########Dos Stub########")
        print(self.all)
        print()

############################################################################################################################################################
# NTHeader
############################################################################################################################################################
class NTHeader:
    def __init__(self, offset):       
        self.Dir = []
        self.all = 0
        t = offset
        try:
            a = self.signature(t) # 변경된 t값 저장
            b = self.file_header(a) # 변경된 t값 저장
            c = self.optional_header(b)
            all = data[offset:c]
        except Exception as e:
            print(e);   sys.exit()
            
    def signature(self, t):
            signature = data[t:t+DWORD]
            if signature != b'\x50\x45\x00\x00':
                raise isNotPE
            self.part1 = [pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Signature', 'IMAGE_NT_SIGNATURE PE']
            t+=DWORD
            self.t = t;
            return self.t;

    def file_header(self, t):
            self.part2 = []
            machine = ''
            if data[t:t+WORD]==b'\x4c\x01':
                machine = 'IMAGE_FILE_MACHINE_I386'
            elif data[t:t+WORD]==b'\x64\x86':
                machine = 'IMAGE_FILE_MACHINE_AMD64'
            else:
                machine = 'IMAGE_FILE_MACINE_IA64'
            
            self.part2.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Machine', machine]); t+=WORD
            self.NumberOfSections = data[t:t+WORD]
            self.part2.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Number Of Section', '']); t+=WORD
            BuildTime = timeTrans(byteToInt(data[t:t+DWORD]))
            self.part2.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Time Date Stamp', BuildTime]); t+=DWORD
            self.part2.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Pointer To Symbol Table', '']); t+=DWORD
            self.part2.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Number of Symbols', '']); t+=DWORD
            self.part2.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'size of Optional Header', '']); t+=WORD
            self.part2.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Characteristics', ''])
            flag = byteToInt(data[t:t+WORD]+b'\x00\x00')
            t+=WORD
            charType = ['IMAGE_FILE_RELOCS_STRIPPED', 
                        'IMAGE_FILE_EXECUTABLE_IMAGE',
                        'IMAGE_FILE_LINE_NUMS_STRIPPED',
                        'IMAGE_FILE_LOCAL_SYMS_STRIPPED',
                        'IMAGE_FILE_AGGRESIVE_WS_TRIM',
                        'IMAGE_FILE_LARGE_ADDRESS_AWARE',
                        'IMAGE_FILE_BYTES_REVERSED_L0',
                        'IMAGE_FILE_32BIT_MACHINE',
                        'IMAGE_FILE_DEBUG_STRIPPED',
                        'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP',
                        'IMAGE_FILE_NET_RUN_FROM_SWAP',
                        'IMAGE_FILE_SYSTEM',
                        'IMAGE_FILE_DLL',
                        'IMAGE_FILE_UP_SYSTEM_ONLY',
                        'IMAGE_FILE_BYTES_REVERSED_HI']
            if flag & 0x0001:
                self.part2.append(['','', "%04x"%(int("0x0001",16)), charType[0]])
            if flag & 0x0002:
                self.part2.append(['','', "%04x"%(int("0x0002",16)), charType[1]])
            if flag & 0x0004:
                self.part2.append(['','' , "%04x"%(int("0x0004",16)), charType[2]])   
            if flag & 0x0008:
                self.part2.append(['','', "%04x"%(int("0x0008",16)), charType[3]])
            if flag & 0x0010:
                self.part2.append(['','', "%04x"%(int("0x0010",16)), charType[4]])
            if flag & 0x0020:
                self.part2.append(['','', "%04x"%(int("0x0020",16)), charType[5]])
            if flag & 0x0080:
                self.part2.append(['','',"%04x"%(int("0x0080",16)), charType[6]])
            if flag & 0x0100:
                self.part2.append(['','' , "%04x"%(int("0x0100",16)), charType[7]])
            if flag & 0x0200:
                self.part2.append(['','' , "%04x"%(int("0x0200",16)), charType[8]])
            if flag & 0x0400:
                self.part2.append(['','' , "%04x"%(int("0x0400",16)), charType[9]])
            if flag & 0x0800:
                self.part2.append(['','' , "%04x"%(int("0x0800",16)), charType[10]])
            if flag & 0x1000:
                self.part2.append(['','' , "%04x"%(int("0x1000",16)), charType[11]])
            if flag & 0x2000:
                self.part2.append(['','' , "%04x"%(int("0x2000",16)), charType[12]])
            if flag & 0x4000:
                self.part2.append(['','' , "%04x"%(int("0x4000",16)), charType[13]])
            if flag & 0x8000:
                self.part2.append(['','' , "%04x"%(int("0x8000",16)), charType[14]])
            self.t = t;
            return self.t;            

    def optional_header(self, t):        
            global BIT, dirRva, dirSize, dllChar
            value = ''
            self.part3 = []
            self.part4 = []
            self.Magic = data[t:t+WORD]                      
            if self.Magic == b'\x0b\x01':
                value = 'IMAGE_NT_OPTIONAL_HDR32_MAGIC'
                BIT = 32
            elif self.Magic == b'\x0b\x02':
                value = 'IMAGE_NT_OPTIONAL_HDR64_MAGIC'
                BIT = 64
            elif self.Magic == b'\x07\x01':
                value = 'IMAGE_ROM_OPTIONAL_HDR_MAGIC'
                BIT = 0 #ROM Image file
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Magic', value]); t+=WORD
            self.part3.append([pFile(t), bYTE(hex(struct.unpack('<l', data[t:t+BYTE]+b'\x00\x00\x00')[0])), 'Major Linker Version', '']); t+=BYTE
            self.part3.append([pFile(t), bYTE(hex(struct.unpack('<l', data[t:t+BYTE]+b'\x00\x00\x00')[0])), 'Minor Linker Version', '']); t+=BYTE
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Code', '']); t+=DWORD
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Initialized Data', '']); t+=DWORD
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Uninitialized Data', '']); t+=DWORD
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Address of Entry Point', '']); t+=DWORD   
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Base of Code', '']); t+=DWORD   
            if BIT == 32:
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Base of Data', '']); t+=DWORD   
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'ImageBase', '']); t+=DWORD       
            elif BIT == 64:
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'ImageBase', '']); t+=DWORD   
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD 
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Section Alignment', '']); t+=DWORD  
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'File Alignment', '']); t+=DWORD 
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Major O/S Version', '']); t+=WORD
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Minor O/S Version', '']); t+=WORD
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Major Image Version', '']); t+=WORD
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Minor Image Version', '']); t+=WORD
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Major Subsystem Version', '']); t+=WORD
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Minor Subsystem Version', '']); t+=WORD
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Win32 Version Value', '']); t+=DWORD 
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size Of Image', '']); t+=DWORD 
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size Of Headers', '']); t+=DWORD 
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Checksum', '']); t+=DWORD
            subSystemValue = ['IMAGE_SUBSYSTEM_UNKNOWN',
                              'IMAGE_SUBSYSTEM_NATIVE',
                              'IMAGE_SUBSYSTEM_WINDOWS_GUI',
                              'IMAGE_SUBSYSTEM_WINDOWS_CUI',
                              '',
                              'IMAGE_SUBSYSTEM_OS2_CUI',
                              '',
                              'IMAGE_SUBSYSTEM_POSIX_CUT',
                              'IMAGE_SUBSYSTEM_NATIVE_WINDOWS',
                              'IMAGE_SUBSYSTEM_WINDOWS_CE_GUI']
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Subsystem', 
                               subSystemValue[byteToInt(data[t:t+WORD]+b'\x00\x00')]]); t+=WORD
            dllChar = byteToInt(data[t:t+WORD]+b'\x00\x00')
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Dll characteries', '']); t+=WORD
                               
            DllCharaEnt = ['IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA',
                           'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE',
                           'IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY',
                           'IMAGE_DLLCHARACTERISTICS_NX_COMPAT',
                           'IMAGE_DLLCHARACTERISTICS_NO_ISOLATION',
                           'IMAGE_DLLCHARACTERISTICS_NO_SEH',
                           'IMAGE_DLLCHARACTERISTICS_NO_BIND',
                           'IMAGE_DLLCHARACTERISTICS_APPCONTAINER',
                           'IMAGE_DLLCHARACTERISTICS_WDM_DRIVER',
                           'IMAGE_DLLCHARACTERISTICS_GUARD_CF',
                           'IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE']
            if dllChar & 0x0020:
                self.part3.append(['','' , "%04x"%(int("0x0020",16)), DllCharaEnt[0]])
            if dllChar & 0x0040:
                self.part3.append(['','' , "%04x"%(int("0x0040",16)), DllCharaEnt[1]])
            if dllChar & 0x0080:
                self.part3.append(['','' , "%04x"%(int("0x0080",16)), DllCharaEnt[2]])   
            if dllChar & 0x0100:
                self.part3.append(['','' , "%04x"%(int("0x0100",16)), DllCharaEnt[3]])
            if dllChar & 0x0200:
                self.part3.append(['','' , "%04x"%(int("0x0200",16)), DllCharaEnt[4]])
            if dllChar & 0x0400:
                self.part3.append(['','' , "%04x"%(int("0x0400",16)), DllCharaEnt[5]])
            if dllChar & 0x0800:
                self.part3.append(['','' , "%04x"%(int("0x0800",16)), DllCharaEnt[6]])
            if dllChar & 0x1000:
                self.part3.append(['','' , "%04x"%(int("0x1000",16)), DllCharaEnt[7]])
            if dllChar & 0x2000:
                self.part3.append(['','' , "%04x"%(int("0x2000",16)), DllCharaEnt[8]])
            if dllChar & 0x4000:
                self.part3.append(['','' , "%04x"%(int("0x4000",16)), DllCharaEnt[9]])
            if dllChar & 0x8000:
                self.part3.append(['','' , "%04x"%(int("0x8000",16)), DllCharaEnt[10]])

            if BIT==32:
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Stack Reverse', '']); t+=DWORD
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Stack Commit', '']); t+=DWORD
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Heap Reverse', '']); t+=DWORD 
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Heap Commit', '']); t+=DWORD 
            elif BIT==64:
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Stack Reverse', '']); t+=DWORD
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Stack Commit', '']); t+=DWORD
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Heap Reverse', '']); t+=DWORD 
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Heap Commit', '']); t+=DWORD 
                self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
            
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Loader Flags', '']); t+=DWORD 
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Number of Data Directories', '']); t+=DWORD 
            
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'EXPORT Table']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'IMPORT Table']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'RESOURCE Table']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'EXCEPTION Table']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'CERTIFICATE Table']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'BASE RELOCATION Table']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'DEBUG Directoty']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'Architecture Specific Data']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'GLOBAL POINTER Register']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'TLS Table']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'LOAD CONFIGURATION Table']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'BOUND IMPORT Table']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'IMPORT Address Table']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'Delay IMPORT Descriptors']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA', 'CLI Header']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part4.append([pFile(t), '00000000', 'RVA', '']); t+=DWORD
            self.part4.append([pFile(t), '00000000', 'Size', '']); t+=DWORD
            t-=(DWORD*32)
            for i in range(0, 15):
                dirRva.append(byteToInt(data[t:t+DWORD])); t+=DWORD
                dirSize.append(byteToInt(data[t:t+DWORD])); t+=DWORD
            t+=(DWORD*2)
            self.t = t;
            return self.t
            
    def print(self):
        # Signature
        print('########NT Header########')
        print('########Sinature########')
        i = self.part1
        print(i[0], i[1], i[2], i[3]) 
        print()

        # FILE_HEADER
        print('########File Header########')
        for i in self.part2:
            print(i[0], i[1], i[2], i[3])
        print()
        
        # OPTIONAL_HEADER
        print('########Option Header########') #part3, part4
        for i in self.part3:
            print(i[0], i[1], i[2], i[3])
        print("==========================")
        #DATA_DIRECTORY
        check=0
        for i in self.part4:
            print(i[0], i[1], i[2], i[3])
            check+=1
            if check%2==0:
                print("==========================")
        print()
            
    def getT(self):
        return self.t
    
    def getNumberOfSections(self):
        return self.NumberOfSections
############################################################################################################################################################
# SectionHeader
############################################################################################################################################################      
class SectionHeader:
    def __init__(self, t, SecNumber):   
        global headerRva, headerPToRawData, headerSize, secName #
        self.SecHeader = []
        self.part = []
        for i in range(0, SecNumber):
            subPart = []
            secName.append((data[t:t+DWORD].decode('ISO-8859-1') + data[t+DWORD:t+DWORD*2].decode('ISO-8859-1')))
            #소연 부분#####
            if data[t:t+DWORD*2] ==  b'\x2e\x72\x73\x72\x63\x00\x00\x00':
                global rsrcIndex #리소스 섹션헤더의 인덱스
                rsrcIndex = i
            ###############
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 
                           'Name', (data[t:t+DWORD].decode('ISO-8859-1') + data[t+DWORD:t+DWORD*2].decode('ISO-8859-1'))]); t+=DWORD
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 
                                 'Virtual Size', '']); t+=DWORD
            headerRva.append(byteToInt(data[t:t+DWORD]))
            #소연 부분#####
            global rsrcVirAdress #리소스 섹션헤더의 VA(RVA)
            rsrcVirAdress = headerRva[rsrcIndex]
            ###############
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 
                                 'RVA', '']); t+=DWORD
            headerSize.append(byteToInt(data[t:t+DWORD]))
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 
                                 'Size of Raw Data', '']); t+=DWORD
            headerPToRawData.append(byteToInt(data[t:t+DWORD]))
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 
                                 'Pointer to Raw Data', '']); t+=DWORD
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 
                                 'Pointer to Relocations', '']); t+=DWORD
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 
                                 'Pointer to Line Numbers', '']); t+=DWORD
            subPart.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 
                                 'Number of Relocations', '']); t+=WORD
            subPart.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 
                                 'Number of Line Numbers', '']); t+=WORD
            charType = ['IMAGE_SCN_CNT_CODE',
                        'IMAGE_SCN_CNT_INITIALIZED_DATA',
                        'IMAGE_SCN_CNT_UNINITIALIZED_DATA',
                        'IMAGE_SCN_CNT_DISCARDABLE',
                        'IMAGE_SCN_CNT_CHACHED',
                        'IMAGE_SCN_CNT_PAGED',
                        'IMAGE_SCN_CNT_SHARED',
                        'IMAGE_SCN_CNT_EXECUTE',
                        'IMAGE_SCN_CNT_READ',
                        'IMAGE_SCN_CNT_WRITE']
            flag = byteToInt(data[t:t+DWORD])
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])),
                                 'Characteristics', '']); t+=DWORD
            if flag & 0x00000020:
                subPart.append(['','' , "%08x"%(int("00000020",16)), charType[0]])
            if flag & 0x00000040:
                subPart.append(['','' , "%08x"%(int("00000040",16)), charType[1]])
            if flag & 0x00000080:
                subPart.append(['','' , "%08x"%(int("00000080",16)), charType[2]])
            if flag & 0x02000000:
                subPart.append(['','' , "%08x"%(int("02000000",16)), charType[3]])  
            if flag & 0x04000000:
                subPart.append(['','' , "%08x"%(int("04000000",16)), charType[4]])  
            if flag & 0x08000000:
                subPart.append(['','' , "%08x"%(int("08000000",16)), charType[5]])
            if flag & 0x10000000:
                subPart.append(['','' , "%08x"%(int("10000000",16)), charType[6]])  
            if flag & 0x20000000:
                subPart.append(['','' , "%08x"%(int("20000000",16)), charType[7]])  
            if flag & 0x40000000:
                subPart.append(['','' , "%08x"%(int("40000000",16)), charType[8]])  
            if flag & 0x80000000:
                subPart.append(['','' , "%08x"%(int("80000000",16)), charType[9]])  
            self.part.append(subPart)

            
    def print(self): #Secion header이름은 전역변수 secName 배열에 있습니다.
        print('########Section Header########')
        count = 0
        for i in self.part: 
            print('########Image Section Header'+secName[count]+'########')
            for j in i:
                print(j[0], j[1], j[2], j[3])
            count+=1
            print()

class BoundedImport:
    def __init__(self):
        global dirRva, dirSize
        self.offset = dirRva[11]
        self.size = dirSize[11]
        t = self.BoundedIDT()
        self.BoundedName(t)
    def BoundedIDT(self):
        self.idt = []
        self.element = ['Time Date Stamp', 'Offset to Module Name',
                        'Number of Module Forwarder Refs']
        self.part = []
        t = self.offset
        while True:
            subPart = []
            BuildTime = timeTrans(byteToInt(data[t:t+DWORD]))
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 
                            'Time Date Stamp', BuildTime]); t+=DWORD
            if byteToInt(data[t:t+DWORD]) == 0:
                subPart.append([pFile(t), '', '', '']); t+=WORD
                subPart.append([pFile(t), '', '', '']); t+=WORD
                break
            dllStart = address = self.offset+byteToInt(data[t:t+WORD]+b'\x00\x00')
            while data[address]!=0:
                address+=1
            subPart.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 
                            'Offset to Module Name', data[dllStart:address].decode('ISO-8859-1')]); t+=WORD
            subPart.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 
                            'Number of Module Forwarded Refs', '']); t+=WORD
            self.part.append(subPart)
            """self.idt.append([data[t:t+DWORD], data[t+DWORD:t+DWORD+WORD], data[t+DWORD+WORD:t+DWORD*2]])
            if byteToInt(data[t:t+DWORD]) == 0:
                t+=(DWORD*2)
                break
            t+=(DWORD*2)"""
        return t

    def BoundedName(self, t):
        self.info = data[t:self.offset+self.size]
    
    def print(self):
        print('########Bounded Import Directory Table########')
        for i in self.part:
            for j in i:
                print(j[0], j[1], j[2], j[3])
            print('==========================')
        print('########Bounded Import Dll Names########')
        print(self.info)

class Section:
    def __init__(self, rva, size, secNum, pToRawData):
        global dirRva, secName, debugTypeRva, debugTypeSize, debugType, countDebug, intRvaList, importDllNameRvaList
        global delayIatRvaList, delayIntRvaList, delayDllNameRvaList, delayDllFuncRvaList
        all = data[pToRawData:pToRawData+size]
        self.SecPartOffset = []
        self.secNum = secNum
        self.SecPart = [] 
        if (dirRva[0] >= rva) and (dirRva[0] <= rva+size):
            self.SecPart.append(exportTable(rvaToOffset(dirRva[0], rva, pToRawData), dirSize[0], rva, pToRawData)) #구현완료
        if (dirRva[1] >= rva) and (dirRva[1] <= rva+size):
            self.SecPart.append(ImportTable(rvaToOffset(dirRva[1], rva, pToRawData), dirSize[1], rva, pToRawData)) #구현완료
        if (dirRva[2] >= rva) and (dirRva[2] <= rva+size):
            self.SecPart.append(resourceTable(rvaToOffset(dirRva[2], rva, pToRawData), dirSize[2])) #소연님이 구현하실 리소스 테이블
        if (dirRva[3] >= rva) and (dirRva[3] <= rva+size):
            self.SecPart.append(RuntimeFunction(rvaToOffset(dirRva[3], rva, pToRawData), dirSize[3])) #구현 완료         
        #if (dirRva[4] >= rva) and (dirRva[4] <= rva+size) #별도 구현(구현 완료)
        if (dirRva[5] >= rva) and (dirRva[5] <= rva+size):
            self.SecPart.append(relocSection(rvaToOffset(dirRva[5], rva, pToRawData), dirSize[5])) #구현완료(출력이 많다, 다른 것 테스트 할 때 이부분 주석)
        if (dirRva[6] >= rva) and (dirRva[6] <= rva+size):
            self.SecPart.append(debugDirectory(rvaToOffset(dirRva[6], rva, pToRawData), dirSize[6])) #구현완료
        #if (dirRva[7] >= rva) and (dirRva[7] <= rva+size): #일반 윈도우에서 사용하지 않는다, 구현 생략
        #if (dirRva[8] >= rva) and (dirRva[8] <= rva+size): #일반 윈도우에서 사용하지 않는다, 구현 생략
        if (dirRva[9] >= rva) and (dirRva[9] <= rva+size):
            self.SecPart.append(TlsTable(rvaToOffset(dirRva[9], rva, pToRawData), dirSize[9])) #구현완료
        if (dirRva[10] >= rva) and (dirRva[10] <= rva+size):
            self.SecPart.append(LoadConfig(rvaToOffset(dirRva[10], rva, pToRawData), dirSize[10])) #구현완료
        #if (dirRva[11] >= rva) and (dirRva[11] <= rva+size) #별도 구현(구현 완료)       
        #if (dirRva[12] >= rva) and (dirRva[12] <= rva+size):
        #    self.SecPart.append(ImportAddressTable(rvaToOffset(dirRva[12], rva, pToRawData), dirSize[12])) #별도 구현(구현완료)  
        if (dirRva[13] >= rva) and (dirRva[13] <= rva+size):
            self.SecPart.append(DelayImport(rvaToOffset(dirRva[13], rva, pToRawData), dirSize[13], rva, pToRawData)) #구현완료      
        if (dirRva[14] >= rva) and (dirRva[14] <= rva+size):
            self.SecPart.append(CliHeader(rvaToOffset(dirRva[14], rva, pToRawData), dirSize[14])) #구현완료
        for i in debugTypeRva:
            if (i >= rva) and (i <= rva+size):
                self.SecPart.append(DebugType(rvaToOffset(i, rva, pToRawData), debugTypeSize[countDebug], debugTypeNumber[countDebug]))
                countDebug+=1
        
        if (intRvaList[0][0] >= rva) and (intRvaList[0][0] <= rva+size):
            self.SecPart.append(ImportNameTable(rva, pToRawData))
        if (iatRvaList[0][0] >= rva) and (iatRvaList[0][0] <= rva+size):
            self.SecPart.append(ImportAddressTable(rva, pToRawData))        
        if (min(importDllNameRvaList)>= rva) and (min(importDllNameRvaList) <= rva+size):
            self.SecPart.append(ImportHintsAndNames(rva, pToRawData))
        if (delayIatRvaList[0][0] >= rva) and (delayIatRvaList[0][0] <= rva+size):
            self.SecPart.append(DelayImportAddressTable(rva, pToRawData)) 
        if (delayIntRvaList[0][0] >= rva) and (delayIntRvaList[0][0] <= rva+size):
            self.SecPart.append(DelayImportNameTable(rva, pToRawData))
        if (min(delayDllNameRvaList)>=rva) and (min(delayDllNameRvaList) <= rva+size):
            self.SecPart.append(DelayImportName(rva, pToRawData))
        if (min(delayDllFuncRvaList)>=rva) and (min(delayDllFuncRvaList) <= rva+size):
            self.SecPart.append(DelayImportHintsAndNames(rva, pToRawData))    

    def print(self):
        count = 0
        SecPartReal = []
        for i in self.SecPart:
            self.SecPartOffset.append([i.offset, count])
            count+=1
        self.SecPartOffset.sort()
        count=0
        for i in self.SecPartOffset:
            SecPartReal.append(self.SecPart[self.SecPartOffset[count][1]])
            count+=1
        print('########',secName[self.secNum], '########')
        for i in SecPartReal:
            i.print()

class exportTable:
    def __init__(self, offset, size, secOffset, pToRawData):
        self.offset = offset
        self.size = size
        self.secOffset = secOffset
        self.pToRawData = pToRawData
        self.ImageExportDirectory(offset)
        self.ExportAddressTable(rvaToOffset(byteToInt(self.AddressOfFunctions), secOffset, pToRawData))
        self.ExportNamePointerTable(rvaToOffset(byteToInt(self.AddressOfNames), secOffset, pToRawData))
        self.ExportOrdinalTable(rvaToOffset(byteToInt(self.AddressOfNameOrdinals), secOffset, pToRawData))
        self.ExportName(rvaToOffset(byteToInt(self.Name), secOffset, pToRawData))
        
    def ImageExportDirectory(self, t):
        self.part1 = []
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Characteristics', '']); t+=DWORD
        buildTime = timeTrans(byteToInt(data[t:t+DWORD]))
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Time Date Stamp', buildTime]); t+=DWORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Major Version', '']); t+=WORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Minor Version', '']); t+=WORD
        start = end = rvaToOffset(byteToInt(data[t:t+DWORD]), self.secOffset, self.pToRawData)
        print(start)
        while data[end] !=0:
            end+=1
        name = data[start:end].decode('ISO-8859-1')     
        self.Name = data[t:t+DWORD];
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Name RVA', name]); t+=DWORD
        self.Base = data[t:t+DWORD];
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Ordinal Base', '']); t+=DWORD
        self.NumberOfFunctions = data[t:t+DWORD];
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Number of Functions', '']); t+=DWORD
        self.NumberOfNames = data[t:t+DWORD];
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Number of Names', '']); t+=DWORD
        self.AddressOfFunctions = data[t:t+DWORD]
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Address Table RVA', '']); t+=DWORD
        self.AddressOfNames = data[t:t+DWORD];
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Name Pointer Table RVA', '']); t+=DWORD
        self.AddressOfNameOrdinals = data[t:t+DWORD];
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Ordinal Table RVA', '']); t+=DWORD
        
        return t
    
    def ExportAddressTable(self, t):
        self.part2 = []
        number = byteToInt(self.NumberOfFunctions)
        for i in range(0, number):
            self.part2.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Function RVA', '']);
            t+=DWORD
        return t
    
    def ExportNamePointerTable(self, t):
        self.part3 = []
        number = byteToInt(self.NumberOfNames)
        for i in range(0, number):
            start = end = rvaToOffset(byteToInt(data[t:t+DWORD]), self.secOffset, self.pToRawData)
            while data[end] !=0:
                end+=1
            value = str((byteToInt(self.Base)+i))+' '+data[start:end].decode('ISO-8859-1')
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Function Name RVA', value]);
            self.part2[i][3] = value
            t+=DWORD
        return t

    def ExportOrdinalTable(self, t):
        self.part4 = []
        number = byteToInt(self.NumberOfFunctions)
        for i in range(0, number):
            self.part4.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Function Ordinal', self.part2[i][3]])
            t+=WORD
        return t

    def ExportName(self, t):
        self.info = data[t:self.offset+self.size]
        return t

    def print(self):
        print('########Image Export Directory########')
        for i in self.part1:
            print(i[0], i[1], i[2], i[3])
        print()
        print('########Export Address Table########')
        for i in self.part2:
            print(i[0], i[1], i[2], i[3])
        print()
        print('########Export Name Pointer Table########')
        for i in self.part3:
            print(i[0], i[1], i[2], i[3])
        print()
        print('########Export Odrinal Table########')
        for i in self.part4:
            print(i[0], i[1], i[2], i[3])
        print()
        print('########Export Name########')
        print(self.info)
        print()
        

class ImportTable:
    def __init__(self, offset, size, secRva, pToRawData):
        global intRvaList, importDllNameRvaList, iatRvaList, importDllName
        self.offset = offset
        intRvaList.pop()
        importDllNameRvaList.pop()
        iatRvaList.pop()
        self.part1 = []
        self.element = ['Import Name Table RVA', 'Time Date Stamp', 'Forwarder Chain',
                        'Name RVA', 'Import Address Table RVA']
        t = offset
        count = 0
        while t < offset+size:
            subpart = []
            if data[t:t+DWORD] != b'\x00\x00\x00\x00':
                intRvaList.append([byteToInt(data[t:t+DWORD]), ''])
            if data[t+DWORD*3:t+DWORD*4] != b'\x00\x00\x00\x00':
                importDllNameRvaList.append(byteToInt(data[t+DWORD*3:t+DWORD*4]))
            if data[t+DWORD*4:t+DWORD*5] != b'\x00\x00\x00\x00':
                iatRvaList.append([byteToInt(data[t+DWORD*4:t+DWORD*5]), ''])
            subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Import Name Table RVA', '']); t+=DWORD
            subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Time Date Stamp', '']); t+=DWORD
            subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Forwarder Chain', '']); t+=DWORD
            if byteToInt(data[t:t+DWORD]) != 0:
                start = end = rvaToOffset(byteToInt(data[t:t+DWORD]), secRva, pToRawData)
                while data[end]!=0:
                    end+=1
                subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Name RVA', data[start:end].decode('ISO-8859-1')]); t+=DWORD
                intRvaList[count][1]=(data[start:end].decode('ISO-8859-1'))
                iatRvaList[count][1]=(data[start:end].decode('ISO-8859-1'))
            else:
                subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Name RVA', '']); t+=DWORD
            subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Import Address Table RVA', '']); t+=DWORD
            self.part1.append(subpart)
            count+=1
        intRvaList.sort()
        iatRvaList.sort()
        
    def print(self):
        print('########Import Directory Table########')
        for i in self.part1:
            for j in i:
                print(j[0], j[1], j[2], j[3])
            print('==========================')
        print()

class ImportNameTable:
    def __init__(self, rva, pToRawData):
        global intRva, intRvaList, importDllNameRvaList
        self.tempPart = []
        self.offset = rvaToOffset(intRvaList[0][0], rva, pToRawData)
        intRva = intRvaList[0][0]
        count = 0
        for i in intRvaList:
                subPart = []
                t = rvaToOffset(i[0], rva, pToRawData)
                while True:
                    k = byteToInt(data[t:t+DWORD])
                    if k & 0x80000000:
                        subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Ordinal Number', k & 0x000000FF]); t+=DWORD
                    elif k & 0x70000000:
                        subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Virtual Address', '']); t+=DWORD
                    elif k !=0:
                        subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Hint/Name RVA', '']); t+=DWORD
                    else :
                        subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'End of Imports', i[1]]); t+=DWORD
                        break
                count +=1
                self.tempPart.append(subPart)
    
    def print(self):
        global intRvaList
        print('########Import Name Table########')
        self.part1 = []
        for i in self.tempPart:
            for j in i:
                print(j[0], j[1], j[2], j[3])
            print('==========================')

class ImportAddressTable:
    def __init__(self, rva, pToRawData):
        global iatRva, iatRvaList, importDllNameRvaList
        self.tempPart = []
        self.offset = rvaToOffset(iatRvaList[0][0], rva, pToRawData)
        iatRva = iatRvaList[0][0]
        count = 0
        for i in iatRvaList:
                subPart = []
                t = rvaToOffset(i[0], rva, pToRawData)
                while True:
                    k = byteToInt(data[t:t+DWORD])
                    if k & 0x80000000:
                        subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Ordinal Number', k & 0x000000FF]); t+=DWORD
                    elif k & 0x70000000:
                        subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Virtual Address', '']); t+=DWORD
                    elif k !=0:
                        subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Hint/Name RVA', '']); t+=DWORD
                    else:
                        subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'End of Imports', i[1]]); t+=DWORD
                        break
                count +=1
                self.tempPart.append(subPart)
    
    def print(self):
        global iatRvaList
        print('########Import Address Table########')
        self.part1 = []
        for i in self.tempPart:
            for j in i:
                print(j[0], j[1], j[2], j[3])
            print('==========================')
            
class ImportHintsAndNames:
    def __init__(self, rva, pToRawData):
        global importDllNameRvaList
        self.offset = rvaToOffset(min(importDllNameRvaList), rva, pToRawData)
        dirEnd = rvaToOffset(max(importDllNameRvaList), rva, pToRawData)
        while True:
            if data[dirEnd:dirEnd+1] == b'\x00':
                break
            dirEnd+=1
        self.info = data[rvaToOffset(min(importDllNameRvaList), rva, pToRawData):dirEnd]

    def print(self):
        global importDllNameRvaList
        print('########Import Hints/Names & DLL Names########')
        print(self.info)

class DelayImport:
    def __init__(self, offset, size, rva, pToRawData):
        global delayDllNameRvaList, delayIatRvaList, delayIntRvaList
        self.offset = offset
        delayDllNameRvaList.pop()
        delayIatRvaList.pop()
        delayIntRvaList.pop()
        self.part1 = []
        self.element = ['Attributes', 'RVA to DLL Name', 'RVA to HMODULE',
                        'RVA to Import Address Table', 'RVA to Import Name Table'
                        , 'RVA to Bound IAT', 'RVA to Unload IAT', 'Time Date Stamp']
        t = offset
        count = 0
        while t < offset+size:
            subpart = []
            if data[t+DWORD:t+DWORD*2] != b'\x00\x00\x00\x00':
                delayDllNameRvaList.append(byteToInt(data[t+DWORD:t+DWORD*2]))
            if data[t+DWORD*3:t+DWORD*4] != b'\x00\x00\x00\x00':
                delayIatRvaList.append([byteToInt(data[t+DWORD*3:t+DWORD*4]),''])
            if data[t+DWORD*4:t+DWORD*5] != b'\x00\x00\x00\x00':
                delayIntRvaList.append([byteToInt(data[t+DWORD*4:t+DWORD*5]),''])
            subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Attribute', '']); t+=DWORD
            if data[t:t+DWORD] == b'\x00\x00\x00\x00':
                subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Rva to Dll Name','']); t+=DWORD
            else:
                start = end = rvaToOffset(byteToInt(data[t:t+DWORD]), rva, pToRawData)
                while data[end]!=0:
                    end+=1
                subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Rva to Dll Name', data[start:end].decode('ISO-8859-1')]); t+=DWORD
                delayIntRvaList[count][1]=(data[start:end].decode('ISO-8859-1'))
                delayIatRvaList[count][1]=(data[start:end].decode('ISO-8859-1'))
            subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Rva to HMODULE', '']); t+=DWORD
            subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Rva to Import Address Table', '']); t+=DWORD
            subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Rva to Import Name Table', '']); t+=DWORD
            subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA to Bound IAT', '']); t+=DWORD
            subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Rva to Unload IAT', '']); t+=DWORD
            subpart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Time Date Stamp', '']); t+=DWORD
            self.part1.append(subpart)
        delayIatRvaList.sort()
        delayIntRvaList.sort()
        
    def print(self):
        print('########Delay Import Descriptors########')
        for i in self.part1:
            for j in i:
                print(j[0], j[1], j[2], j[3])
            print('==========================')
        print()

class DelayImportNameTable:
    def __init__(self, rva, pToRawData):
        global delayIntRva, delayIntRvaList, delayDllFuncRvaList
        self.offset = rvaToOffset(delayIntRvaList[0][0], rva, pToRawData)
        if delayDllFuncRvaList[0]==0:
            delayDllFuncRvaList.pop()
        self.part1 = []
        delayIntRva = delayIntRvaList[0][0]
        for i in delayIntRvaList:
            subPart = []
            t = rvaToOffset(i[0], rva, pToRawData)
            while True:
                k = byteToInt(data[t:t+DWORD])
                if k < 0x20000000 and k !=0:
                    delayDllFuncRvaList.append(byteToInt(data[t:t+DWORD]))
                if k & 0x80000000:
                    subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Ordinal Number', k & 0x000000FF]);
                elif k & 0x70000000:
                    subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Virtual Address', '']);
                elif k !=0:
                    subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Hint/Name RVA', '']);
                if(data[t:t+DWORD]) == b'\x00\x00\x00\x00':
                    subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'End of Imports', i[1]]);
                    break
                else:
                    if byteToInt(data[t:t+DWORD]) < 0x20000000:
                        delayDllFuncRvaList.append(byteToInt(data[t:t+DWORD]))
                t+=DWORD
            self.part1.append(subPart)
            
    
    def print(self):
        print('########Delay Import Name Table########')
        for i in self.part1:
            for j in i:
                print(j[0], j[1], j[2], j[3])
            print('==========================')
        print()

class DelayImportAddressTable:
    def __init__(self, rva, pToRawData):
        global delayIatRva, delayIatRvaList, delayDllFuncRvaList
        self.offset = rvaToOffset(delayIatRvaList[0][0], rva, pToRawData)
        if delayDllFuncRvaList[0]==0:
            delayDllFuncRvaList.pop()
        self.part1 = []
        delayIatRva = delayIatRvaList[0][0]
        for i in delayIatRvaList:
            subPart = []
            t = rvaToOffset(i[0], rva, pToRawData)
            while True:
                k = byteToInt(data[t:t+DWORD])
                if k < 0x20000000 and k !=0:
                        delayDllFuncRvaList.append(byteToInt(data[t:t+DWORD]))
                if k & 0x80000000:
                    subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Ordinal Number', k & 0x000000FF]);
                elif k & 0x70000000:
                    subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Virtual Address', '']);
                elif k!=0:
                    subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Hint/Name RVA', '']);
                if(data[t:t+DWORD]) == b'\x00\x00\x00\x00':
                    subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'End of Imports', i[1]]);
                    break
                t+=DWORD
            self.part1.append(subPart)
            
    
    def print(self):
        print('########Delay Import Name Table########')
        for i in self.part1:
            for j in i:
                print(j[0], j[1], j[2], j[3])
            print('==========================')
        print()

class DelayImportName:
    def __init__(self, rva, pToRawData):
        global delayDllNameRvaList
        self.offset = rvaToOffset(min(delayDllNameRvaList), rva, pToRawData)
        dirEnd = rvaToOffset(max(delayDllNameRvaList), rva, pToRawData)
        while True:
            if data[dirEnd:dirEnd+1] == b'\x00':
                break
            dirEnd+=1
        self.info = data[rvaToOffset(min(delayDllNameRvaList), rva, pToRawData):dirEnd]

    def print(self):
        global importDllNameRvaList
        print('########Delay Import DLL Name########')
        print(self.info)
        print()

class DelayImportHintsAndNames:
    def __init__(self, rva, pToRawData):
        global delayDllFuncRvaList
        self.offset = rvaToOffset(min(delayDllFuncRvaList), rva, pToRawData)
        dirEnd = rvaToOffset(max(delayDllFuncRvaList), rva, pToRawData)
        print(delayDllFuncRvaList)
        while True:
            if data[dirEnd:dirEnd+1] == b'\x00':
                break
            dirEnd+=1
        self.info = data[rvaToOffset(min(delayDllFuncRvaList), rva, pToRawData):dirEnd]

    def print(self):
        global importDllNameRvaList
        print('########Delay Import Hints/Names & DLL Names########')
        print(self.info)
        print()

class RuntimeFunction:
    def __init__(self, offset, size):
        self.offset=offset
        self.part1 = []
        t = offset
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Begin Address', '']);
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'End Address', '']);
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Unwind', '']);
    
    def print(self):
        print('########Image Runtime Function Entry########')
        for i in self.part1:
            print(i[0], i[1], i[2], i[3])
        
class resourceTable:
    def __init__(self, offset, size):
        self.offset = offset # .rsrc 시작위치
        t = offset
        self.all = data[offset:offset+size]
        
        self.DirectoryEntriesId = [] #rsrcType[] 인덱스 번호 저장
        self.OffsetToData = [] # 세부 섹션 시작 주소 저장()

        #실행
        ar = self.rsrcDirType(t)
        br = self.rsrcDirNameId(ar)
        cr = self.rsrcDirLan(br)
        dr = self.rsrcData(cr)    
        self.rsrcDirString(dr, self.OffsetToData[0])
        
        for i in range(1, self.count):
            self.subRsrc(self.OffsetToData[i])
      

    def rsrcDirType(self, t):

        self.part1 = []
        self.part2 = []

        global rsrcType

        

        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Characteristics', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'TimeDateStamp', '']); t+=DWORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'MajorVersion', '']); t+=WORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'MinorVersion', '']); t+=WORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'NumberOfNamedEntries', '']); t+=WORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'NumberOfIdEntries', '']); t+=WORD
        image_rscr_directory_type.append(self.part1)    
        for i in range(0, len(rsrcType)):
            if byteToInt(data[t:t+DWORD]) == i:
                self.DirectoryEntriesId.append(byteToInt(data[t:t+DWORD])); #rsrcType[] 인덱스 번호 저장
                self.part2.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'ID', '']); t+=DWORD;
                self.part2.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Offset to DIRECTORY', rsrcType[i]]); t+=DWORD;
                image_rscr_directory_type.append(self.part2)
        self.t = t;
        return self.t;
    
    def rsrcDirNameId(self, t):
        self.part3 = []
        self.count = 0

        global rsrcType, rsrcString
        
        for i in range(0, len(self.DirectoryEntriesId)):
            global rsrcString
            self.NumberOfNamedEntries = self.NumberOfIdEntries = 0
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Characteristics', '']); t+=DWORD
            self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'TimeDateStamp', '']); t+=DWORD
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'MajorVersion', '']); t+=WORD
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'MinorVersion', '']); t+=WORD
            
            self.NumberOfNamedEntries = byteToInt(data[t:t+WORD]+b'\x00\x00')
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'NumberOfNamedEntries', '']); t+=WORD
            self.NumberOfIdEntries = byteToInt(data[t:t+WORD]+b'\x00\x00')
            self.part3.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'NumberOfIdEntries', '']); t+=WORD
            
            self.part3.append(["==========================",'','',''])
            for j in range(0, (self.NumberOfNamedEntries + self.NumberOfIdEntries)):
                if self.NumberOfNamedEntries > 0:
                    vAlue.append([rsrcType[self.DirectoryEntriesId[i]], 'NameValue'])
                    self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Name', '']); t+=DWORD;
                    self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Offset to DIRECTORY', ' '.join(vAlue[i][:2])]); t+=DWORD;
                    self.NumberOfNamedEntries-=1
                else:
                    id = wORD(hex(struct.unpack('<l', data[t:t+DWORD])[0]))
                    vAlue.append([rsrcType[self.DirectoryEntriesId[i]], id])
                    self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'ID', '']); t+=DWORD;
                    self.part3.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Offset to DIRECTORY', ' '.join(vAlue[i][:2])]); t+=DWORD;
                self.part3.append(["==========================",'','',''])
                rsrc_dir_nameid.append(self.part3)
                self.count += 1 #rsrcDirLan 반복 횟수

        self.t = t;

        return self.t;
    
    def rsrcDirLan(self, t):
        self.part4 = []

        global rsrcType, rsrcVirAdress

        for i in range(0, self.count):
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Characteristics', '']); t+=DWORD
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'TimeDateStamp', '']); t+=DWORD
            self.part4.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'MajorVersion', '']); t+=WORD
            self.part4.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'MinorVersion', '']); t+=WORD
            self.part4.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'NumberOfNamedEntries', '']); t+=WORD
            self.part4.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'NumberOfIdEntries', '']); t+=WORD            
            self.lanId = wORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])) #나라언어
            
            self.part4.append(["==========================",'','',''])
            vAlue[i].append(self.lanId) #Value에 나라언어 추가
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'ID', '']); t+=DWORD;           
            self.part4.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Offset to DATA ENTRY', ' '.join(vAlue[i])]); t+=DWORD;
            self.part4.append(["==========================",'','',''])
            rsrc_dir_nameid.append(self.part4)

        self.t = t;
        return self.t;
    
    def rsrcData(self, t):
        self.part5 = []
        self.subRsrcSize = []

        for i in range(0, self.count):
            self.OffsetToData.append(byteToInt(data[t:t+DWORD]) - rsrcVirAdress + self.offset)          
            self.part5.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA of Data', ' '.join(vAlue[i])]); t+=DWORD
            self.subRsrcSize.append(data[t:t+DWORD])
            self.part5.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
            self.part5.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Code Page', '']); t+=DWORD
            self.part5.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Reserved', '']); t+=DWORD
            self.part5.append(["==========================",'','',''])
            rsrc_dir_nameid.append(self.part5)
        self.t = t;
        return self.t;

    def rsrcDirString(self, t, d):
        self.part6 = data[t:d]
        
        global rsrcString
        
        a = self.part6
        st = list(a.decode('utf-8'))
        st1 = []
        alpa = []
        ycount = 0

        for x in range(97, 123):#알파벳 소문자 저장
            alpa.append(chr(x))
        for x in range(65, 91):#알파벳 대문자 저장
            alpa.append(chr(x))

        for y in range(0, len(st)):
            if st[y] in alpa:
                st1.append(st[y])
                ycount = 0
            else:
                ycount += 1
                if ycount%3 == 0:
                    st1.append(',')

        st2 = ''.join(st1)
        rsrcString = st2.split(',') # rsrcString에 NameValue 저장됨
        rsrc_dir_nameid.append(rsrcString)
    def subRsrc(self, t):
        self.part7 = []
        self.start = t
        self.subRsrcName = []
        a = 0

        for i in range(0, self.count):
            if vAlue[i][1] == 'NameValue':
                vAlue[i][1] = rsrcString[a]
                a+=1
            b = ' '.join(vAlue[i])
            self.subRsrcName.append(b) # 엔트리 예시 : 'MENU 0001 0412'
            self.part7.append(data[t:t+byteToInt(self.subRsrcSize[i])])
            rsrc_dir_nameid.append(self.part7)
 

    def print(self):
        #print(self.offset, self.all) # SECTION .rsrc 전체 Raw Data 출력

        print('########IMAGE Resource Directory Type########')
        for i in self.part1:
            print(i[0], i[1], i[2], i[3])
        print("==========================")
        check=0
        for i in self.part2:
            print(i[0], i[1], i[2], i[3])
            check+=1
            if check%2==0:
                print("==========================")
        
        print('########IMAGE Resource Directory NameId########')
        for i in self.part3:
            print(i[0], i[1], i[2], i[3])
        
        print('########IMAGE Resource Directory Language########')
        for i in self.part4:
            print(i[0], i[1], i[2], i[3])
        
        print('########IMAGE Resource Data Entry########')
        for i in self.part5:
            print(i[0], i[1], i[2], i[3])

        print()
        print('########IMAGE Resource Directory String########')
        print(self.part6)

        print()
        print('########Sub Entry########')
        for i in range(0, self.count):
            print()
            print('=============  '+self.subRsrcName[i]+'  =============')
            print(self.part7[i])
            print()
        
        
class debugDirectory:
    def __init__(self, offset, size): #TimeDataStamp, Type
        global debugTypeRva, debugTypeSize, debugType
        self.offset=offset
        debugTypeRva.pop()
        t = offset
        self.part1 = []
        self.element = ['Characteristics', 'Time Date Stamp', 'Major Version',
                        'Minor version', 'Type', 'Size of Data',
                         'Address Of Raw Data', 'Pointer to Raw Data']
        debugType = ['IMAGE_DEBUG_TYPE_UNKNOWN',
             'IMAGE_DEBUG_TYPE_COFF',
             'IMAGE_DEBUG_TYPE_CODEVIEW',
             'IMAGE_DEBUG_TYPE_FPO',
             'IMAGE_DEBUG_TYPE_MISC'
             'IMAGE_DEBUG_TYPE_EXCEPTION',
             'IMAGE_DEBUG_TYPE_FIXUP',
             'IMAGE_DEBUG_TYPE_OMAP_TO_SRC',
             'IMAGE_DEBUG_TYPE__OMAP_FROM_SRC',
             'IMAGE_DEBUG_TYPE_BORLAND',
             'IMAGE_DEBUG_TYPE_RESERVED10',
             'IMAGE_DEBUG_TYPE_CLSID',
             'IMAGE_DEBUG_TYPE_','IMAGE_DEBUG_TYPE_','IMAGE_DEBUG_TYPE_','IMAGE_DEBUG_TYPE_']
        while True:
            if offset+size==t:
                break
            subPart = []
            '''self.debugDir.append([data[t:t+DWORD], data[t+DWORD:t+DWORD+WORD], data[t+DWORD+WORD:t+DWORD*2]
                                 ,data[t+DWORD*2:t+DWORD*3], data[t+DWORD*3:t+DWORD*4],
                                 data[t+DWORD*4:t+DWORD*5], data[t+DWORD*5:t+DWORD*6],
                                 data[t+DWORD*6:t+DWORD*7]])
            t+=(DWORD*7)'''
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Charasteristics', '']); t+=DWORD
            BuildTime = timeTrans(byteToInt(data[t:t+DWORD]))
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Time Date Stamp', BuildTime]); t+=DWORD
            subPart.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Major Version', '']); t+=WORD
            subPart.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Minor Version', '']); t+=WORD
            debugTypeNumber.append(byteToInt(data[t:t+DWORD]))
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Type', debugType[byteToInt(data[t:t+DWORD])]]); t+=DWORD
            debugTypeSize.append(byteToInt(data[t:t+DWORD]))
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Data', '']); t+=DWORD
            debugTypeRva.append(byteToInt(data[t:t+DWORD]))
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Address of Raw Data', '']); t+=DWORD
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Pointer to Raw Data', '']); t+=DWORD
            self.part1.append(subPart)
                    
    def print(self):
        print('########Image Debug Directory########')
        for i in self.part1:
            for j in i:
                print(j[0], j[1], j[2], j[3])
        print()

class DebugType:
    def __init__(self, offset, size, type):
        global debugType
        self.offset=offset
        self.part1 = []
        t = offset
        self.type = type
        if type==2:
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Signature', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Guid', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Age', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', data[t:offset+size]]); t+=DWORD            
        else:
            self.info = data[t:offset+size]

    def print(self):
        print('########',debugType[self.type],'########')
        if self.type==2:
            for i in self.part1:
                print(i[0], i[1], i[2], i[3])
        else:
            print(self.info)
        print()
        
class relocSection:
    def __init__(self, offset, size):
        self.part1 = []
        self.offset = offset #정렬 위해 만든 변수
        groupOffset = offset
        relocType = ['IMAGE_REL_BASED_ABSOLUTE', 
             'IMAGE_REL_BASED_HIGH',
             'IMAGE_REL_BASED_LOW',
             'IMAGE_REL_BASED_HIGHLOW',
             'IMAGE_REL_BASED_HIGHADJ',
             'IMAGE_REL_BASED_MACHINE_SPECIFIC_5',
             'IMAGE_REL_BASED_RESERVED',
             'IMAGE_REL_BASED_MACHINE_SPECIFIC_7',
             'IMAGE_REL_BASED_MACHINE_SPECIFIC_8',
             'IMAGE_REL_BASED_MACHINE_SPECIFIC_9',
             'IMAGE_REL_BASED_DIR64',
             'IMAGE_REL_BASED']
        
        while True:
            subPart = [] # Temp에 reloc 그룹 하나씩 저장하고, reloc에 append 한다.
            t = groupOffset
            if offset+size == t:
                break
            rvaOfBlock = byteToInt(data[t:t+DWORD])
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'RVA of Block', '']); t+=DWORD
            groupSize = byteToInt(data[t:t+DWORD])
            subPart.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Block', '']); t+=DWORD
            while True:
                if t == groupOffset+groupSize-WORD:
                    subPart.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'type RVA', '']); t+=WORD
                    groupOffset = t
                    break
                value1 = (byteToInt(data[t:t+WORD]+b'\x00\x00') & 0xF000) / 0x1000
                value2 = byteToInt(data[t:t+WORD]+b'\x00\x00') & 0x0FFF
                subPart.append([pFile(t), wORD(hex(struct.unpack('<l',  data[t:t+WORD]+b'\x00\x00')[0])), 
                                'Type RVA', str(rvaOfBlock+int(value2))+' '+relocType[int(value1)]]); t+=WORD
            self.part1.append(subPart)
            
    def print(self):
        for i in self.part1:
            for j in i:
                print(j[0], j[1], j[2], j[3])
            print('==========================')
        print()

class TlsTable:
    def __init__(self, offset, size):
        self.offset=offset
        self.part1 = []
        t = offset
        if BIT==32:
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Start Address of Raw Data', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'End Address of Raw Data', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Address of Index', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Address of Callbacks', '']); t+=DWORD
        if BIT==64:
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Start Address of Raw Data', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'End Address of Raw Data', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Address of Index', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Address of Callbacks', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size of Zero Fill', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Characteristics', '']); t+=DWORD
                    
    def print(self):
        print('########Image Directory Entry TLS########')
        for i in self.part1:
            print(i[0], i[1], i[2], i[3])
        print()

class LoadConfig:
    def __init__(self, offset, size):
        global BIT, dllChar
        self.offset=offset
        self.part1 = []
        t = offset
        dType = getDType()
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Size', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Time Data Stamp', '']); t+=DWORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Major Version', '']); t+=WORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Start Address of Raw Data', '']); t+=WORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Global Flags Clear', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Global Flags Set', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Critical Section Default Timeout', '']); t+=DWORD
        if BIT==32:
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'DeCommit Free Block Threshold', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'DeCommit Total Free Threshold', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Lock Prefix Table', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Maximum Allocation Size', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Virtual Memory Threshold', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Process Affinity Mask', '']); t+=DWORD
        if BIT==64:
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'DeCommit Free Block Threshold', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'DeCommit Total Free Threshold', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Lock Prefix Table', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Maximum Allocation Size', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Virtual Memory Threshold', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Process Affinity Mask', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
        
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Process Heap Flags', '']); t+=DWORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'CSE Version', '']); t+=WORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Reserved1', '']); t+=WORD
        if BIT==32:
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Edit List', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Security Cookie', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'SE Handler Table', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'SE Handler Count', '']); t+=DWORD
        if BIT==64:
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Edit List', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Security Cookie', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'SE Handler Table', '']); t+=DWORD
            self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'SE Handler Count', '']); t+=DWORD     
            self.part1.append([pFile(t), '', '', '']); t+=DWORD

        if dllChar & 0x4000 == 0x4000:
            if BIT==32:
                self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Guard CF Check Function Pointer', '']); t+=DWORD
                self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Guard CF Dispatch Function Pointer', '']); t+=DWORD
                self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Guard CF Function Table', '']); t+=DWORD
                self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Guard CF Function Count', '']); t+=DWORD
            if BIT==64:
                self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Guard CF Check Function Pointer', '']); t+=DWORD
                self.part1.append([pFile(t), '', '', '']); t+=DWORD
                self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Guard CF Dispatch Function Pointer', '']); t+=DWORD
                self.part1.append([pFile(t), '', '', '']); t+=DWORD
                self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Guard CF Function Table', '']); t+=DWORD
                self.part1.append([pFile(t), '', '', '']); t+=DWORD
                self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Guard CF Function Count', '']); t+=DWORD
                self.part1.append([pFile(t), '', '', '']); t+=DWORD
            self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Guard Flags', '']); t+=DWORD
            
    def print(self):
        print('########Image Load Config Directory########')
        for i in self.part1:
           print(i[0], i[1], i[2], i[3])
        print()       
         
class CliHeader:
    def __init__(self, offset, size):
        self.offset=offset
        self.part1=[]
        t = offset
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'cb', '']); t+=DWORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Major Runtime Version', '']); t+=WORD
        self.part1.append([pFile(t), wORD(hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0])), 'Major Runtime Version', '']); t+=WORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Metadata', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Flags', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'EntryPoint', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Resources', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Strong Name Signature', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Code Manager Table', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Vtable Fixups', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Export Address Table Jumps', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), 'Managed Native Header', '']); t+=DWORD
        self.part1.append([pFile(t), dWORD(hex(struct.unpack('<l', data[t:t+DWORD])[0])), '', '']); t+=DWORD
        
    def print(self):
        print('########Image Cor20 Header########')
        for i in self.part1:
            print(i[0], i[1], i[2], i[3])
        print()
############################################################################################################################################################
# CertificateTable
############################################################################################################################################################  
class CertificateTable:
    def __init__(self):
        global dirRva, dirSize
        self.offset = dirRva[4]
        self.size = dirSize[4]
        self.all = data[self.offset:self.offset+self.size]
    def print(self):
        print("########Certificate Table########")
        print(self.all)
        print()

        
        
###Main Class###

# f = open("C:\\Users\\lisas\\Desktop\\DEBUG\\프젝 도구\\notepad.exe", 'rb')
#f = open("C:\Program Files (x86)\AquaNPlayer\AquaAgent.exe", 'rb')
#f = open("C:\Program Files (x86)\ESTsoft\ALZip\ALZip.exe", 'rb')
#f= open("C:\Program Files\Bandizip\Bandizip.exe", 'rb')
path = input('경로를 입력해주세요 : ')
f = open(path, 'rb')
t = 0x0
data = f.read()
DosHeaderInfo = DosHeader(t)
DosHeaderInfo.print()
NTHeaderAddress = byteToInt(DosHeaderInfo.getE_lfanew()) #e_lfanew에 NTHeaderAddress의 주소가 있다

DosStubInfo = DosStub(DosHeaderInfo.getT(), NTHeaderAddress)
DosStubInfo.print()

NTHeaderInfo = NTHeader(NTHeaderAddress)
NTHeaderInfo.print()

SecNumber = byteToInt(b'\x00\x00'+NTHeaderInfo.getNumberOfSections())
SecHeaderInfo = SectionHeader(NTHeaderInfo.getT(), SecNumber)
SecHeaderInfo.print()

if dirRva[11] !=0 :
    BoundedInfo = BoundedImport()
    BoundedInfo.print()

SectionInfo = []
for i in range (0, SecNumber):
    SectionInfo.append(Section(headerRva[i], headerSize[i], i, headerPToRawData[i]))

for i in SectionInfo:
    i.print()

if dirRva[4] !=0 :
    CertificateInfo = CertificateTable()
    CertificateInfo.print()

# print("****rsrc_dir_nameid********************")
# print(rsrc_dir_nameid)
# print(image_rscr_directory_type)
    
f.close()