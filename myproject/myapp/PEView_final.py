# -*- coding: utf-8 -*-
"""
PE Viewer
"""
import struct
import sys
import datetime
import copy

BYTE = 1
WORD = 2 
DWORD = 4
ULONGLONG = 8
BIT = 0

dostub_list=[]
rva_list=[]

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

debugTypeRva = [0]
debugTypeSize = []
debugTypeNumber = []
intRva = 0
iatRva = 0
intRvaList = [0]
iatRvaList = [0]
importDllNameRvaList = [0]

delayIntRva = 0
delayIatRva = 0
delayDllNameRvaList = [0]
delayDllFuncRvaList = [0]
delayIatRvaList = [0]
delayIntRvaList = [0]

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
             'IMAGE_REL_BASED_DIR64']

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
    timeStr = '1970-01-01 09:00:00'
    thisTime = datetime.datetime.strptime(timeStr, '%Y-%m-%d %H:%M:%S')
    lastBuildTime = thisTime + datetime.timedelta(seconds=timeDateStamp)
    return lastBuildTime

def getDType():
   if BIT==32:
       return DWORD
   elif BIT==64:
       return ULONGLONG

class DosHeader:
    def __init__(self, t):
        try:
            self.part1 = []
            self.e_magic = data[t:t+WORD]      
            if self.e_magic != b'MZ':
                raise isNotMZ
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Signature', 'IMAGE_DOS_SIGNATURE MZ']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Bytes on Last Page of File', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Pages in File', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Relocations', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Size of Headers in Paragraphs', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Minimum Extra Paragraphs', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Maximum Extra Paragraphs', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Initial (relative) SS', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Initial SP', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Checksum', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Initial IP', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Initial (relative) CS', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Offset to Relocation Table', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Overlay Number', '']); t+=WORD
            for i in range(0, 4):
                self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Reserved', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'OEM Identifier', '']); t+=WORD
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'OEM Information', '']); t+=WORD
            for i in range(0, 10):
                self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Reserved', '']); t+=WORD
            self.e_lfanew = data[t:t+DWORD]
            self.part1.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Offset to New Exe Header', '']); t+=DWORD
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
            self.part1 = [hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Signature', 'IMAGE_NT_SIGNATURE PE']
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
            
            self.part2.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'machine', machine]); t+=WORD
            self.NumberOfSections = data[t:t+WORD]
            self.part2.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Number Of Section', '']); t+=WORD
            BuildTime = timeTrans(byteToInt(data[t:t+DWORD]))
            self.part2.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Time Date Stamp', BuildTime]); t+=DWORD
            self.part2.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Pointer To Symbol Table', '']); t+=DWORD
            self.part2.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Number of Symbols', '']); t+=DWORD
            self.part2.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'size of Optional Header', '']); t+=WORD
            self.part2.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Characteristics', ''])
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
                self.part2.append(['','' , 0x0001, charType[0]])
            if flag & 0x0002:
                self.part2.append(['','' , 0x0002, charType[1]])
            if flag & 0x0004:
                self.part2.append(['','' , 0x0004, charType[2]])   
            if flag & 0x0008:
                self.part2.append(['','' , 0x0008, charType[3]])
            if flag & 0x0010:
                self.part2.append(['','' , 0x0010, charType[4]])
            if flag & 0x0020:
                self.part2.append(['','' , 0x0020, charType[5]])
            if flag & 0x0080:
                self.part2.append(['','' , 0x0080, charType[6]])
            if flag & 0x0100:
                self.part2.append(['','' , 0x0100, charType[7]])
            if flag & 0x0200:
                self.part2.append(['','' , 0x0200, charType[8]])
            if flag & 0x0400:
                self.part2.append(['','' , 0x0400, charType[9]])
            if flag & 0x0800:
                self.part2.append(['','' , 0x0800, charType[10]])
            if flag & 0x1000:
                self.part2.append(['','' , 0x1000, charType[11]])
            if flag & 0x2000:
                self.part2.append(['','' , 0x2000, charType[12]])
            if flag & 0x4000:
                self.part2.append(['','' , 0x4000, charType[13]])
            if flag & 0x8000:
                self.part2.append(['','' , 0x8000, charType[14]])
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
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Magic', value]); t+=WORD
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+BYTE]+b'\x00\x00\x00')[0]), 'Major Linker Version', '']); t+=BYTE
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+BYTE]+b'\x00\x00\x00')[0]), 'Minor Linker Version', '']); t+=BYTE
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size of Code', '']); t+=DWORD
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size of Initialized Data', '']); t+=DWORD
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size of Uninitialized Data', '']); t+=DWORD
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Address of Entry Point', '']); t+=DWORD   
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Base of Code', '']); t+=DWORD   
            if BIT == 32:
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Base of Data', '']); t+=DWORD   
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'ImageBase', '']); t+=DWORD       
            elif BIT == 64:
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'ImageBase', '']); t+=DWORD   
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), '', '']); t+=DWORD 
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Section Alignment', '']); t+=DWORD  
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'File Alignment', '']); t+=DWORD 
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Major O/S Version', '']); t+=WORD
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Minor O/S Version', '']); t+=WORD
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Major Image Version', '']); t+=WORD
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Minor Image Version', '']); t+=WORD
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Major Subsystem Version', '']); t+=WORD
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Minor Subsystem Version', '']); t+=WORD
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Win32 Version Value', '']); t+=DWORD 
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size Of Image', '']); t+=DWORD 
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size Of Headers', '']); t+=DWORD 
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Checksum', '']); t+=DWORD
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
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Subsystem', 
                               subSystemValue[byteToInt(data[t:t+WORD]+b'\x00\x00')]]); t+=WORD
            dllChar = byteToInt(data[t:t+WORD]+b'\x00\x00')
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+WORD]+b'\x00\x00')[0]), 'Dll characteries', '']); t+=WORD
                               
            flag = byteToInt(data[t:t+WORD]+b'\x00\x00')
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
            if flag & 0x0020:
                self.part3.append(['','' , 0x0020, DllCharaEnt[0]])
            if flag & 0x0040:
                self.part3.append(['','' , 0x0040, DllCharaEnt[1]])
            if flag & 0x0080:
                self.part3.append(['','' , 0x0080, DllCharaEnt[2]])   
            if flag & 0x0100:
                self.part3.append(['','' , 0x0100, DllCharaEnt[3]])
            if flag & 0x0200:
                self.part3.append(['','' , 0x0200, DllCharaEnt[4]])
            if flag & 0x0400:
                self.part3.append(['','' , 0x0400, DllCharaEnt[5]])
            if flag & 0x0800:
                self.part3.append(['','' , 0x0800, DllCharaEnt[6]])
            if flag & 0x1000:
                self.part3.append(['','' , 0x1000, DllCharaEnt[7]])
            if flag & 0x2000:
                self.part3.append(['','' , 0x2000, DllCharaEnt[8]])
            if flag & 0x4000:
                self.part3.append(['','' , 0x4000, DllCharaEnt[9]])
            if flag & 0x8000:
                self.part3.append(['','' , 0x8000, DllCharaEnt[10]])

            if BIT==32:
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size of Stack Reverse', '']); t+=DWORD
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size of Stack Commit', '']); t+=DWORD
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size of Heap Reverse', '']); t+=DWORD 
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size of Heap Commit', '']); t+=DWORD 
            elif BIT==64:
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size of Stack Reverse', '']); t+=DWORD
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), '', '']); t+=DWORD
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size of Stack Commit', '']); t+=DWORD
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), '', '']); t+=DWORD
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size of Heap Reverse', '']); t+=DWORD 
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), '', '']); t+=DWORD
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size of Heap Commit', '']); t+=DWORD 
                self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), '', '']); t+=DWORD
            
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Loader Flags', '']); t+=DWORD 
            self.part3.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Number of Data Directories', '']); t+=DWORD 
            
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'EXPORT Table'])
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'EXPORT Table'])
            t+=DWORD
           
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'IMPORT Table'])
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'IMPORT Table'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'RESOURCE Table'])
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'RESOURCE Table'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'EXCEPTION Table']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'EXCEPTION Table'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'CERTIFICATE Table']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'CERTIFICATE Table'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'BASE RELOCATION Table']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'BASE RELOCATION Table'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'DEBUG Directoty']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'DEBUG Directoty'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'Architecture Specific Data']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'Architecture Specific Data'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'GLOBAL POINTER Register']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'GLOBAL POINTER Register'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'TLS Table']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'TLS Table'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'LOAD CONFIGURATION Table']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'LOAD CONFIGURATION Table'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'BOUND IMPORT Table']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'BOUND IMPORT Table'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'IMPORT Address Table']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'IMPORT Address Table'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'Delay IMPORT Descriptors']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'Delay IMPORT Descriptors'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'CLI Header']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'RVA', 'CLI Header'])
            t+=DWORD
            self.part4.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', '']); 
            rva_list.append([hex(t), hex(struct.unpack('<l', data[t:t+DWORD])[0]), 'Size', ''])
            t+=DWORD
            self.part4.append(['', '', '', '']); 
            rva_list.append(['', '', '', ''])
            t+=DWORD
            self.part4.append(['', '', '', '']); 
            rva_list.append(['', '', '', ''])
            t+=DWORD
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
        for i in range(1, SecNumber+1):
            self.SecHeader.append([data[t:t+DWORD*2], data[t+DWORD*2:t+DWORD*3], data[t+DWORD*3:t+DWORD*4],
                             data[t+DWORD*4:t+DWORD*5], data[t+DWORD*5:t+DWORD*6], data[t+DWORD*6:t+DWORD*7], data[t+DWORD*7:t+DWORD*8],
                             data[t+DWORD*8:t+DWORD*8+WORD], data[t+DWORD*8+WORD:t+DWORD*9], data[t+DWORD*9:t+DWORD*10]])
            headerRva.append(byteToInt(self.SecHeader[i-1][2]))
            headerPToRawData.append(byteToInt(self.SecHeader[i-1][4]))
            headerSize.append(byteToInt(self.SecHeader[i-1][3]))
            secName.append((data[t:t+DWORD].decode('ISO-8859-1') + data[t+DWORD:t+DWORD*2].decode('ISO-8859-1')))
            t+=(DWORD*10)
            
    def print(self):
        print('########Section Header########')
        for i in self.SecHeader:
            print('Name: ', i[0])
            print('Virtual Size: ', i[1])
            print('RVA: ', i[2])
            print('Size of Raw Data: ', i[3])
            print('Pointer to Raw Data: ', i[4])
            print('Pointer to Relocations: ', i[5])
            print('Pointer to Line Number: ', i[6])
            print('Number of Relocations: ', i[7])
            print('Number of Line Numbers: ', i[8])
            print('Characteristics: ', i[9])
            print("==========================")
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
        t = self.offset
        while True:
            self.idt.append([data[t:t+DWORD], data[t+DWORD:t+DWORD+WORD], data[t+DWORD+WORD:t+DWORD*2]])
            if byteToInt(data[t:t+DWORD]) == 0:
                t+=(DWORD*2)
                break
            t+=(DWORD*2)
        return t

    def BoundedName(self, t):
        self.info = data[t:self.offset+self.size]
    
    def print(self):
        print('########Bounded Import Directory Table########')
        for i in self.idt:
            for j in range(0, 3):
                print(i[j], self.element[j])
            print('==========================')
        print()
        print('########Bounded Import Dll Names########')
        print(self.info)

class Section:
    def __init__(self, rva, size, secNum, pToRawData):
        global dirRva, secName, debugTypeRva, debugTypeSize, debugType, countDebug, intRvaList, importDllNameRvaList
        global delayIatRvaList, delayIntRvaList, delayDllNameRvaList, delayDllFuncRvaList
        self.SecPartOffset = []
        self.secNum = secNum
        self.SecPart = [] 
        if (dirRva[0] >= rva) and (dirRva[0] <= rva+size):
            self.SecPart.append(exportTable(rvaToOffset(dirRva[0], rva, pToRawData), dirSize[0], rva, pToRawData)) #구현완료
        #if (dirRva[1] >= rva) and (dirRva[1] <= rva+size):
        #    self.SecPart.append(ImportTable(rvaToOffset(dirRva[1], rva, pToRawData), dirSize[1])) #구현완료
        if (dirRva[2] >= rva) and (dirRva[2] <= rva+size):
            self.SecPart.append(resourceTable(rvaToOffset(dirRva[2], rva, pToRawData), dirSize[2])) #소연님이 구현하실 리소스 테이블
        if (dirRva[3] >= rva) and (dirRva[3] <= rva+size):
            self.SecPart.append(RuntimeFunction(rvaToOffset(dirRva[3], rva, pToRawData), dirSize[3])) #구현 완료         
        #if (dirRva[4] >= rva) and (dirRva[4] <= rva+size) #별도 구현(구현 완료)
        #if (dirRva[5] >= rva) and (dirRva[5] <= rva+size):
        #    self.SecPart.append(relocSection(rvaToOffset(dirRva[5], rva, pToRawData), dirSize[5])) #구현완료(출력이 많다, 다른 것 테스트 할 때 이부분 주석)
        if (dirRva[6] >= rva) and (dirRva[6] <= rva+size):
            self.SecPart.append(debugDirectory(rvaToOffset(dirRva[6], rva, pToRawData), dirSize[6])) #구현완료
        #if (dirRva[7] >= rva) and (dirRva[7] <= rva+size): #일반 윈도우에서 사용하지 않는다, 구현 생략
        #if (dirRva[8] >= rva) and (dirRva[8] <= rva+size): #일반 윈도우에서 사용하지 않는다, 구현 생략
        if (dirRva[9] >= rva) and (dirRva[9] <= rva+size):
            self.SecPart.append(TlsTable(rvaToOffset(dirRva[9], rva, pToRawData), dirSize[9])) #구현완료
        #if (dirRva[10] >= rva) and (dirRva[10] <= rva+size):
        #    self.SecPart.append(LoadConfig(rvaToOffset(dirRva[10], rva, pToRawData), dirSize[10])) #구현완료
        #if (dirRva[11] >= rva) and (dirRva[11] <= rva+size) #별도 구현(구현 완료)       
        #if (dirRva[12] >= rva) and (dirRva[12] <= rva+size):
        #    self.SecPart.append(ImportAddressTable(rvaToOffset(dirRva[12], rva, pToRawData), dirSize[12])) #별도 구현(구현완료)  
        if (dirRva[13] >= rva) and (dirRva[13] <= rva+size):
            self.SecPart.append(DelayImport(rvaToOffset(dirRva[13], rva, pToRawData), dirSize[13])) #구현완료      
        if (dirRva[14] >= rva) and (dirRva[14] <= rva+size):
            self.SecPart.append(CliHeader(rvaToOffset(dirRva[14], rva, pToRawData), dirSize[14])) #구현완료
        for i in debugTypeRva:
            if (i >= rva) and (i <= rva+size):
                self.SecPart.append(DebugType(rvaToOffset(i, rva, pToRawData), debugTypeSize[countDebug], debugTypeNumber[countDebug]))
                countDebug+=1
        
        #if (intRvaList[0] >= rva) and (intRvaList[0] <= rva+size):
        #    self.SecPart.append(ImportNameTable(rva, pToRawData))
        #if (iatRvaList[0] >= rva) and (iatRvaList[0] <= rva+size):
        #    self.SecPart.append(ImportAddressTable(rva, pToRawData))        
        #if (min(importDllNameRvaList)>= rva) and (min(importDllNameRvaList) <= rva+size):
        #    self.SecPart.append(ImportHintsAndNames(rva, pToRawData))
        #if (delayIatRvaList[0] >= rva) and (delayIatRvaList[0] <= rva+size):
        #    self.SecPart.append(DelayImportAddressTable(rva, pToRawData)) 
        #if (delayIntRvaList[0] >= rva) and (delayIntRvaList[0] <= rva+size):
        #    self.SecPart.append(DelayImportNameTable(rva, pToRawData))
        #if (min(delayDllNameRvaList)>=rva) and (min(delayDllNameRvaList) <= rva+size):
        #    self.SecPart.append(DelayImportName(rva, pToRawData))
        #if (min(delayDllFuncRvaList)>=rva) and (min(delayDllFuncRvaList) <= rva+size):
        #    self.SecPart.append(DelayImportHintsAndNames(rva, pToRawData))    

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
        self.Characteristic = data[t:t+DWORD]; t+=DWORD;    self.TimeDateStamp = data[t:t+DWORD];   t+=DWORD;
        self.MajorVersion = data[t:t+WORD]; t+=WORD;        self.MinorVersion = data[t:t+WORD];     t+=WORD;
        self.Name = data[t:t+DWORD]; t+=DWORD;              self.Base = data[t:t+DWORD]; t+=DWORD;
        self.NumberOfFunctions = data[t:t+DWORD]; t+=DWORD; self.NumberOfNames = data[t:t+DWORD]; t+=DWORD;
        self.AddressOfFunctions = data[t:t+DWORD]; t+=DWORD; self.AddressOfNames = data[t:t+DWORD]; t+=DWORD;
        self.AddressOfNameOrdinals = data[t:t+DWORD]; t+=DWORD;
        return t
    
    def ExportAddressTable(self, t):
        self.functionRVA = []
        number = byteToInt(self.NumberOfFunctions)
        for i in range(1, number+1):
            self.functionRVA.append(data[t:t+DWORD])
            t+=DWORD
        return t
    
    def ExportNamePointerTable(self, t):
        self.functionNameRVA = []
        number = byteToInt(self.NumberOfNames)
        for i in range(1, number+1):
            self.functionNameRVA.append(data[t:t+DWORD])
            t+=DWORD
        return t

    def ExportOrdinalTable(self, t):
        self.functionOrdinal = []
        number = byteToInt(self.NumberOfFunctions)
        for i in range(1, number+1):
            self.functionOrdinal.append(data[t:t+WORD])
            t+=WORD
        return t

    def ExportName(self, t):
        self.info = data[t:self.offset+self.size]
        return t

    def print(self):
        print('########Image Export Directory########')
        print('Characteristic', self.Characteristic);    print('TimeDateStamp', self.TimeDateStamp)
        print('MajorVersion', self.MajorVersion);        print('MinorVersion', self.MinorVersion)
        print('Name', self.Name);                        print('Base', self.Base)
        print('NumberOfFunctions', self.NumberOfFunctions); print('NumberOfNames ', self.NumberOfNames)
        print('AddressOfFunctions', self.AddressOfFunctions); print('AddressOfNames', self.AddressOfNames)
        print('AddressOfNameOrdinals', self.AddressOfNameOrdinals)
        print()
        print('########Export Address Table########')
        for i in self.functionRVA:
            print(i)
        print()
        print('########Export Name Pointer Table########')
        for i in self.functionNameRVA:
            print(i)
        print()
        print('########Export Odrinal Table########')
        for i in self.functionOrdinal:
            print(i)
        print()
        print('########Export Name########')
        print(self.info)
        print()

class ImportTable:
    def __init__(self, offset, size):
        global intRvaList, importDllNameRvaList, iatRvaList
        self.offset=offset
        intRvaList.pop()
        importDllNameRvaList.pop()
        iatRvaList.pop()
        self.imp = []
        self.element = ['Import Name Table RVA', 'Time Date Stamp', 'Forwarder Chain',
                        'Name RVA', 'Import Address Table RVA']
        t = offset
        while t < offset+size:
            self.imp.append([data[t:t+DWORD], data[t+DWORD:t+DWORD*2], data[t+DWORD*2:t+DWORD*3]
                                ,data[t+DWORD*3:t+DWORD*4], data[t+DWORD*4:t+DWORD*5]])
            if data[t:t+DWORD] != b'\x00\x00\x00\x00':
                intRvaList.append(byteToInt(data[t:t+DWORD]))
            if data[t+DWORD*3:t+DWORD*4] != b'\x00\x00\x00\x00':
                importDllNameRvaList.append(byteToInt(data[t+DWORD*3:t+DWORD*4]))
            if data[t+DWORD*4:t+DWORD*5] != b'\x00\x00\x00\x00':
                iatRvaList.append(byteToInt(data[t+DWORD*4:t+DWORD*5]))
            t+=(DWORD*5)
        intRvaList.sort()
        iatRvaList.sort()
        
    def print(self):
        print('########Import Directory Table########')
        for i in self.imp:
            for j in range(0, 5):
                print(i[j], self.element[j])
            print('==========================')
        print()

class ImportNameTable:
    def __init__(self, rva, pToRawData):
        global intRva, intRvaList
        self.intDir = []
        self.offset = rvaToOffset(intRvaList[0], rva, pToRawData)
        intRva = intRvaList[0]
        for i in intRvaList:
            intDirTemp = []
            t = rvaToOffset(i, rva, pToRawData)
            while True:
                intDirTemp.append(data[t:t+DWORD])
                if(data[t:t+DWORD]) == b'\x00\x00\x00\x00':
                    break
                t+=DWORD
            self.intDir.append(intDirTemp)
    
    def print(self):
        print('########Image Name Table########')
        for i in self.intDir:
            for j in i:
                if j == b'\x00\x00\x00\x00':
                    print(j, 'End of Imports')
                    print("==========================")
                else:
                    k = byteToInt(j)
                    if k & 0x80000000:
                        print(j, 'Ordinal')
                    elif k & 0x70000000:
                        print(j, 'Virtual Address')
                    else:
                        print(j, 'Hint/Name RVA')
        print()

class ImportAddressTable:
    def __init__(self, rva, pToRawData):
        global iatRva, iatRvaList
        self.iatDir = []
        self.offset = rvaToOffset(iatRvaList[0], rva, pToRawData)
        iatRva = iatRvaList[0]
        for i in iatRvaList:
            iatDirTemp = []
            t = rvaToOffset(i, rva, pToRawData)
            while True:
                iatDirTemp.append(data[t:t+DWORD])
                if(data[t:t+DWORD]) == b'\x00\x00\x00\x00':
                    break
                t+=DWORD
            self.iatDir.append(iatDirTemp)
    
    def print(self):
        print('########Import Address Table########')
        for i in self.iatDir:
            for j in i:
                if j == b'\x00\x00\x00\x00':
                    print(j, 'End of Imports')
                    #print("==========================")
                else:
                    k = byteToInt(j)
                    if k & 0x80000000:
                        print(j, 'Ordinal')
                    elif k & 0x70000000:
                        print(j, 'Virtual Address')
                    else:
                        print(j, 'Hint/Name RVA')
        print()
            
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
    def __init__(self, offset, size):
        global delayDllNameRvaList, delayIatRvaList, delayIntRvaList
        self.offset = offset
        delayDllNameRvaList.pop()
        delayIatRvaList.pop()
        delayIntRvaList.pop()
        self.dimp = []
        self.element = ['Attributes', 'RVA to DLL Name', 'RVA to HMODULE',
                        'RVA to Import Address Table', 'RVA to Import Name Table'
                        , 'RVA to Bound IAT', 'RVA to Unload IAT', 'Time Date Stamp']
        t = offset
        while t < offset+size:
            self.dimp.append([data[t:t+DWORD], data[t+DWORD:t+DWORD*2], data[t+DWORD*2:t+DWORD*3]
                             ,data[t+DWORD*3:t+DWORD*4], data[t+DWORD*4:t+DWORD*5], data[t+DWORD*5:t+DWORD*6], 
                             data[t+DWORD*6:t+DWORD*7], data[t+DWORD*7:t+DWORD*8]])
            if data[t+DWORD:t+DWORD*2] != b'\x00\x00\x00\x00':
                delayDllNameRvaList.append(byteToInt(data[t+DWORD:t+DWORD*2]))
            if data[t+DWORD*3:t+DWORD*4] != b'\x00\x00\x00\x00':
                delayIatRvaList.append(byteToInt(data[t+DWORD*3:t+DWORD*4]))
            if data[t+DWORD*4:t+DWORD*5] != b'\x00\x00\x00\x00':
                delayIntRvaList.append(byteToInt(data[t+DWORD*4:t+DWORD*5]))
            t+=(DWORD*8)
        delayIatRvaList.sort()
        delayIntRvaList.sort()
        
    def print(self):
        print('########Delay Import Descriptors########')
        for i in self.dimp:
            for j in range(0, 8):
                print(i[j], self.element[j])
            print('==========================')
        print()    

class DelayImportNameTable:
    def __init__(self, rva, pToRawData):
        global delayIntRva, delayIntRvaList, delayDllFuncRvaList
        self.offset = rvaToOffset(delayDllFuncRvaList[0], rva, pToRawData)
        if delayDllFuncRvaList[0]==0:
            delayDllFuncRvaList.pop()
        self.delayIntDir = []
        delayIntRva = delayIntRvaList[0]
        for i in delayIntRvaList:
            delayIntDirTemp = []
            t = rvaToOffset(i, rva, pToRawData)
            while True:
                delayIntDirTemp.append(data[t:t+DWORD])
                if(data[t:t+DWORD]) == b'\x00\x00\x00\x00':
                    break
                else:
                    if byteToInt(data[t:t+DWORD]) < 0x20000000:
                        delayDllFuncRvaList.append(byteToInt(data[t:t+DWORD]))
                t+=DWORD
            self.delayIntDir.append(delayIntDirTemp)
            
    
    def print(self):
        print('########Delay Import Name Table########')
        for i in self.delayIntDir:
            for j in i:
                if j == b'\x00\x00\x00\x00':
                    print(j, 'End of Imports')
                    print("==========================")
                else:
                    k = byteToInt(j)
                    if k & 0x80000000:
                        print(j, 'Ordinal')
                    elif k & 0x70000000:
                        print(j, 'Virtual Address')
                    else:
                        print(j, 'Hint/Name RVA')
        print()

class DelayImportAddressTable:
    def __init__(self, rva, pToRawData):
        global delayIatRva, delayIatRvaList, delayDllFuncRvaList
        self.offset = rvaToOffset(delayDllFuncRvaList[0], rva, pToRawData)
        if delayDllFuncRvaList[0]==0:
            delayDllFuncRvaList.pop()
        self.delayIatDir = []
        delayIatRva = delayIatRvaList[0]
        for i in delayIatRvaList:
            delayIatDirTemp = []
            t = rvaToOffset(i, rva, pToRawData)
            print(t)
            while True:
                delayIatDirTemp.append(data[t:t+DWORD])
                if(data[t:t+DWORD]) == b'\x00\x00\x00\x00':
                    break
                else:
                    if byteToInt(data[t:t+DWORD]) < 0x20000000:
                        delayDllFuncRvaList.append(byteToInt(data[t:t+DWORD]))
                    delayDllFuncRvaList.append(byteToInt(data[t:t+DWORD]))  
                t+=DWORD
            self.delayIatDir.append(delayIatDirTemp)
    
    def print(self):
        print('########Delay Import Name Table########')
        for i in self.delayIatDir:
            for j in i:
                if j == b'\x00\x00\x00\x00':
                    print(j, 'End of Imports')
                    print("==========================")
                else:
                    k = byteToInt(j)
                    if k & 0x80000000:
                        print(j, 'Ordinal')
                    else:
                        print(j, 'Virtual Address')
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

class RuntimeFunction:
    def __init__(self, offset, size):
        self.offset=offset
        t = offset
        self.BeginAddress = data[t:t+DWORD]; t+=DWORD;      self.EndAddress = data[t:t+DWORD]; t+=DWORD; 
        self.Unwind = data[t:t+DWORD]; t+=DWORD;
    
    def print(self):
        print('########Image Runtime Function Entry########')
        print(self.BeginAddress, 'BeginAddress');         print(self.EndAddress, 'EndAddress')
        print(self.Unwind, 'unwind')
        
class resourceTable:
    def __init__(self, offset, size):
        self.offset=offset
        t = offset
        print()
        
    def print(self):
        print('구현중')
        
class debugDirectory:
    def __init__(self, offset, size): #TimeDataStamp, Type
        global debugTypeRva, debugTypeSize, debugType
        self.offset=offset
        debugTypeRva.pop()
        t = offset
        self.debugDir = []
        self.element = ['Characteristics', 'Time Date Stamp', 'Major Version',
                        'Minor version', 'Type', 'Size of Data',
                         'Address Of Raw Data', 'Pointer to Raw Data']
        while True:
            if offset+size==t:
                break
            self.debugDir.append([data[t:t+DWORD], data[t+DWORD:t+DWORD+WORD], data[t+DWORD+WORD:t+DWORD*2]
                                 ,data[t+DWORD*2:t+DWORD*3], data[t+DWORD*3:t+DWORD*4],
                                 data[t+DWORD*4:t+DWORD*5], data[t+DWORD*5:t+DWORD*6],
                                 data[t+DWORD*6:t+DWORD*7]])
            t+=(DWORD*7)
        for i in self.debugDir:
            debugTypeRva.append(byteToInt(i[6]))
            debugTypeSize.append(byteToInt(i[5]))
            debugTypeNumber.append(byteToInt(i[4]))
                    
    def print(self):
        print('########Image Debug Directory########')
        for i in self.debugDir:
            for j in range(0, 8):
                print(i[j], self.element[j])
        print()

class DebugType:
    def __init__(self, offset, size, type):
        global debugType
        self.offset=offset
        t = offset
        self.type = type
        if type==2:
            self.Signature = data[t:t+DWORD];   t+=DWORD;   self.Guid = data[t:t+16];   t+=16;
            self.Age = data[t:t+DWORD];   t+=DWORD;         self.PdbFileName = data[t:offset+size];
        else:
            self.info = data[t:offset+size]
    def print(self):
        print('########',debugType[self.type],'########')
        if self.type==2:
            print(self.Signature, 'Signature'),     print(self.Guid, 'Guid')
            print(self.Age, 'Age'),                 print(self.PdbFileName, 'PdbFileName')
        else:
            print(self.info)
        print()
        
class relocSection:
    def __init__(self, offset, size):
        self.reloc = []
        self.offset = offset
        groupOffset = offset
        while True:
            relocTemp = [] # Temp에 reloc 그룹 하나씩 저장하고, reloc에 append 한다.
            t = groupOffset
            if offset+size == t:
                break
            relocTemp.append(data[t:t+DWORD]);    t+=DWORD
            groupSize = byteToInt(data[t:t+DWORD])
            relocTemp.append(data[t:t+DWORD]);    t+=DWORD
            while True:
                relocTemp.append(data[t:t+WORD]); t+=WORD
                if t == groupOffset+groupSize:
                    groupOffset = t
                    break
            self.reloc.append(relocTemp)
            
    def print(self):
        for i in self.reloc:
            print('RVA of Block: ', i[0])
            print('Size of BlocK: ', i[1])
            for j in range (2, len(i)):
                value1 = (byteToInt(b'\x00\x00'+i[j]) & 0xF000) / 0x1000
                value2 = (byteToInt(b'\x00\x00'+i[j]) & 0x0FFF)
                print(i[j], ': ', hex((byteToInt(i[0])+int(value2))), relocType[int(value1)])
            print("==========================")    
        print()

class TlsTable:
    def __init__(self, offset, size):
        self.offset=offset
        t = offset
        dType = getDType()
        self.StartAddressOfRawData = data[t:t+dType]; t+=dType;     self.EndAddressOfRawData = data[t:t+dType]; t+=dType
        self.AddressOfIndex = data[t:t+dType]; t+=dType;            self.AddressOfCallBacks = data[t:t+dType]; t+=dType
        self.SizeOfZeroFill = data[t:t+DWORD]; t+=DWORD;            self.Characteristics = data[t:t+DWORD]; t+=DWORD
        
    def print(self):
        print('########Image Directory Entry TLS########')
        print('StartAddressOfRawData', self.StartAddressOfRawData);  print('EndAddressOfRawData', self.EndAddressOfRawData)
        print('AddressOfIndex', self.AddressOfIndex);                print('AddressOfCallBacks', self.AddressOfCallBacks)
        print('SizeOfZeroFill', self.SizeOfZeroFill);                print('Characteristics', self.Characteristics)
        print()

class LoadConfig:
    def __init__(self, offset, size):
        global BIT, dllChar
        self.offset=offset
        t = offset
        dType = getDType()
        
        self.size = data[t:t+DWORD]; t+=DWORD;             self.TimeDateStamp = data[t:t+DWORD]; t+=DWORD;
        self.MajorVersion = data[t:t+WORD]; t+=WORD;       self.MinorVersion = data[t:t+WORD]; t+=WORD;
        self.GlobalFlagsClear = data[t:t+DWORD]; t+=DWORD; self.GlobalFlagsSet = data[t:t+DWORD]; t+=DWORD;
        self.CriticalSectionDefaultTimeout = data[t:t+DWORD]; t+=DWORD;
        self.DeCommitFreeBlockThreshold = data[t:t+dType];  t+=dType;
        self.DeCommitTotalFreeThreshold = data[t:t+dType];  t+=dType;
        self.LockPrefixTable = data[t:t+dType];  t+=dType;
        self.MaximumAllocationSize = data[t:t+dType];  t+=dType;
        self.VirtualMemoryThreshold = data[t:t+dType];  t+=dType;
        self.ProcessAffinityMask = data[t:t+dType];  t+=dType;
        self.ProcessHeapFlags = data[t:t+DWORD]; t+=DWORD;  self.CSDVersion = data[t:t+WORD]; t+=WORD;
        self.Reserved1 = data[t:t+WORD]; t+=WORD;           self.EditList = data[t:t+dType]; t+=dType;
        self.SecurityCookie = data[t:t+dType]; t+=dType;    self.SEHandlerTable = data[t:t+dType]; t+=dType;
        self.SEHandlerCount = data[t:t+dType]; t+=dType;
        if dllChar & 0x4000 == 0x4000:
            self.GuardCFCheckFunctionPointer = data[t:t+dType]; t+=dType;
            self.GuardCFDispatchFunctionPointer = data[t:t+dType]; t+=dType;
            self.GuardCFFunctionTable = data[t:t+dType]; t+=dType;
            self.GuardCFFunctionCount = data[t:t+dType]; t+=dType;
            self.GuardFlags = data[t:t+DWORD]; t+=DWORD;
            
    def print(self):
        print('########Image Load Config Directory########')
        print('size', self.size);                            print('TimeDateStamp', self.TimeDateStamp)
        print('MajorVersion', self.MajorVersion);            print('MinorVersion', self.MinorVersion)
        print('GlobalFlagsClear', self.GlobalFlagsClear);    print('GlobalFlagsSet', self.GlobalFlagsSet)
        print('CriticalSectionDefaultTimeout', self.CriticalSectionDefaultTimeout)
        print('DeCommitFreeBlockThreshold ', self.DeCommitFreeBlockThreshold)
        print('DeCommitTotalFreeThreshold', self.DeCommitTotalFreeThreshold)
        print('LockPrefixTable', self.LockPrefixTable)
        print('MaximumAllocationSize', self.MaximumAllocationSize)
        print('VirtualMemoryThreshold', self.VirtualMemoryThreshold)
        print('ProcessAffinityMask', self.ProcessAffinityMask)
        print('ProcessHeapFlags', self.ProcessHeapFlags);    print('CSDVersion', self.CSDVersion)
        print('Reserved1', self.Reserved1);                  print('EditList', self.EditList)
        print('SecurityCookie', self.SecurityCookie);        print('SEHandlerTable', self.SEHandlerTable)
        print('SEHandlerCount', self.SEHandlerCount)
        if dllChar & 0x4000 == 0x4000:
            print('GuardCFCheckFunctionPointer', self.GuardCFCheckFunctionPointer)
            print('GuardCFDispatchFunctionPointer', self.GuardCFDispatchFunctionPointer)
            print('GuardCFFunctionTable', self.GuardCFFunctionTable)
            print('GuardCFFunctionCount', self.GuardCFFunctionCount)
            print('GuardFlags', self.GuardFlags)
         
class CliHeader:
    def __init__(self, offset, size):
        self.offset=offset
        t = offset
        self.cb = data[t:t+DWORD]; t+=DWORD;                self.MajorRuntimeVersion; data[t:t+WORD]; t+=WORD;
        self.MinorRuntimeVersion = data[t:t+WORD]; t+=WORD; self.Metadata; data[t:t+ULONGLONG]; t+=ULONGLONG;
        self.Flags = data[t:t+DWORD]; t+=DWORD;             self.EntryPoint; data[t:t+DWORD]; t+=DWORD;
        self.Resources = data[t:t+ULONGLONG]; t+=ULONGLONG; self.StrongNameSignature; data[t:t+ULONGLONG]; t+=ULONGLONG;
        self.CodeManagerTable = data[t:t+ULONGLONG]; t+=ULONGLONG;  self.VTableFixups; data[t:t+ULONGLONG]; t+=ULONGLONG;
        self.ExportAddressTableJumps = data[t:t+ULONGLONG]; t+=ULONGLONG;   self.ManagedNativeHeader; data[t:t+ULONGLONG]; t+=ULONGLONG;
    
    def print(self):
        print('########Image Cor20 Header########')
        print('cb', self.cb);                                    print('MajorRuntimeVersion', self.MajorRuntimeVersion)
        print('MinorRuntimeVersion', self.MinorRuntimeVersion);  print('Metadata', self.Metadata)
        print('Flags', self.Flags);                              print('EntryPoint', self.EntryPoint)
        print('Resources', self.Resources);                      print('StrongNameSignature', self.StrongNameSignature)
        print('CodeManagerTable', self.CodeManagerTable);        print('VTableFixups', self.VTableFixups)
        print('ExportAddressTableJumps', self.ExportAddressTableJumps);        print('ManagedNativeHeader',self.ManagedNativeHeader)
        print()
############################################################################################################################################################
# CertificateTable
############################################################################################################################################################  
class CertificateTable:
    def __init__(self):
        global dirRva, dirSize
        self.offset = dirRva[4]
        self.size = dirSize[4]
        self.info = data[self.offset:self.offset+self.size]
    def print(self):
        print("########Certificate Table########")
        print(self.info)
        print()

        
        
###Main Class###

#f = open("C:/reversing/notepad.exe", 'rb')
#f = open("C:\Program Files (x86)\AquaNPlayer\AquaAgent.exe", 'rb')
f= open("C:/reversing/notepad.exe", 'rb')
#f= open("C:\Program Files\Bandizip\Bandizip.exe", 'rb')

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
#SecHeaderInfo.print()
print("*****************2*******************")
print(rva_list)

if dirRva[11] !=0 :
    BoundedInfo = BoundedImport()
    #BoundedInfo.print()

SectionInfo = []
for i in range (0, SecNumber):
    SectionInfo.append(Section(headerRva[i], headerSize[i], i, headerPToRawData[i]))

"""for i in SectionInfo:
    i.print()

if dirRva[4] !=0 :
    CertificateInfo = CertificateTable()
    #CertificateInfo.print()"""
    
f.close()