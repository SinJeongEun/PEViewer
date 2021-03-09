# -*- coding: utf-8 -*-
"""
PE Viewer
"""
import struct
import sys

BYTE = 1
WORD = 2 
DWORD = 4
ULONGLONG = 8
BIT = 0

notMzError = '윈도우 실행 파일 포맷이 아닙니다.'
notPeError = 'PE 포맷이 아닙니다.'

dirRva = []
dirSize = []
headerRva = []
headerPToRawData = []
headerSize = []

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


class DosHeader:
    def __init__(self, t):
        try:
            self.e_magic = data[t:t+WORD]; t+=WORD;          
            if self.e_magic != b'MZ':
                raise isNotMZ
            self.e_cblp = data[t:t+WORD]; t+=WORD
            self.e_cp = data[t:t+WORD]; t+=WORD;              self.e_crlc = data[t:t+WORD]; t+=WORD
            self.e_minalloc = data[t:t+WORD]; t+=WORD;        self.e_maxalloc = data[t:t+WORD]; t+=WORD
            self.e_ss = data[t:t+WORD]; t+=WORD;              self.e_sp = data[t:t+WORD]; t+=WORD
            self.e_csum = data[t:t+WORD]; t+=WORD;            self.e_ip = data[t:t+WORD]; t+=WORD
            self.e_cs = data[t:t+WORD]; t+=WORD;              self.e_lfarlc = data[t:t+WORD]; t+=WORD
            self.e_ovno = data[t:t+WORD]; t+=WORD;            self.e_res = data[t:t+WORD*4]; t+=(WORD*4)
            self.e_oemid = data[t:t+WORD]; t+=WORD;           self.e_oeminfo = data[t:t+WORD]; t+=WORD
            self.e_res2 = data[t:t+WORD*10]; t+=(WORD*10);    self.e_lfanew = data[t:t+DWORD]; t+=DWORD
            self.t = t
        except Exception as e:
            print(e);   sys.exit()
    def print(self):
        print('########Dos Header########')
        print('e_magic:', self.e_magic);    print('e_cblp', self.e_cblp);           print('e_cp:', self.e_cp);             
        print('e_crlc', self.e_crlc);       print('e_mixalloc:', self.e_minalloc);  print('e_maxalloc', self.e_maxalloc)
        print('e_ss:', self.e_ss);          print('e_sp:', self.e_sp);              print('e_sum:', self.e_csum)
        print('e_ip:', self.e_ip);          print('e_cs:', self.e_cs);              print('e_lfaric:', self.e_lfarlc)   
        print('e_ovno:', self.e_ovno);      print('e_res:', self.e_res);            print('e_oemid:', self.e_oemid)
        print('e_oeminfo:', self.e_oeminfo);print('e_res2:', self.e_res2);          print('e_lfanew:',self.e_lfanew)
        print()

        #print(type(self.e_lfanew))

    def getT(self):
        return self.t
    
    def getE_lfanew(self):
        return self.e_lfanew
         
DosStub_list = []
class DosStub:
    def __init__(self, t, d):  
        self.info = data[t:d]
        DosStub_list.append(["RawData",self.info])   

    def print(self):
        print("########Dos Stub########")
        print(self.info)
        #print(hex(NTHeaderAddress))
        print()

############################################################################################################################################################
# NTHeader
############################################################################################################################################################

class NTHeader:
    def __init__(self, t):       
        self.Dir = []
        try:
            a = self.signature(t) # 변경된 t값 저장
            b = self.file_header(a) # 변경된 t값 저장
            self.optional_header(b)

        except Exception as e:
            print(e);   sys.exit()
            
    def signature(self, t):
            self.Signature = data[t:t+DWORD]; t+=DWORD;

            if 'PE' not in self.Signature.decode('utf-8'):
                raise isNotPE

            self.t = t;
            return self.t;

    def file_header(self, t):
            self.Machine = data[t:t+WORD]; t+=WORD;                      self.NumberOfSections = data[t:t+WORD]; t+=WORD;
            self.TimeDateStamp = data[t:t+DWORD]; t+=DWORD;              self.PointerToSymbolTable = data[t:t+DWORD]; t+=DWORD;
            self.NumberOfSymbols = data[t:t+DWORD]; t+=DWORD;            self.SizeOfOptionalHeader = data[t:t+WORD]; t+=WORD;
            self.Characteristics = data[t:t+WORD]; t+=WORD;
            
            self.t = t;
            return self.t;            

    def optional_header(self, t):        
            global BIT
            global dirRva
            global dirSize
            self.Magic = data[t:t+WORD]; t+=WORD;                        
            if self.Magic == b'\x0b\x01':
                BIT = 32
            elif self.Magic == b'\x0b\x02':
                BIT = 64
            elif self.Magic == b'\x07\x01':
                BIT = 0 #ROM Image file
            self.MajorLinkerVersion = data[t:t+BYTE]; t+=BYTE;
            self.MinorLinkerVersion = data[t:t+BYTE]; t+=BYTE;            self.SizeOfCode = data[t:t+DWORD]; t+=DWORD;
            self.SizeOfInitializedData = data[t:t+DWORD]; t+=DWORD;       self.SizeOfUnitializedData = data[t:t+DWORD]; t+=DWORD;
            self.AddressOfEntryPoint = data[t:t+DWORD]; t+=DWORD;         
            if BIT == 32:
                self.BaseOfCode = data[t:t+DWORD]; t+=DWORD;              self.BaseOfData = data[t:t+DWORD]; t+=DWORD;      
                self.ImageBase = data[t:t+DWORD]; t+=DWORD;
            elif BIT == 64:
                self.BaseOfCode = data[t:t+ULONGLONG]; t+=ULONGLONG;      self.ImageBase = data[t:t+ULONGLONG]; t+=ULONGLONG;
                
            self.SectionAlignment = data[t:t+DWORD]; t+=DWORD;            self.FileAlignment = data[t:t+DWORD]; t+=DWORD;
            self.MajorOperatingSystemVersion = data[t:t+WORD]; t+=WORD;   self.MinorOperatingSystemVersion = data[t:t+WORD]; t+=WORD;
            self.MajorImageVersion = data[t:t+WORD]; t+=WORD;             self.MinorImageVersion = data[t:t+WORD]; t+=WORD;
            self.MajorSubsystemVersion = data[t:t+WORD]; t+=WORD;         self.MinorSubsystemVersion = data[t:t+WORD]; t+=WORD;
            self.Win32VersionValue = data[t:t+DWORD]; t+=DWORD;           self.SizeOfImage = data[t:t+DWORD]; t+=DWORD;
            self.SizeOfHeaders = data[t:t+DWORD]; t+=DWORD;               self.CheckSum = data[t:t+DWORD]; t+=DWORD;
            self.Subsystem = data[t:t+WORD]; t+=WORD;                     self.DllCharateristics = data[t:t+WORD]; t+=WORD;
            if BIT==32:
                self.SizeOfStackReserve = data[t:t+DWORD]; t+=DWORD;      self.SizeOfStackCommit = data[t:t+DWORD]; t+=DWORD;
                self.SizeOfHeapReserve = data[t:t+DWORD]; t+=DWORD;       self.SizeOfHeapCommit = data[t:t+DWORD]; t+=DWORD;
            elif BIT==64:
                self.SizeOfStackReserve = data[t:t+ULONGLONG]; t+=ULONGLONG;      self.SizeOfStackCommit = data[t:t+ULONGLONG]; t+=ULONGLONG;
                self.SizeOfHeapReserve = data[t:t+ULONGLONG]; t+=ULONGLONG;       self.SizeOfHeapCommit = data[t:t+ULONGLONG]; t+=ULONGLONG;
            self.LoaderFlags = data[t:t+DWORD]; t+=DWORD;                 self.NumberOfRvaAndSizes = data[t:t+DWORD]; t+=DWORD;
            
            
            self.Dir = [
                ['EXPORT Table', data[t:t+DWORD], data[t+DWORD:t+DWORD*2]],
                ['IMPORT Table', data[t+DWORD*2:t+DWORD*3], data[t+DWORD*3:t+DWORD*4]],
                ['RESOURCE Table', data[t+DWORD*4:t+DWORD*5], data[t+DWORD*5:t+DWORD*6]],
                ['EXCEPTION Table', data[t+DWORD*6:t+DWORD*7], data[t+DWORD*7:t+DWORD*8]],
                ['CERTIFICATE Table', data[t+DWORD*8:t+DWORD*9], data[t+DWORD*9:t+DWORD*10]],
                ['BASE RELOCATION Table', data[t+DWORD*10:t+DWORD*11], data[t+DWORD*11:t+DWORD*12]],
                ['DEBUG Directory', data[t+DWORD*12:t+DWORD*13], data[t+DWORD*13:t+DWORD*14]],
                ['Architecture Specific Data', data[t+DWORD*14:t+DWORD*15], data[t+DWORD*15:t+DWORD*16]],
                ['GLOBAL POINTER Register', data[t+DWORD*16:t+DWORD*17], data[t+DWORD*17:t+DWORD*18]],
                ['TLS Table', data[t+DWORD*18:t+DWORD*19], data[t+DWORD*19:t+DWORD*20]],
                ['LOAD CONFIGURATION Table', data[t+DWORD*20:t+DWORD*21], data[t+DWORD*21:t+DWORD*22]],
                ['BOUND IMPORT Table', data[t+DWORD*22:t+DWORD*23], data[t+DWORD*23:t+DWORD*24]],
                ['IMPORT Address Table', data[t+DWORD*24:t+DWORD*25], data[t+DWORD*25:t+DWORD*26]],
                ['DELAY IMPORT Descriptors', data[t+DWORD*26:t+DWORD*27], data[t+DWORD*27:t+DWORD*28]],
                ['CLI Header', data[t+DWORD*28:t+DWORD*29], data[t+DWORD*29:t+DWORD*30]],
                ['reverse', data[t+DWORD*30:t+DWORD*31], data[t+DWORD*31:t+DWORD*32]]
                ];
            
            t+=(DWORD*32)
            for i in self.Dir:
                dirRva.append(byteToInt(i[1]))
                dirSize.append(byteToInt(i[2]))
            self.t = t;
            
    def print(self):
        # Signature
        print('########NT Header########')
        print('Signature:', self.Signature);  

        # FILE_HEADER
        print('########File Header########')
        print('Machine', self.Machine);                                             print('NumberOfSections:',  self.NumberOfSections);             
        print('TimeDateStamp:', self.TimeDateStamp);                                print('PointerToSymbolTable', self.PointerToSymbolTable);
        print('NumberOfSymbols:', self.NumberOfSymbols);                            print('SizeOfOptionalHeader', self.SizeOfOptionalHeader);
        print('Characteristics:', self.Characteristics);             
        
        # OPTIONAL_HEADER
        print('########Option Header########')
        print('Magic:', self.Magic);                                                print('MajorLinkerVersion', self.MajorLinkerVersion);
        print('MinorLinkerVersion:', self.MinorLinkerVersion);                      print('SizeOfCode', self.SizeOfCode);
        print('SizeOfInitializedData:', self.SizeOfInitializedData);                print('SizeOfUnitializedData', self.SizeOfUnitializedData);
        print('AddressOfEntryPoint:', self.AddressOfEntryPoint);                    print('BaseOfCode', self.BaseOfCode);
        if BIT==32:
            print('BaseOfData:', self.BaseOfData);                                      
        print('ImageBase:', self.ImageBase);
        print('SectionAlignment', self.SectionAlignment);                           print('FileAlignment:', self.FileAlignment);
        print('MajorOperatingSystemVersion', self.MajorOperatingSystemVersion);     print('MinorOperatingSystemVersion:', self.MinorOperatingSystemVersion);
        print('MajorImageVersion', self.MajorImageVersion);                         print('MinorImageVersion:', self.MinorImageVersion);
        print('MajorSubsystemVersion', self.MajorSubsystemVersion);                 print('MinorSubsystemVersion:', self.MinorSubsystemVersion);
        print('Win32VersionValue', self.Win32VersionValue);                         print('SizeOfImage:', self.SizeOfImage);
        print('SizeOfHeaders', self.SizeOfHeaders);                                 print('CheckSum:', self.CheckSum);
        print('Subsystem', self.Subsystem);                                         print('DllCharateristics:', self.DllCharateristics);
        print('SizeOfStackReserve', self.SizeOfStackReserve);                       print('SizeOfStackCommit:', self.SizeOfStackCommit);
        print('SizeOfHeapReserve', self.SizeOfHeapReserve);                         print('SizeOfHeapCommit:', self.SizeOfHeapCommit);
        print('LoaderFlags', self.LoaderFlags);                                     print('NumberOfRvaAndSizes:', self.NumberOfRvaAndSizes);   
        print("==========================")
        #DATA_DIRECTORY
        for i in self.Dir:
            print(i[0])
            print('RVA: ', i[1])
            print('Size: ', i[2])
            print("==========================")
        print()
            
    def getT(self):
        return self.t
    
    def getNumberOfSections(self):
        return self.NumberOfSections
        
    def getDir(self):
        return self.Dir
############################################################################################################################################################
# SectionHeader
############################################################################################################################################################      
class SectionHeader:
    def __init__(self, t, SecNumber):   
        global headerRva, headerPToRawData, headerSize
        self.SecHeader = []
        for i in range(1, SecNumber+1):
            self.SecHeader.append([data[t:t+DWORD*2], data[t+DWORD*2:t+DWORD*3], data[t+DWORD*3:t+DWORD*4],
                             data[t+DWORD*4:t+DWORD*5], data[t+DWORD*5:t+DWORD*6], data[t+DWORD*6:t+DWORD*7], data[t+DWORD*7:t+DWORD*8],
                             data[t+DWORD*8:t+DWORD*8+WORD], data[t+DWORD*8+WORD:t+DWORD*9], data[t+DWORD*9:t+DWORD*10]])
            headerRva.append(byteToInt(self.SecHeader[i-1][2]))
            headerPToRawData.append(byteToInt(self.SecHeader[i-1][4]))
            headerSize.append(byteToInt(self.SecHeader[i-1][3]))
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
    
class relocSection:
    def __init__(self, offset, size):
        self.reloc = []
        groupOffset = offset
        while True:
            relocTemp = [] # Temp에 reloc 그룹 하나씩 저장하고, reloc에 append 한다.
            t = groupOffset
            if offset+size == t:
                break
            relocTemp.append(data[t:t+4]);    t+=4
            groupSize = byteToInt(data[t:t+4])
            relocTemp.append(data[t:t+4]);    t+=4
            while True:
                relocTemp.append(data[t:t+2]); t+=2
                if t == groupOffset+groupSize:
                    groupOffset = t
                    break
            self.reloc.append(relocTemp)
            
    def print(self):
        print("==========================")
        for i in self.reloc:
            print('RVA of Block: ', i[0])
            print('Size of BlocK: ', i[1])
            for j in range (2, len(i)):
                value1 = (byteToInt(b'\x00\x00'+i[j]) & 0xF000) / 0x1000
                value2 = (byteToInt(b'\x00\x00'+i[j]) & 0x0FFF)
                print(i[j], ': ', hex((byteToInt(i[0])+int(value2))), relocType[int(value1)])
        print("==========================")    
        print()
       
############################################################################################################################################################
# CertificateTable
############################################################################################################################################################  
class CertificateTable:
    def __init__(self, offset, size):
        self.info = data[offset:offset+size]
    def print(self):
        print("########Certificate Table########")
        print(self.info)
        print()

        
        
###Main Class###

f = open("C:/reversing/notepad.exe", 'rb')
# f = open("C:\Program Files (x86)\AquaNPlayer\AquaAgent.exe", 'rb')
t = 0x0
data = f.read()
DosHeaderInfo = DosHeader(t)
DosHeaderInfo.print()
NTHeaderAddress = byteToInt(DosHeaderInfo.getE_lfanew()) #e_lfanew에 NTHeaderAddress의 주소가 있다

DosStubInfo = DosStub(DosHeaderInfo.getT(), NTHeaderAddress)
DosStubInfo.print()
print(DosStub_list)

NTHeaderInfo = NTHeader(NTHeaderAddress)
NTHeaderInfo.print()

SecNumber = byteToInt(b'\x00\x00'+NTHeaderInfo.getNumberOfSections())
SecHeaderInfo = SectionHeader(NTHeaderInfo.getT(), SecNumber)
SecHeaderInfo.print()

SectionInfo = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
relocSecNumber = -1
for i in headerRva:
    if dirRva[5] == i:
        relocSecNumber = headerRva.index(i)
if relocSecNumber != -1:
    SectionInfo[relocSecNumber] = relocSection(rvaToOffset(dirRva[5], headerRva[relocSecNumber], headerPToRawData[relocSecNumber]), dirSize[5]) 

# SectionInfo[relocSecNumber].print() # 나중에는 각각의 섹션을 index0부터 반복문으로 출력하게 구현
# CertiOffset = byteToInt(NTHeaderInfo.getDir()[4][1])
# CertiSize = byteToInt(NTHeaderInfo.getDir()[4][2])
# CertificateInfo = CertificateTable(CertiOffset, CertiSize)
# CertificateInfo.print()
    
f.close()