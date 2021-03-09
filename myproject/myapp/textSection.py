# -*- coding: utf-8 -*-
import pefile
import sys
import struct
"""
Section *text
"""
WORD = 2 
DWORD = 4

def intTupletoInt(a) :
    s = a[0]
    for i in range(0, len(a)):
      s + 256*i+a[i]
    return int(s)

pe = pefile.PE('C:/reversing/notepad.exe')
f = open("C:/reversing/notepad.exe", 'rb')
data = f.read()
tSectionStart = pe.sections[0].VirtualAddress - pe.sections[0].PointerToRawData
TableRawStart = (pe.DOS_HEADER.e_lfanew)+0x78
#IMPORT Address Table
IATRvaB = data[TableRawStart+8*12:TableRawStart+8*12+4] # Option header에서 IAT의 RVA를 추출
IATRVATuple = struct.unpack('<HH', IATRvaB )
IATRva = intTupletoInt(IATRVATuple)
t = IATRva-tSectionStart #RVA를 RAW로 맵핑
print("##IMPORT_Address_Table##")

#IMAGE_DEBUG_DIRECTORY
DebugDirRvaB = data[TableRawStart+8*6:TableRawStart+8*6+4]
DebugDirRvaTuple = struct.unpack('<HH', DebugDirRvaB)
DebugDirRva = intTupletoInt(DebugDirRvaTuple)
t = DebugDirRva-tSectionStart

CharacteristicsIDD = data[t:t+DWORD];  t+=DWORD;    TimeDateStampIDD = data[t:t+DWORD];  t+=DWORD;
MajorVersionIDD = data[t:t+WORD];  t+=WORD;         MinorVersionIDD = data[t:t+WORD];  t+=WORD;
TypeIDD = data[t:t+DWORD];  t+=DWORD;               SizeOfDataIDD = data[t:t+DWORD];  t+=DWORD;
AddressOfRawDataIDD = data[t:t+DWORD];  t+=DWORD;   PointerToRawDataIDD = data[t:t+DWORD];  t+=DWORD;

print("##IMAGE_DEBUG_DIRECTORY##")
print(CharacteristicsIDD);  print(TimeDateStampIDD);    print(MajorVersionIDD)
print(MinorVersionIDD);     print(TypeIDD);             print(SizeOfDataIDD)
print(AddressOfRawDataIDD); print(PointerToRawDataIDD); print("")

#IMAGE_LOAD_CONFIG_DIRECTORY
LCDRvaB = data[TableRawStart+8*10:TableRawStart+8*10+4]
LCDRvaTuple = struct.unpack('<HH', LCDRvaB)
LCDRva = intTupletoInt(LCDRvaTuple)
t = LCDRva-tSectionStart

SizeLCD = data[t:t+DWORD];  t+=DWORD;              TimeDateStampLCD = data[t:t+DWORD];  t+=DWORD;
MajorVersionLCD = data[t:t+WORD];  t+=WORD;        MinorVersionLCD = data[t:t+WORD];  t+=WORD;
GlobalFlagsClearLCD = data[t:t+DWORD];  t+=DWORD;  GlobalFlagsSetLCD = data[t:t+DWORD];  t+=DWORD;    
CriticalSectionDefaultTimeoutLCD = data[t:t+DWORD];  t+=DWORD;
DeCommitFreeBlockThresholdLCD = data[t:t+DWORD];   t+=DWORD;  
DeCommitTotalFreeThresholdLCD = data[t:t+DWORD];  t+=DWORD; 
LockPrefixTableLCD = data[t:t+DWORD];  t+=DWORD;  MaximumAllocationSizeLCD = data[t:t+DWORD];  t+=DWORD;
VirtualMemoryThresholdLCD = data[t:t+DWORD];  t+=DWORD;
ProcessHeapFlagsLCD = data[t:t+DWORD];  t+=DWORD;  ProcessAffinityMaskLCD = data[t:t+DWORD];  t+=DWORD;
CSDVersionLCD = data[t:t+WORD];  t+=WORD;          DependentLoadFlagsLCD = data[t:t+WORD];  t+=WORD
EditListLCD = data[t:t+DWORD];  t+=DWORD;          SecurityCookieLCD = data[t:t+DWORD];  t+=DWORD; 
SEHandlerTableLCD = data[t:t+DWORD];  t+=DWORD;    SEHandlerCountLCD = data[t:t+DWORD];  t+=DWORD;

print("##IMAGE_LOAD_CONFIG_DIRECTORY##")
print(SizeLCD);            print(TimeDateStampLCD);        print(MajorVersionLCD);
print(MinorVersionLCD);    print(GlobalFlagsClearLCD);     print(GlobalFlagsSetLCD);
print(CriticalSectionDefaultTimeoutLCD);                print(DeCommitFreeBlockThresholdLCD);
print(DeCommitTotalFreeThresholdLCD);                   print(LockPrefixTableLCD);
print(MaximumAllocationSizeLCD);                        print(VirtualMemoryThresholdLCD);
print(ProcessHeapFlagsLCD);print(ProcessAffinityMaskLCD);  print(CSDVersionLCD);
print(DependentLoadFlagsLCD);                           print(EditListLCD);
print(SecurityCookieLCD);  print(SEHandlerTableLCD);       print(SEHandlerCountLCD);
print("")

#IMAGE_DEBUG_TYPE_CODEVIEW
PointerToRawDataIDDTuple = LCDRvaTuple = struct.unpack('<HH', PointerToRawDataIDD)
#IMAGE_DEBUG_DIRECTORY 구조체의 PointerToRawData 맴버가 IMAGE_DEBUG_TYPE_CODEVIEW를 가리킨다.
t = intTupletoInt(PointerToRawDataIDDTuple)

IMAGE_DEBUG_TYPE_CODEVIEW = data[t:t+0x24]
print("##IMAGE_DEBUG_TYPE_CODEVIEW##")
print(IMAGE_DEBUG_TYPE_CODEVIEW)

#IMPORT Directory Table
IDTRvaB = data[TableRawStart+8*1:TableRawStart+8*1+4]
IDTRVATuple = struct.unpack('<HH', IDTRvaB )
IDTRva = intTupletoInt(IDTRVATuple)
t = IDTRva-tSectionStart
print("##IMAGE_Directory_Table##")
