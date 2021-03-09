# -*- coding: utf-8 -*-
"""
PE Viewer
"""
import struct
import sys
import pefile

WORD = 2 
DWORD = 4

image_dos_header_list = []
notPeError = 'PE 포맷이 아닙니다.'

def intTupletoInt(a) :
    s = a[len(a)-1]
    for i in range(len(a)-1, 0):
      s + 256*(i-len(a)-1)*a[i]
    return int(s)


class isNotPE(Exception):
    def __init__(self):
        super().__init__(notPeError)
        
#class PE:
#    def __init__(self):
#        self.t = 0x0

class DosHeader:
    def __init__(self,t):
        try:
            image_dos_header_list.append(["Description", "Data"])
            self.e_magic = data[t:t+WORD]; t+=WORD;   
            image_dos_header_list.append(["Signature", self.e_magic])        
            if self.e_magic != b'MZ':
                raise isNotPE
            self.e_cblp = data[t:t+WORD]; t+=WORD
            image_dos_header_list.append(["Bytes on Last Page of File", self.e_cblp])
            self.e_cp = data[t:t+WORD]; t+=WORD; 
            image_dos_header_list.append([" Pages in File",  self.e_cp])             
            self.e_crlc = data[t:t+WORD]; t+=WORD
            image_dos_header_list.append(["Relocation", self.e_crlc])         
            self.e_minalloc = data[t:t+WORD]; t+=WORD; 
            image_dos_header_list.append([" Minimun Extra Paragraphs", self.e_minalloc])                
            self.e_maxalloc = data[t:t+WORD]; t+=WORD
            image_dos_header_list.append(["Maximun Extra Paragraphs", self.e_maxalloc])         
            self.e_ss = data[t:t+WORD]; t+=WORD;   
            image_dos_header_list.append(["Initial (relative) SS", self.e_ss])                    
            self.e_sp = data[t:t+WORD]; t+=WORD
            image_dos_header_list.append([" Initial SP", self.e_sp])         
            self.e_csum = data[t:t+WORD]; t+=WORD
            image_dos_header_list.append([" Checksum",  self.e_csum])                    
            self.e_ip = data[t:t+WORD]; t+=WORD
            image_dos_header_list.append([" Initial IP",self.e_ip])         
            self.e_cs = data[t:t+WORD]; t+=WORD;   
            image_dos_header_list.append([" Initial (relative) CS", self.e_cs])                   
            self.e_lfarlc = data[t:t+WORD]; t+=WORD
            image_dos_header_list.append(["Offset to Relocation Table", self.e_lfarlc])         
            self.e_ovno = data[t:t+WORD]; t+=WORD; 
            image_dos_header_list.append(["Overlay Number", self.e_ovno])                    
            self.e_res = data[t:t+WORD*4]; t+=(WORD*4)
            image_dos_header_list.append(["Reservedr", self.e_res]) 
            self.e_oemid = data[t:t+WORD]; t+=WORD; 
            image_dos_header_list.append(["OEM Identifier", self.e_oemid])                  
            self.e_oeminfo = data[t:t+WORD]; t+=WORD
            image_dos_header_list.append(["OEM Infomation", self.e_oeminfo])         
            self.e_res2 = data[t:t+WORD*10]; t+=(WORD*10)
            image_dos_header_list.append(["Reserved2", self.e_res2])             
            self.e_lfanew = data[t:t+DWORD]; t+=DWORD
            image_dos_header_list.append(["Offset to New EXE Header", self.e_lfanew])         
            self.t = t
               
        except Exception as e:
            print(e);   sys.exit()
    def print(self):
        print('e_magic:', self.e_magic);    print('e_cblp', self.e_cblp);           print('e_cp:', self.e_cp);             
        print('e_crlc', self.e_crlc);       print('e_mixalloc:', self.e_minalloc);  print('e_maxalloc', self.e_maxalloc)
        print('e_ss:', self.e_ss);          print('e_sp:', self.e_sp);              print('e_sum:', self.e_csum)
        print('e_ip:', self.e_ip);          print('e_cs:', self.e_cs);              print('e_lfaric:', self.e_lfarlc)   
        print('e_ovno:', self.e_ovno);      print('e_res:', self.e_res);            print('e_oemid:', self.e_oemid)
        print('e_oeminfo:', self.e_oeminfo);print('e_res2:', self.e_res2);          print('e_lfanew:',self.e_lfanew)
    
    def getT(self):
        return self.t
         
class DosStub:
    def __init__(self, t, d):      
        self.info = data[t:d]
    def print(self):
        print(self.info)
        
f = open("C:/reversing/notepad.exe", 'rb')
t = 0x0
data = f.read()
DosHeaderInfo = DosHeader(t)
DosHeaderInfo.print()
NTHeaderAddressSt = struct.unpack('<HH', DosHeaderInfo.e_lfanew) #e_lfanew에 NTHeaderAddress의 주소가 있다
NTHeaderAddress = intTupletoInt(NTHeaderAddressSt) 
DosStubInfo = DosStub(DosHeaderInfo.getT(), NTHeaderAddress)
#DosStubInfo.print()
print(image_dos_header_list)

f.close()