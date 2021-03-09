from django.db import models

# Create your models here.
class Parsing_PE(models.Model): 
    def __init__(self,f): 
        self.f = f 
        self.buf = bytearray(self.f.read()) 
        self.IMAGE_DOS_HEADER() 
        self.IMAGE_NT_HEADER() 
        self.IMAGE_SECTION_HEADER()

    # def IMAGE_DOS_HEADER(self): 
    #     dos_header = self.buf[0x0:0x40] 
    #     mz_signature = dos_header[0x0:0x2] 

    # def IMAGE_NT_HEADER(self): 
    #     nt_header = self.buf[self.e_lfanew:self.e_lfanew+0x200] 
    #     pe_signature = nt_header[0x00:0x2] 

    # def IMAGE_SECTION_HEADER(self): 
    #     sectiontable_size = self.numberofsections*0x28 
    #     sectiontable = self.buf[self.sectiontable_offset : self.sectiontable_offset+sectiontable_size] 