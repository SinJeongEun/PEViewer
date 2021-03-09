import pefile
import sys

pe = pefile.PE("C:/reversing/notepad.exe", 'rb')

pFile_start = pe.DOS_HEADER.e_lfanew
pFile = format(pFile_start, '#010x') #pFile 출력형식지정

print("-" *60)
print('IMAGE_NT_HEADERS'.rjust(35))
print("-" *60)

def signature_header(pe):
    
    print("-" *60)
    print('Signature')
    print("-" *60)

    signature_header_list = []
    signature_header_list.append(["pFile", "Data", "Description"])

    # Signature
    signature_header_list.append([pFile, hex(pe.NT_HEADERS.Signature), "Signature"])
    pFileSize()

    print_pe(signature_header_list)


def file_header(pe):
    
    print("-" *60)
    print('IMAGE_FILE_HEADERS')
    print("-" *60)

    file_header_list = []
    file_header_list.append(["pFile", "Data", "Description"])

    # IMAGE_FILE_HEADER
    file_header_list.append([pFile, hex(pe.FILE_HEADER.Machine), "Machine"])
    pFileSize()

    file_header_list.append([pFile, hex(pe.FILE_HEADER.NumberOfSections), "NumberOfSections"])
    pFileSize()

    file_header_list.append([pFile, hex(pe.FILE_HEADER.TimeDateStamp), "TimeDaeStamp"])
    pFileSize()

    file_header_list.append([pFile, hex(pe.FILE_HEADER.PointerToSymbolTable), "PointerToSymbolTable"])
    pFileSize()

    file_header_list.append([pFile, hex(pe.FILE_HEADER.NumberOfSymbols), "NumberOfSymbols"])
    pFileSize()

    file_header_list.append([pFile, hex(pe.FILE_HEADER.SizeOfOptionalHeader), "SizeOfOptionalHeader"])
    pFileSize()

    file_header_list.append([pFile, hex(pe.FILE_HEADER.Characteristics), "Characteristics"])
    pFileSize()

    print_pe(file_header_list)

def optional_header(pe):
    
    print("-" *60)
    print('IMAGE_OPTIONAL_HEADERS')
    print("-" *60)

    optional_header_list = []
    optional_header_list.append(["pFile", "Data", "Description"])

    # IMAGE_OPTINAL_HEADER
    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.Magic), "Magic"])
    pFileSize()

    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.MajorLinkerVersion), "MajorLinkerVersion"])
    pFileSize()

    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.MinorLinkerVersion), "MinorLinkerVersion"])
    pFileSize()

    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.SizeOfCode), "SizeOfCode"])
    pFileSize()

    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.SizeOfInitializedData), "SizeOfInitializedData"])
    pFileSize()

    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "AddressOfEntryPoint"])
    pFileSize()

    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.BaseOfCode), "BaseOfCode"])
    pFileSize()

    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.BaseOfData), "BaseOfData"])
    pFileSize()

    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.ImageBase), "ImageBase"])
    pFileSize()

    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.SectionAlignment), "SectionAlignment"])
    pFileSize()


    print_pe(optional_header_list)



def pFileSize():
    global pFile, pFile_start
    if sys.getsizeof(pe.FILE_HEADER.TimeDateStamp) == 28:
        pFile_start += 2
        pFile = format(pFile_start, '#010x')

    else:
        pFile_start += 4
        pFile = format(pFile_start, '#010x')

def print_pe(data_list):
    for data in data_list:
        print(data[0].ljust(20), data[1].ljust(20), data[2].ljust(20))


signature_header(pe)
file_header(pe)
optional_header(pe)