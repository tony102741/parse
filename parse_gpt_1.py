import os
import struct
# 대문자: unsigned, 소문자: signed
# 1 byte = B
# 2 bytes = H
# 4 bytes = I
# 8 bytes = Q

SECTOR_SIZE = 0x200
MBR_SIGNATURE = "0xaa55"
PROTECTIVE_MBR_FILESYSTEM_ID = "0xee"

# -----------------------------------------------------------------------------------|
def print_gpt_header_data(gpt_header_struct):
    print(f'[+] GPT Header Information')
    print(f' [-] signature: {hex(gpt_header_struct["signature"])}')
    print(f' [-] revision: {hex(gpt_header_struct["revision"])}')
    print(f' [-] header_size: {hex(gpt_header_struct["header_size"])}')
    print(f' [-] header_crc: {hex(gpt_header_struct["header_crc"])}')
    print(f' [-] current_LBA: {hex(gpt_header_struct["current_LBA"])}')
    print(f' [-] backup_LBA: {hex(gpt_header_struct["backup_LBA"])}')
    print(f' [-] first_usable_LBA: {hex(gpt_header_struct["first_usable_LBA"])}')
    print(f' [-] last_usable_LBA: {hex(gpt_header_struct["last_usable_LBA"])}')
    print(f' [-] disk_guid: 0x{gpt_header_struct["disk_guid"].hex()}')
    print(f' [-] starting_LBA_of_entries: {hex(gpt_header_struct["starting_LBA_of_entries"])}')
    print(f' [-] number_of_entries: {hex(gpt_header_struct["number_of_entries"])}')
    print(f' [-] entry_size: {hex(gpt_header_struct["entry_size"])}')
    print(f' [-] crc_of_partition_array: {hex(gpt_header_struct["crc_of_partition_array"])}')

# -----------------------------------------------------------------------------------|
def parse_gpt(disk_path, list_partition_entry):
    with open(disk_path, "rb") as f:
        f.seek(list_partition_entry[0]["first_sector"])
        gpt_header_data = f.read(SECTOR_SIZE)
   
    gpt_header_struct = {}
    gpt_header_struct["signature"] = struct.unpack("<Q", gpt_header_data[:0x8])[0]
    gpt_header_struct["revision"] = struct.unpack("<I", gpt_header_data[0x8:0xc])[0]
    gpt_header_struct["header_size"] = struct.unpack("<I", gpt_header_data[0xc:0x10])[0]
    gpt_header_struct["header_crc"] = struct.unpack("<I", gpt_header_data[0x10:0x14])[0]
    gpt_header_struct["current_LBA"] = struct.unpack("<Q", gpt_header_data[0x18:0x20])[0] * SECTOR_SIZE
    gpt_header_struct["backup_LBA"] = struct.unpack("<Q", gpt_header_data[0x20:0x28])[0] * SECTOR_SIZE
    gpt_header_struct["first_usable_LBA"] = struct.unpack("<Q", gpt_header_data[0x28:0x30])[0] * SECTOR_SIZE
    gpt_header_struct["last_usable_LBA"] = struct.unpack("<Q", gpt_header_data[0x30:0x38])[0] * SECTOR_SIZE
    gpt_header_struct["disk_guid"] = gpt_header_data[0x38:0x48]
    gpt_header_struct["starting_LBA_of_entries"] = struct.unpack("<Q", gpt_header_data[0x48:0x50])[0] * SECTOR_SIZE
    gpt_header_struct["number_of_entries"] = struct.unpack("<I", gpt_header_data[0x50:0x54])[0]
    gpt_header_struct["entry_size"] = struct.unpack("<I", gpt_header_data[0x54:0x58])[0]
    gpt_header_struct["crc_of_partition_array"] = struct.unpack("<I", gpt_header_data[0x58:0x5c])[0]

    print_gpt_header_data(gpt_header_struct)
    list_gpt_partition_entry = parse_gpt_partition_table(disk_path, gpt_header_struct)
    print_gpt_partition_entry_data(list_gpt_partition_entry)

# -----------------------------------------------------------------------------------|
def print_gpt_partition_entry_data(list_gpt_partition_entry):
    print(f'[+] GPT Partition Entry Information')
    for i in range(len(list_gpt_partition_entry)):
        print(f' [-] partition entry #{i+1} ')
        print(f'   [-] Partition Type GUID: 0x{list_gpt_partition_entry[i]["Partition Type GUID"].hex()}')
        print(f'   [-] Unique Partition GUID: 0x{list_gpt_partition_entry[i]["Unique Partition GUID"].hex()}')
        print(f'   [-] First LBA: {hex(list_gpt_partition_entry[i]["First LBA"])}')
        print(f'   [-] Last LBA: {hex(list_gpt_partition_entry[i]["Last LBA"])}')
        print(f'   [-] Attribute Flags: {hex(list_gpt_partition_entry[i]["Attribute Flags"])}')
        print(f'   [-] Partition Name: {(list_gpt_partition_entry[i]["Partition Name"].decode("utf-16le"))}')

# -----------------------------------------------------------------------------------|
def parse_gpt_partition_table(disk_path, gpt_header_struct):
    with open(disk_path, "rb") as f:
        f.seek(gpt_header_struct["starting_LBA_of_entries"])
        gpt_partition_entry_data = f.read(gpt_header_struct["entry_size"] * gpt_header_struct["number_of_entries"])
    list_gpt_partition_entry = []
    gpt_cnt_entry = 0

    while gpt_cnt_entry < gpt_header_struct["number_of_entries"]:
        gpt_partition_entry_struct = {}
        gpt_entry_offset = gpt_cnt_entry * gpt_header_struct["entry_size"]

        gpt_partition_entry_struct["Partition Type GUID"] = struct.unpack("<16s",  gpt_partition_entry_data[gpt_entry_offset:gpt_entry_offset+0x10])[0]
        gpt_partition_entry_struct["Unique Partition GUID"] = struct.unpack("<16s", gpt_partition_entry_data[gpt_entry_offset+0x10:gpt_entry_offset+0x20])[0]
        gpt_partition_entry_struct["First LBA"] = struct.unpack("<Q", gpt_partition_entry_data[gpt_entry_offset+0x20:gpt_entry_offset+0x28])[0]
        gpt_partition_entry_struct["Last LBA"] = struct.unpack("<Q", gpt_partition_entry_data[gpt_entry_offset+0x28:gpt_entry_offset+0x30])[0]
        gpt_partition_entry_struct["Attribute Flags"] = struct.unpack("<Q", gpt_partition_entry_data[gpt_entry_offset+0x30:gpt_entry_offset+0x38])[0]
        gpt_partition_entry_struct["Partition Name"] = gpt_partition_entry_data[gpt_entry_offset+0x38:gpt_entry_offset+0x80]

        if gpt_partition_entry_struct["First LBA"] != 0:    
            list_gpt_partition_entry.append(gpt_partition_entry_struct)
            gpt_cnt_entry += 1  
        else:   
            break
                       
    return list_gpt_partition_entry

# -----------------------------------------------------------------------------------|
def print_partition_entry_data(list_partition_entry):
    if (len(list_partition_entry) == 1):
        if hex(list_partition_entry[0]["filesystem_id"]) == PROTECTIVE_MBR_FILESYSTEM_ID:
            print(f'[+] Protective MBR Partition Entry Information')
            mbr_type = "protective_mbr"
    else:
        print(f'[+] MBR Partition Entry Information')
        mbr_type = "mbr"
   
    for i in range(len(list_partition_entry)):
        print(f' [-] partition entry #{i+1} ')
        print(f'   [-] active_partition_flag: {hex(list_partition_entry[i]["active_partition_flag"])}')
        print(f'   [-] filesystem_id: {hex(list_partition_entry[i]["filesystem_id"])}')
        print(f'   [-] first_sector: {hex(list_partition_entry[i]["first_sector"])}')
        print(f'   [-] total_sectors: {hex(list_partition_entry[i]["total_sectors"])}')

    return mbr_type
# -----------------------------------------------------------------------------------|
def parse_partition_table(disk_path, br_start_offset, mbr_data):
    list_partition_entry = []
    cnt_entry = 0
   
    while(cnt_entry < 4):
        partition_entry_struct = {}
        entry_offset = 0x1be + (cnt_entry*0x10)
       
        partition_entry_struct["active_partition_flag"] = struct.unpack("<B", mbr_data[entry_offset:entry_offset+0x1])[0]
        partition_entry_struct["filesystem_id"] = struct.unpack("<B", mbr_data[entry_offset+0x4:entry_offset+0x5])[0]
        partition_entry_struct["first_sector"] = br_start_offset + struct.unpack("<I", mbr_data[entry_offset+0x8:entry_offset+0xc])[0] * SECTOR_SIZE
        partition_entry_struct["total_sectors"] = struct.unpack("<I", mbr_data[entry_offset+0xc:entry_offset+0x10])[0] * SECTOR_SIZE

        if (partition_entry_struct["filesystem_id"] != 5) and (partition_entry_struct["total_sectors"] != 0):
            list_partition_entry.append(partition_entry_struct)
            cnt_entry = cnt_entry+1
            continue
        elif partition_entry_struct["filesystem_id"] == 5:
            br_start_offset = partition_entry_struct["first_sector"]
            with open(disk_path, "rb") as f:
                f.seek(br_start_offset)
                mbr_data = f.read(SECTOR_SIZE)
            cnt_entry = 0
            continue
        elif partition_entry_struct["total_sectors"] == 0:
            break
           
    return list_partition_entry

# file_path의 파일에서 MBR 데이터 파싱
# -----------------------------------------------------------------------------------
def parse_mbr(disk_path):
# 1. 파일 오픈
# 2. 1개 섹터 read
    with open(disk_path, "rb") as f:
        mbr_data = f.read(SECTOR_SIZE)

# 3. MBR 데이터 파싱
    mbr_struct = {}
    list_partition_entry = []
   
    if hex(struct.unpack("<H", mbr_data[0x1fe:0x200])[0]) != MBR_SIGNATURE:
        print("This is a not MBR data.")
        return False
       
    mbr_struct["bootstrap_code"] = mbr_data[:0x1b8]
    mbr_struct["disk_serial_number"] = struct.unpack("<I", mbr_data[0x1b8:0x1bc])[0]
    br_start_offset = 0
    list_partition_entry = parse_partition_table(disk_path, br_start_offset, mbr_data)
    mbr_type = print_partition_entry_data(list_partition_entry)

    return list_partition_entry, mbr_type
# -----------------------------------------------------------------------------------    
# file_path = "C:\\Users\\exdus\\Desktop\\파일시스템\\프로그래밍\\MBR\\USB_4GB.dd"
disk_path = "\\\\.\\PhysicalDrive0"
try:
    os.path.isfile(disk_path) # file_path가 파일인지 확인
    list_partition_entry, mbr_type = parse_mbr(disk_path) # file_path의 파일에서 MBR 데이터 파싱

    if mbr_type == "protective_mbr":
        parse_gpt(disk_path, list_partition_entry)
       
except Exception as e:
    print(e)