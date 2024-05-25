import os
import struct
# 대문자: unsigned, 소문자: signed
# 1 byte = B
# 2 bytes = H
# 4 bytes = I
# 8 bytes = Q

SECTOR_SIZE = 0x200
CLUSTER_SIZE = 0x1000
MBR_SIGNATURE = "0xaa55"
PARTITON_TABLE_SIZE = 0x40

# -----------------------------------------------------------------------------------|
def print_boot_sector_data(boot_sector):
    print('[+] Boot Sector Information')
    print(f' [-] jump_instruction: 0x{(boot_sector["jump_instruction"][::-1]).hex()}')
    print(f' [-] oem_id: {(boot_sector["oem_id"].decode("ascii"))}')
    print(f' [-] bytes_per_sector: {hex(boot_sector["bytes_per_sector"])}')
    print(f' [-] sectors_per_cluster: {hex(boot_sector["sectors_per_cluster"])}')
    print(f' [-] reserved_sectors: {hex(boot_sector["reserved_sectors"])}') 
    print(f' [-] number_of_fats: {hex(boot_sector["number_of_fats"])}') 
    print(f' [-] media_description: {hex(boot_sector["media_description"])}')
    print(f' [-] sectors_per_track: {hex(boot_sector["sectors_per_track"])}')
    print(f' [-] number_of_heads: {hex(boot_sector["number_of_heads"])}')
    print(f' [-] hidden_sectors: {hex(boot_sector["hidden_sectors"])}')
    print(f' [-] total_sectors: {hex(boot_sector["total_sectors"])}')
    print(f' [-] sectors_per_fat: {hex(boot_sector["sectors_per_fat"])}')
    print(f' [-] extended_flags: {hex(boot_sector["extended_flags"])}')
    print(f' [-] version: {hex(boot_sector["version"])}')
    print(f' [-] root_cluster: {hex(boot_sector["root_cluster"])}')
    print(f' [-] system_information_sector: {hex(boot_sector["system_information_sector"])}')
    print(f' [-] backup_boot_sector: {hex(boot_sector["backup_boot_sector"])}')
    print(f' [-] physical_drive: {hex(boot_sector["physical_drive"])}')
    print(f' [-] extended_signature: {hex(boot_sector["extended_signature"])}')
    print(f' [-] serial_number: {hex(boot_sector["serial_number"])}')
    print(f' [-] volume_label: {(boot_sector["volume_label"])}')
    print(f' [-] file_system: {(boot_sector["file_system"].decode("ascii"))}')
    
# -----------------------------------------------------------------------------------|
def parse_boot_sector_data(file_path, partition_entry_struct): 
    with open(file_path, "rb") as f:
        f.seek(partition_entry_struct["first_sector"])
        boot_sector_data = f.read(SECTOR_SIZE)
            
    boot_sector = {}
    boot_sector["jump_instruction"] = struct.unpack("<3s", boot_sector_data[:0x3])[0]
    boot_sector["oem_id"] = boot_sector_data[0x3:0xb]
    boot_sector["bytes_per_sector"] = struct.unpack("<H", boot_sector_data[0xb:0xd])[0]
    boot_sector["sectors_per_cluster"] = struct.unpack("<B", boot_sector_data[0xd:0xe])[0]
    boot_sector["reserved_sectors"] = struct.unpack("<H", boot_sector_data[0xe:0x10])[0]
    boot_sector["number_of_fats"] = struct.unpack("<B", boot_sector_data[0x10:0x11])[0]
    boot_sector["media_description"] = struct.unpack("<B", boot_sector_data[0x15:0x16])[0]
    boot_sector["sectors_per_track"] = struct.unpack("<H", boot_sector_data[0x18:0x1a])[0]
    boot_sector["number_of_heads"] = struct.unpack("<H", boot_sector_data[0x1a:0x1c])[0]
    boot_sector["hidden_sectors"] = struct.unpack("<I", boot_sector_data[0x1c:0x20])[0]
    boot_sector["total_sectors"] = struct.unpack("<I", boot_sector_data[0x20:0x24])[0]
    boot_sector["sectors_per_fat"] = struct.unpack("<I", boot_sector_data[0x24:0x28])[0]
    boot_sector["extended_flags"] = struct.unpack("<H", boot_sector_data[0x28:0x2a])[0]
    boot_sector["version"] = struct.unpack("<H", boot_sector_data[0x2a:0x2c])[0]
    boot_sector["root_cluster"] = struct.unpack("<I", boot_sector_data[0x2c:0x30])[0]
    boot_sector["system_information_sector"] = struct.unpack("<H", boot_sector_data[0x30:0x32])[0]
    boot_sector["backup_boot_sector"] = struct.unpack("<H", boot_sector_data[0x32:0x34])[0]
    boot_sector["physical_drive"] = struct.unpack("<B", boot_sector_data[0x40:0x41])[0]
    boot_sector["extended_signature"] = struct.unpack("<B", boot_sector_data[0x42:0x43])[0]
    boot_sector["serial_number"] = struct.unpack("<I", boot_sector_data[0x43:0x47])[0]
    boot_sector["volume_label"] = boot_sector_data[0x47:0x52]
    boot_sector["file_system"] = boot_sector_data[0x52:0x5a]

    return boot_sector
# -----------------------------------------------------------------------------------|
def print_parse_fs_info_data(fs_info):
    print('[+] FS Info')
    print(f' [-] lead_signature: {hex(fs_info["lead_signature"])}')
    print(f' [-] struct_signature: {hex(fs_info["struct_signature"])}')
    print(f' [-] number_of_free_cluster: {hex(fs_info["number_of_free_cluster"])}')
    print(f' [-] next_free_cluster: {hex(fs_info["next_free_cluster"])}')
    print(f' [-] tail_signature: {hex(fs_info["tail_signature"])}')

# -----------------------------------------------------------------------------------|
def parse_fs_info_data(file_path, boot_sector, partition_entry_struct):
    with open(file_path, "rb") as f:
        f.seek(partition_entry_struct["first_sector"] + boot_sector["system_information_sector"] * SECTOR_SIZE)
        fs_info_data = f.read(SECTOR_SIZE)

    fs_info = {}
    fs_info["lead_signature"] = struct.unpack("<I", fs_info_data[:0x4])[0]
    fs_info["struct_signature"] = struct.unpack("<I", fs_info_data[0x1e4:0x1e8])[0]
    fs_info["number_of_free_cluster"] = struct.unpack("<I", fs_info_data[0x1e8:0x1ec])[0]
    fs_info["next_free_cluster"] = struct.unpack("<I", fs_info_data[0x1ec:0x1f0])[0]
    fs_info["tail_signature"] =struct.unpack("<H", fs_info_data[0x1fe:0x200])[0]

    return fs_info

# -----------------------------------------------------------------------------------|
def print_parse_boot_strap_data(boot_strap):
    if boot_strap["boot_strap_data"] != b'\x00' * len(boot_strap["boot_strap_data"]):
        print(f'[+] Boot Strap: ') 
        print(f' [-] boot_strap_data: 0x{(boot_strap["boot_strap_data"]).hex()}')
        print(f' [-] signature: {hex(boot_strap["signature"])}')   

# -----------------------------------------------------------------------------------|
def parse_boot_strap_data(file_path, boot_sector, partition_entry_struct):
    with open(file_path, "rb") as f:
        f.seek((partition_entry_struct["first_sector"] + boot_sector["system_information_sector"] * SECTOR_SIZE) + SECTOR_SIZE)
        boot_strap_data = f.read(SECTOR_SIZE)

        boot_strap = {}
        boot_strap["boot_strap_data"] = boot_strap_data[:0x1fe]
        boot_strap["signature"] = struct.unpack("<H", boot_strap_data[0x1fe:0x200])[0]

        return boot_strap
# -----------------------------------------------------------------------------------|
'''   
def info_created_time(root_directory_enrty):
    if root_directory_enrty["created_time"] != 0:   
        binary_created_time = bin(root_directory_enrty["created_time"])[2:]
        hour = int(binary_created_time[:5], 2)
        minute = int(binary_created_time[5:11], 2)
        second = int(binary_created_time[11:], 2) * 2
        print(f'   [-] created_time: {hour}시{minute}분{second}초')

    else:   
        print(f'   [-] created_time: {bin(root_directory_enrty["created_time"])}')
           
# -----------------------------------------------------------------------------------|\
def info_created_date(root_directory_enrty):
    if root_directory_enrty["created_date"] != 0:   
        binary_created_date = bin(root_directory_enrty["created_date"])[2:]
        year = int(binary_created_date[:7], 2) + 1980
        month = int(binary_created_date[7:12], 2)
        day = int(binary_created_date[12:], 2)
        print(f'   [-] created_time: {year}년{month}월{day}일')
    else:   
        print(f'   [-] created_date: {bin(root_directory_enrty["created_date"])}')  
'''
# -----------------------------------------------------------------------------------|
def print_parse_root_directory_enrty_data(root_directory_enrty):
    print(f'[+] Root Directory Entry Information')
    print(f' [-] name: {(root_directory_enrty["name"].decode("ascii"))}')
    print(f' [-] extensions: {(root_directory_enrty["extensions"].decode("ascii"))}')
    print(f' [-] attribute: {hex(root_directory_enrty["attribute"])}')
    print(f' [-] created_time: {hex(root_directory_enrty["created_time"])}')
    print(f' [-] created_date: {hex(root_directory_enrty["created_date"])}')
    print(f' [-] first_cluster(high): {hex(root_directory_enrty["first_cluster(high)"])}')
    print(f' [-] first_cluster(low): {hex(root_directory_enrty["first_cluster(low)"])}')
    print(f' [-] file_size: {hex(root_directory_enrty["file_size"])}')

# -----------------------------------------------------------------------------------|
def parse_root_directory_enrty_data(file_path, partition_entry_struct, boot_sector):
    with open(file_path, "rb") as f:
        f.seek(partition_entry_struct["first_sector"] +
               (boot_sector["reserved_sectors"] * boot_sector["bytes_per_sector"]) + 
               (boot_sector["number_of_fats"] * boot_sector["sectors_per_fat"] * boot_sector["bytes_per_sector"]))
        root_directory_enrty_data = f.read(CLUSTER_SIZE)
    
    list_sub_dierctory_entry_offset = []
    entry_size = 0x20
    entry_loc = 0
   
    while(entry_loc < 80):
        entry_offset = entry_loc * entry_size
        root_directory_enrty = {}

        root_directory_enrty["name"] = root_directory_enrty_data[entry_offset:entry_offset+0x8]
        root_directory_enrty["extensions"] = root_directory_enrty_data[entry_offset+0x8:entry_offset+0xb]
        root_directory_enrty["attribute"] = struct.unpack("<B", root_directory_enrty_data[entry_offset+0xb:entry_offset+0xc])[0]
        root_directory_enrty["created_time"] = struct.unpack("<H", root_directory_enrty_data[entry_offset+0xe:entry_offset+0x10])[0]
        root_directory_enrty["created_date"] = struct.unpack("<H", root_directory_enrty_data[entry_offset+0x10:entry_offset+0x12])[0]
        root_directory_enrty["first_cluster(high)"] = struct.unpack("<H", root_directory_enrty_data[entry_offset+0x14:entry_offset+0x16])[0]
        root_directory_enrty["first_cluster(low)"] = struct.unpack("<H", root_directory_enrty_data[entry_offset+0x1a:entry_offset+0x1c])[0]
        root_directory_enrty["file_size"] = struct.unpack("<I", root_directory_enrty_data[entry_offset+0x1c:entry_offset+0x20])[0]
        
        if (root_directory_enrty["name"] != (b'\x00' * len(root_directory_enrty["name"]))) and (root_directory_enrty["attribute"] != 0xf): 
            print_parse_root_directory_enrty_data(root_directory_enrty)
            sub_dierctory_entry_offset = root_directory_enrty["first_cluster(low)"] - 2
            list_sub_dierctory_entry_offset.append(sub_dierctory_entry_offset)
            parse_sub_directory_enrty_data(file_path, partition_entry_struct, boot_sector, list_sub_dierctory_entry_offset)
            entry_loc += 1
            continue

        elif (root_directory_enrty["name"] != (b'\x00' * len(root_directory_enrty["name"]))) and (root_directory_enrty["attribute"] == 0xf):
            lfn_entry = parse_root_lfn_entry_data(root_directory_enrty_data, entry_offset)
            print_parse_root_lfn_entry_data(lfn_entry)
            entry_loc += 1
            continue

        elif ((root_directory_enrty["name"][:2]) == b'\xE5'):
            print(f'[+] Deleted Root Directory Entry Information')
            print_parse_root_directory_enrty_data(root_directory_enrty)
            entry_loc += 1
            continue 

        else:   
            break

    return list_sub_dierctory_entry_offset             

# -----------------------------------------------------------------------------------|
def print_parse_sub_directory_enrty_data(sub_directory_enrty):
    print(f'[+] Sub Directory Entry Information')
    print(f' [-] name: {(sub_directory_enrty["name"].decode("ascii") if all(32 <= x <= 126 for x in sub_directory_enrty["name"]) else sub_directory_enrty["name"].decode("utf-16"))}')
    print(f' [-] extensions: {(sub_directory_enrty["extensions"].decode("ascii") if all(32 <= x <= 126 for x in sub_directory_enrty["extensions"]) else sub_directory_enrty["extensions"].decode("utf-16"))}')
    print(f' [-] attribute: {hex(sub_directory_enrty["attribute"])}')
    print(f' [-] created_time: {hex(sub_directory_enrty["created_time"])}')
    print(f' [-] created_date: {hex(sub_directory_enrty["created_date"])}')
    print(f' [-] first_cluster(high): {hex(sub_directory_enrty["first_cluster(high)"])}')
    print(f' [-] first_cluster(low): {hex(sub_directory_enrty["first_cluster(low)"])}')
    print(f' [-] file_size: {hex(sub_directory_enrty["file_size"])}')

# -----------------------------------------------------------------------------------|
def parse_sub_directory_enrty_data(file_path, partition_entry_struct, boot_sector, list_sub_dierctory_entry_offset):
    with open(file_path, "rb") as f:
        for i in range(len(list_sub_dierctory_entry_offset)):
            f.seek(partition_entry_struct["first_sector"] +
               (boot_sector["reserved_sectors"] * boot_sector["bytes_per_sector"]) + 
               (boot_sector["number_of_fats"] * boot_sector["sectors_per_fat"] * boot_sector["bytes_per_sector"]) +
               list_sub_dierctory_entry_offset[i] * CLUSTER_SIZE)
            sub_directory_enrty_data = f.read(CLUSTER_SIZE)
    
        entry_size = 0x20
        entry_loc = 0
   
        while(entry_loc < 80):
            entry_offset = entry_loc * entry_size
            sub_directory_enrty = {}

            sub_directory_enrty["name"] = sub_directory_enrty_data[entry_offset:entry_offset+0x8]
            sub_directory_enrty["extensions"] = sub_directory_enrty_data[entry_offset+0x8:entry_offset+0xb]
            sub_directory_enrty["attribute"] = struct.unpack("<B", sub_directory_enrty_data[entry_offset+0xb:entry_offset+0xc])[0]
            sub_directory_enrty["created_time"] = struct.unpack("<H", sub_directory_enrty_data[entry_offset+0xe:entry_offset+0x10])[0]
            sub_directory_enrty["created_date"] = struct.unpack("<H", sub_directory_enrty_data[entry_offset+0x10:entry_offset+0x12])[0]
            sub_directory_enrty["first_cluster(high)"] = struct.unpack("<H", sub_directory_enrty_data[entry_offset+0x14:entry_offset+0x16])[0]
            sub_directory_enrty["first_cluster(low)"] = struct.unpack("<H", sub_directory_enrty_data[entry_offset+0x1a:entry_offset+0x1c])[0]
            sub_directory_enrty["file_size"] = struct.unpack("<I", sub_directory_enrty_data[entry_offset+0x1c:entry_offset+0x20])[0]
        
            if (sub_directory_enrty["name"] != (b'\x00' * len(sub_directory_enrty["name"]))) and (sub_directory_enrty["attribute"] != 0xf): 
                print_parse_sub_directory_enrty_data(sub_directory_enrty)
                entry_loc += 1
                continue

            elif (sub_directory_enrty["name"] != (b'\x00' * len(sub_directory_enrty["name"]))) and (sub_directory_enrty["attribute"] == 0xf):
                parse_sub_lfn_entry_data(sub_directory_enrty_data, entry_offset)
                entry_loc += 1
                continue

            else:   
                break
          
# -----------------------------------------------------------------------------------|
def print_parse_root_lfn_entry_data(lfn_entry):
    print(f' [+] Root LFN Entry Information') 
    print(f'  [-] sequence_number: 0x{(lfn_entry["sequence_number"]).hex()}')
    print(f'  [-] attribute: 0x{(lfn_entry["attribute"]).hex()}')
    print(f'  [-] name1: {(lfn_entry["name1"].decode("ascii") if all(32 <= x <= 126 for x in lfn_entry["name1"]) else lfn_entry["name1"].decode("utf-16"))}')
    print(f'  [-] name2: {(lfn_entry["name2"].decode("ascii") if all(32 <= x <= 126 for x in lfn_entry["name2"]) else lfn_entry["name1"].decode("utf-16"))}')
    print(f'  [-] name3: {(lfn_entry["name3"].decode("ascii") if all(32 <= x <= 126 for x in lfn_entry["name3"]) else lfn_entry["name1"].decode("utf-16"))}') 
 
# -----------------------------------------------------------------------------------|
def print_parse_sub_lfn_entry_data(lfn_entry):
    print(f'  [+] Sub LFN Entry Information') 
    print(f'   [-] sequence_number: 0x{(lfn_entry["sequence_number"]).hex()}')
    print(f'   [-] attribute: 0x{(lfn_entry["attribute"]).hex()}')
    print(f'   [-] name1: {(lfn_entry["name1"].decode("ascii") if all(32 <= x <= 126 for x in lfn_entry["name1"]) else lfn_entry["name1"].decode("utf-16"))}')
    print(f'   [-] name2: {(lfn_entry["name2"].decode("ascii") if all(32 <= x <= 126 for x in lfn_entry["name2"]) else lfn_entry["name1"].decode("utf-16"))}')
    print(f'   [-] name3: {(lfn_entry["name3"].decode("ascii") if all(32 <= x <= 126 for x in lfn_entry["name3"]) else lfn_entry["name1"].decode("utf-16"))}')

# -----------------------------------------------------------------------------------| 
def parse_root_lfn_entry_data(root_directory_enrty_data, entry_offset):  
    lfn_entry ={}
    lfn_entry["sequence_number"] =  root_directory_enrty_data[entry_offset:entry_offset+0x1]
    lfn_entry["attribute"] = root_directory_enrty_data[entry_offset+0xb:entry_offset+0xc]
    name1 = root_directory_enrty_data[entry_offset+0x1:entry_offset+0xb]
    name2 = root_directory_enrty_data[entry_offset+0xe:entry_offset+0x1a]
    name3 = root_directory_enrty_data[entry_offset+0x1c:entry_offset+0x20]
    lfn_entry["name1"] =  bytes([x for x in name1 if x != 0xFF])
    lfn_entry["name2"] =  bytes([x for x in name2 if x != 0xFF])
    lfn_entry["name3"] =  bytes([x for x in name3 if x != 0xFF])

    return lfn_entry

# -----------------------------------------------------------------------------------|
def parse_sub_lfn_entry_data(sub_directory_enrty_data, entry_offset):  
    lfn_entry ={}
    lfn_entry["sequence_number"] =  sub_directory_enrty_data[entry_offset:entry_offset+0x1]
    lfn_entry["attribute"] = sub_directory_enrty_data[entry_offset+0xb:entry_offset+0xc]
    lfn_entry["checksum"] = struct.unpack("<B", sub_directory_enrty_data[entry_offset+0xd:entry_offset+0xe])[0]
    name1 = sub_directory_enrty_data[entry_offset+0x1:entry_offset+0xb]
    name2 = sub_directory_enrty_data[entry_offset+0xe:entry_offset+0x1a]
    name3 = sub_directory_enrty_data[entry_offset+0x1c:entry_offset+0x20]
    lfn_entry["name1"] =  bytes([x for x in name1 if x != 0xFF])
    lfn_entry["name2"] =  bytes([x for x in name2 if x != 0xFF])
    lfn_entry["name3"] =  bytes([x for x in name3 if x != 0xFF])

    if lfn_entry["checksum"] == 0xff:   
        return 0
    
    else:   
        print_parse_sub_lfn_entry_data(lfn_entry)

# -----------------------------------------------------------------------------------|
def print_partition_entry_data(list_partition_entry):
    print(f'[+] MBR Partition Entry Information')
    for i in range(len(list_partition_entry)):
        print(f' [-] partition entry #{i+1} ')
        print(f'   [-] active_partition_flag: {hex(list_partition_entry[i]["active_partition_flag"])}')
        print(f'   [-] filesystem_id: {hex(list_partition_entry[i]["filesystem_id"])}')
        print(f'   [-] first_sector: {hex(list_partition_entry[i]["first_sector"])}')
        print(f'   [-] total_sectors: {hex(list_partition_entry[i]["total_sectors"])}')

# -----------------------------------------------------------------------------------|
def parse_partition_table(file_path, br_start_offset, mbr_data):
    list_partition_entry = []
    cnt_entry = 0
   
    while(cnt_entry < 4):
        partition_entry_struct = {}
        entry_offset = 0x1be + (cnt_entry*0x10)
       
        partition_entry_struct["active_partition_flag"] = struct.unpack("<B", mbr_data[entry_offset:entry_offset+0x1])[0]
        partition_entry_struct["filesystem_id"] = struct.unpack("<B", mbr_data[entry_offset+0x4:entry_offset+0x5])[0]
        partition_entry_struct["first_sector"] = br_start_offset + struct.unpack("<I", mbr_data[entry_offset+0x8:entry_offset+0xc])[0] * SECTOR_SIZE
        partition_entry_struct["total_sectors"] = struct.unpack("<I", mbr_data[entry_offset+0xc:entry_offset+0x10])[0] * SECTOR_SIZE
        
        if partition_entry_struct["filesystem_id"] == 0xc:
            boot_sector = parse_boot_sector_data(file_path, partition_entry_struct)
            print_boot_sector_data(boot_sector)
            fs_info = parse_fs_info_data(file_path, boot_sector, partition_entry_struct)
            print_parse_fs_info_data(fs_info)
            boot_strap = parse_boot_strap_data(file_path, boot_sector, partition_entry_struct)
            print_parse_boot_strap_data(boot_strap)
            parse_root_directory_enrty_data(file_path, partition_entry_struct, boot_sector)
            break
        
        if  (partition_entry_struct["active_partition_flag"] == 0 & partition_entry_struct["filesystem_id"] == 0xee    
             & partition_entry_struct["total_sectors"] == 0xffffffff):  
            print("This is a Protective MBR.")
            break
       
        if (partition_entry_struct["filesystem_id"] != 5) and (partition_entry_struct["total_sectors"] != 0):
            list_partition_entry.append(partition_entry_struct)
            cnt_entry = cnt_entry+1
            continue
        elif partition_entry_struct["filesystem_id"] == 5:
            br_start_offset = partition_entry_struct["first_sector"]
            with open(file_path, "rb") as f:
                f.seek(br_start_offset)
                mbr_data = f.read(SECTOR_SIZE)
            cnt_entry = 0
            continue
        elif partition_entry_struct["total_sectors"] == 0:
            break
           
    return list_partition_entry

# file_path의 파일에서 MBR 데이터 파싱
# -----------------------------------------------------------------------------------
def parse_mbr(file_path):
# 1. 파일 오픈
# 2. 1개 섹터 read
    with open(file_path, "rb") as f:
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
    list_partition_entry = parse_partition_table(file_path, br_start_offset, mbr_data)
   
               
# -----------------------------------------------------------------------------------    
file_path = "C:\\Users\\JUNSUNG\\Desktop\\수업\\파일시스템\\USB_4GB.dd"
try:
    os.path.isfile(file_path) # file_path가 파일인지 확인
    mbr_data = parse_mbr(file_path) # file_path의 파일에서 MBR 데이터 파싱

except Exception as e:
    print(e)