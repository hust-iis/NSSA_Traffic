import copy
import time
from datetime import datetime
import csv
import os
import pickle
import shutil

import pandas as pd
import pyinotify
from distutils.log import info
from elftools.elf.elffile import ELFFile
import sys
from pathlib import Path

from kafka import KafkaConsumer

sys.path.append(str(Path(__file__).resolve().parents[1]))
from msg_models.models import AbnormalFlowModel, FLOW_TYPE_TROJAN


class trojan_Detector:
    # 初始化：配置项
    def __init__(self, test_path, model_path, traffic_consumer, event_producer, topic) -> None:
        # 消息队列
        self.MQ_Traffic = traffic_consumer
        self.MQ_Event = event_producer
        self.MQ_Event_Topic = topic

        # 目录
        self.test_path = test_path
        self.model_path = model_path

    def checkTrojan(self, filepath):

        input = filepath
        label = 'test_trojan'

        try:
            info_dictionaries = []
            labelCsvFile = "./Trojan/Data/%s.csv" % label

            if os.path.isdir(input):
                input_dir = input
                for filename in os.listdir(input_dir):
                    info_dictionary = get_elf_info(input_dir + "/" + filename, label)
                    if (info_dictionary == None):
                        continue
                    info_dictionaries.append(info_dictionary)

                df = pd.DataFrame(info_dictionaries)
                df.to_csv(labelCsvFile, index=False)


            elif os.path.isfile(input):
                input_file = input
                info_file = get_elf_info(input_file, label)
                df = pd.DataFrame(info_file)
                df.to_csv(labelCsvFile, index=False)

        except pd.errors.EmptyDataError:
            print("Error: Get_elf_info File is empty.")
        except pd.errors.ParserError:
            print("Error: Get_elf_info Unable to parse the file.")

        try:
            # 数据处理，数据清洗
            clean_dataset(label)
            # print("Finish cleaning ...")

            # 读取数据处理的中转文件
            labelCsvFile = "./Trojan/Data/%s.csv" % label
            df = pd.read_csv(labelCsvFile, low_memory=False)

            # 进行数据处理
            data = df
            data_row = data.select_dtypes(exclude=['object'])
            data = data_row[['elf_head_e_type', 'elf_head_ident_EI_OSABI',
                             'dwarf_info_config_machine_arch', 'machine_arch',
                             'dwarf_info_config_default_address_size', 'elf_head_e_phentsize',
                             'elf_head_ident_EI_CLASS', 'seg0_head_p_type', 'has_dwarf_info',
                             'elf_head_e_phnum', 'seg1_PT_LOAD_p_flags',
                             'section_ctors_sh_flags', 'section_text_sh_name',
                             'section_rodata_sh_name', 'elf_head_e_ehsize', 'num_segments',
                             'section_dtors_sh_flags', 'section_data_sh_name',
                             'section_fini_sh_name', 'elf_head_e_shentsize',
                             'section_ctors_sh_name', 'seg2_PT_GNU_STACK_p_flags',
                             'section_init_sh_name', 'section_dtors_sh_name',
                             'section_ctors_sh_addralign', 'section_dtors_sh_addralign',
                             'section_bss_sh_name', 'section_bss_sh_size', 'elf_head_e_machine',
                             'section_shstrtab_sh_name', 'shstrndx', 'elf_head_e_shstrndx',
                             'seg2_PT_GNU_STACK_p_align', 'elf_head_e_shnum',
                             'seg0_PT_LOAD_p_filesz', 'section_shstrtab_sh_size',
                             'num_sections', 'elf_head_e_entry', 'seg0_PT_LOAD_p_memsz',
                             'sec_header_sh_size', 'seg1_PT_LOAD_p_memsz', 'file_size',
                             'seg0_PT_LOAD_p_flags', 'seg1_PT_LOAD_p_vaddr',
                             'section_rodata_sh_offset', 'sec_header_sh_name',
                             'elf_head_e_shoff', 'section_data_sh_addralign',
                             'section_rodata_sh_addr', 'section_rodata_sh_size',
                             'seg1_PT_LOAD_p_paddr', 'section_fini_sh_offset',
                             'section_bss_sh_offset', 'section_ctors_sh_addr',
                             'section_text_sh_size', 'sec_header_sh_offset',
                             'section_ctors_sh_offset', 'section_data_sh_size',
                             'section_data_sh_offset', 'seg1_PT_LOAD_p_offset',
                             'section_init_sh_addralign', 'section_dtors_sh_addr']]
            X = data

            fr = open(self.model_path, "rb")
            rf = pickle.load(fr)

            pred = rf.predict(X)

            for file, ans in zip(df['file_name'], pred):
                if os.path.isdir(input):  # 扫描的是路径
                    file_path = os.path.join(input, file)
                    print(file_path, ans)
                    if ans == 1:
                        return 1  # self.log_attack(file_path)

                elif os.path.isfile(input):
                    file_path = input  # 扫描的是文件
                    print(file_path, ans)
                    if ans == 1:
                        return 1  # self.log_attack(file_path)


        except pd.errors.EmptyDataError:
            # print("Error: Handle File is empty.")
            pass
        except pd.errors.ParserError:
            # print("Error: Handle Unable to parse the file.")
            pass
        return 0

    def detect(self, file_path):
        # 判断传参
        if len(file_path) == 0:
            file_path = self.test_path

        filename = 'other.abc'
        # 逐包读取
        for msg in self.MQ_Traffic:
            # 获取ftp传输的文件
            pkt = pickle.loads(msg.value)
            # 确定传输文件名以及后缀
            if len(pkt.layers) >= 4:
                my_request_command = ""
                my_request_arg = ""
                if pkt.layers[3].layer_name == 'ftp':
                    ftp_pkt = pkt.layers[3]
                    print("ftp输出")
                    print(pkt.layers[3].field_names)
                    if 'request_command' in pkt.layers[3].field_names:
                        print("request_command")
                        my_request_command = pkt.layers[3].request_command
                        print(pkt.layers[3].request_command)
                    if 'request_arg' in pkt.layers[3].field_names:
                        print("request_arg")
                        my_request_arg = pkt.layers[3].request_arg
                        print(pkt.layers[3].request_arg)
                    if my_request_command == 'RETR':
                        filename = my_request_arg
            if filename == 'other.abc':
                continue
            else:
                # 已经获取传输的文件名，保存FTP中传输的文件数据为文件用于病毒检测
                print(pkt.highest_layer)
                dst_ip = pkt.ip.dst
                src_ip = pkt.ip.src
                if len(pkt.layers) >= 4 and pkt.layers[3].layer_name == 'ftp-data' and pkt.highest_layer == 'DATA-TEXT-LINES':
                    print("完整的FTP-DATA pkt")
                    print(pkt)
                    ftp_data = pkt.layers[9]
                    # 保存ftp文件到test目录下
                    writefile(filename, ftp_data, file_path)

                # checkTrojan
                checkfile = file_path+filename
                res = self.checkTrojan(checkfile)
                if res == 1:
                    # 发送消息到事件队列
                    event = AbnormalFlowModel(
                        type=FLOW_TYPE_TROJAN,
                        time=datetime.now(),
                        src=src_ip,
                        dst=dst_ip,
                        detail=copy.deepcopy(pkt))
                    message = pickle.dumps(event)
                    self.MQ_Event.send(self.MQ_Event_Topic, message)

                # 删除文件
                os.remove(checkfile)
                # 修改filename为默认值
                filename = 'other.abc'



# 处理文件，获取elf特征值，存入处理csv中
def get_elf_info(elf, label):
    try:
        # print("reading file - " + elf)    
        with open(elf, 'rb') as elffile:
            features_dict = {}

            features_dict['file_name'] = os.path.basename(elffile.name)
            features_dict['file_size'] = os.path.getsize(elffile.name)

            elffile = ELFFile(elffile)

            num_sections = elffile.num_sections()
            num_segments = elffile.num_segments()
            has_dwarf_info = elffile.has_dwarf_info()
            dwarf_info_config_machine_arch = (elffile.get_dwarf_info().config.machine_arch)
            dwarf_info_config_default_address_size = (elffile.get_dwarf_info().config.default_address_size)
            dwarf_info_config_little_endian = (elffile.get_dwarf_info().config.little_endian)
            dwarf_info_debug_info_sec = (elffile.get_dwarf_info().debug_info_sec)
            if dwarf_info_debug_info_sec is not None:
                dwarf_info_debug_info_sec_name = (elffile.get_dwarf_info().debug_info_sec.name)
                dwarf_info_debug_info_sec_global_offset = (elffile.get_dwarf_info().debug_info_sec.global_offset)
                dwarf_info_debug_info_sec_size = (elffile.get_dwarf_info().debug_info_sec.size)
                dwarf_info_debug_info_sec_address = (elffile.get_dwarf_info().debug_info_sec.address)
            else:
                dwarf_info_debug_info_sec_name = None
                dwarf_info_debug_info_sec_global_offset = None
                dwarf_info_debug_info_sec_size = None
                dwarf_info_debug_info_sec_address = None
            dwarf_info_debug_aranges_sec = (elffile.get_dwarf_info().debug_aranges_sec)
            if dwarf_info_debug_aranges_sec is not None:
                dwarf_info_debug_aranges_sec_name = (elffile.get_dwarf_info().debug_aranges_sec.name)
                dwarf_info_debug_aranges_sec_global_offset = (elffile.get_dwarf_info().debug_aranges_sec.global_offset)
                dwarf_info_debug_aranges_sec_size = (elffile.get_dwarf_info().debug_aranges_sec.size)
                dwarf_info_debug_aranges_sec_address = (elffile.get_dwarf_info().debug_aranges_sec.address)
            else:
                dwarf_info_debug_aranges_sec_name = None
                dwarf_info_debug_aranges_sec_global_offset = None
                dwarf_info_debug_aranges_sec_size = None
                dwarf_info_debug_aranges_sec_address = None
            dwarf_info_debug_abbrev_sec = (elffile.get_dwarf_info().debug_abbrev_sec)
            if dwarf_info_debug_abbrev_sec is not None:
                dwarf_info_debug_abbrev_sec_name = (elffile.get_dwarf_info().debug_abbrev_sec.name)
                dwarf_info_debug_abbrev_sec_global_offset = (elffile.get_dwarf_info().debug_abbrev_sec.global_offset)
                dwarf_info_debug_abbrev_sec_size = (elffile.get_dwarf_info().debug_abbrev_sec.size)
                dwarf_info_debug_abbrev_sec_address = (elffile.get_dwarf_info().debug_abbrev_sec.address)
            else:
                dwarf_info_debug_abbrev_sec_name = None
                dwarf_info_debug_abbrev_sec_global_offset = None
                dwarf_info_debug_abbrev_sec_size = None
                dwarf_info_debug_abbrev_sec_address = None
            dwarf_info_debug_frame_sec = (elffile.get_dwarf_info().debug_frame_sec)
            if dwarf_info_debug_frame_sec is not None:
                dwarf_info_debug_frame_sec_name = (elffile.get_dwarf_info().debug_frame_sec.name)
                dwarf_info_debug_frame_sec_global_offset = (elffile.get_dwarf_info().debug_frame_sec.global_offset)
                dwarf_info_debug_frame_sec_size = (elffile.get_dwarf_info().debug_frame_sec.size)
                dwarf_info_debug_frame_sec_address = (elffile.get_dwarf_info().debug_frame_sec.address)
            else:
                dwarf_info_debug_frame_sec_name = None
                dwarf_info_debug_frame_sec_global_offset = None
                dwarf_info_debug_frame_sec_size = None
                dwarf_info_debug_frame_sec_address = None
            dwarf_info_debug_str_sec = (elffile.get_dwarf_info().debug_str_sec)
            if dwarf_info_debug_str_sec is not None:
                dwarf_info_debug_str_sec_name = (elffile.get_dwarf_info().debug_str_sec.name)
                dwarf_info_debug_str_sec_global_offset = (elffile.get_dwarf_info().debug_str_sec.global_offset)
                dwarf_info_debug_str_sec_size = (elffile.get_dwarf_info().debug_str_sec.size)
                dwarf_info_debug_str_sec_address = (elffile.get_dwarf_info().debug_str_sec.address)
            else:
                dwarf_info_debug_str_sec_name = None
                dwarf_info_debug_str_sec_global_offset = None
                dwarf_info_debug_str_sec_size = None
                dwarf_info_debug_str_sec_address = None
            dwarf_info_debug_loc_sec = (elffile.get_dwarf_info().debug_loc_sec)
            if dwarf_info_debug_loc_sec is not None:
                dwarf_info_debug_loc_sec_name = (elffile.get_dwarf_info().debug_loc_sec.name)
                dwarf_info_debug_loc_sec_global_offset = (elffile.get_dwarf_info().debug_loc_sec.global_offset)
                dwarf_info_debug_loc_sec_size = (elffile.get_dwarf_info().debug_loc_sec.size)
                dwarf_info_debug_loc_sec_address = (elffile.get_dwarf_info().debug_loc_sec.address)
            else:
                dwarf_info_debug_loc_sec_name = None
                dwarf_info_debug_loc_sec_global_offset = None
                dwarf_info_debug_loc_sec_size = None
                dwarf_info_debug_loc_sec_address = None
            dwarf_info_debug_ranges_sec = (elffile.get_dwarf_info().debug_ranges_sec)
            if dwarf_info_debug_ranges_sec is not None:
                dwarf_info_debug_ranges_sec_name = (elffile.get_dwarf_info().debug_ranges_sec.name)
                dwarf_info_debug_ranges_sec_global_offset = (elffile.get_dwarf_info().debug_ranges_sec.global_offset)
                dwarf_info_debug_ranges_sec_size = (elffile.get_dwarf_info().debug_ranges_sec.size)
                dwarf_info_debug_ranges_sec_address = (elffile.get_dwarf_info().debug_ranges_sec.address)
            else:
                dwarf_info_debug_ranges_sec_name = None
                dwarf_info_debug_ranges_sec_global_offset = None
                dwarf_info_debug_ranges_sec_size = None
                dwarf_info_debug_ranges_sec_address = None
            dwarf_info_debug_line_sec = (elffile.get_dwarf_info().debug_line_sec)
            if dwarf_info_debug_line_sec is not None:
                dwarf_info_debug_line_sec_name = (elffile.get_dwarf_info().debug_line_sec.name)
                dwarf_info_debug_line_sec_global_offset = (elffile.get_dwarf_info().debug_line_sec.global_offset)
                dwarf_info_debug_line_sec_size = (elffile.get_dwarf_info().debug_line_sec.size)
                dwarf_info_debug_line_sec_address = (elffile.get_dwarf_info().debug_line_sec.address)
            else:
                dwarf_info_debug_line_sec_name = None
                dwarf_info_debug_line_sec_global_offset = None
                dwarf_info_debug_line_sec_size = None
                dwarf_info_debug_line_sec_address = None
            dwarf_info_debug_pubtypes_sec = (elffile.get_dwarf_info().debug_pubtypes_sec)
            if dwarf_info_debug_pubtypes_sec is not None:
                dwarf_info_debug_pubtypes_sec_name = (elffile.get_dwarf_info().debug_pubtypes_sec.name)
                dwarf_info_debug_pubtypes_sec_global_offset = (
                    elffile.get_dwarf_info().debug_pubtypes_sec.global_offset)
                dwarf_info_debug_pubtypes_sec_size = (elffile.get_dwarf_info().debug_pubtypes_sec.size)
                dwarf_info_debug_pubtypes_sec_address = (elffile.get_dwarf_info().debug_pubtypes_sec.address)
            else:
                dwarf_info_debug_pubtypes_sec_name = None
                dwarf_info_debug_pubtypes_sec_global_offset = None
                dwarf_info_debug_pubtypes_sec_size = None
                dwarf_info_debug_pubtypes_sec_address = None
            dwarf_info_debug_pubnames_sec = (elffile.get_dwarf_info().debug_pubnames_sec)
            if dwarf_info_debug_pubnames_sec is not None:
                dwarf_info_debug_pubnames_sec_name = (elffile.get_dwarf_info().debug_pubnames_sec.name)
                dwarf_info_debug_pubnames_sec_global_offset = (
                    elffile.get_dwarf_info().debug_pubnames_sec.global_offset)
                dwarf_info_debug_pubnames_sec_size = (elffile.get_dwarf_info().debug_pubnames_sec.size)
                dwarf_info_debug_pubnames_sec_address = (elffile.get_dwarf_info().debug_pubnames_sec.address)
            else:
                dwarf_info_debug_pubnames_sec_name = None
                dwarf_info_debug_pubnames_sec_global_offset = None
                dwarf_info_debug_pubnames_sec_size = None
                dwarf_info_debug_pubnames_sec_address = None
            has_ehabi_info = (elffile.has_ehabi_info())
            ehabi_infos = (elffile.get_ehabi_infos())
            machine_arch = (elffile.get_machine_arch())
            shstrndx = (elffile.get_shstrndx())
            identify_file = (elffile._identify_file())
            sec_header_sh_name = (elffile._get_section_header_stringtable().header.sh_name)
            sec_header_sh_type = (elffile._get_section_header_stringtable().header.sh_type)
            sec_header_sh_flags = (elffile._get_section_header_stringtable().header.sh_flags)
            sec_header_sh_addr = (elffile._get_section_header_stringtable().header.sh_addr)
            sec_header_sh_offset = (elffile._get_section_header_stringtable().header.sh_offset)
            sec_header_sh_size = (elffile._get_section_header_stringtable().header.sh_size)
            sec_header_sh_link = (elffile._get_section_header_stringtable().header.sh_link)
            sec_header_sh_info = (elffile._get_section_header_stringtable().header.sh_info)
            sec_header_sh_addralign = (elffile._get_section_header_stringtable().header.sh_addralign)
            sec_header_sh_entsize = (elffile._get_section_header_stringtable().header.sh_entsize)
            elf_head_ident_EI_MAG = (elffile._parse_elf_header().e_ident.EI_MAG)
            elf_head_ident_EI_CLASS = (elffile._parse_elf_header().e_ident.EI_CLASS)
            elf_head_ident_EI_DATA = (elffile._parse_elf_header().e_ident.EI_DATA)
            elf_head_ident_EI_VERSION = (elffile._parse_elf_header().e_ident.EI_VERSION)
            elf_head_ident_EI_OSABI = (elffile._parse_elf_header().e_ident.EI_OSABI)
            elf_head_ident_EI_ABIVERSION = (elffile._parse_elf_header().e_ident.EI_ABIVERSION)
            elf_head_e_type = (elffile._parse_elf_header().e_type)
            elf_head_e_machine = (elffile._parse_elf_header().e_machine)
            elf_head_e_version = (elffile._parse_elf_header().e_version)
            elf_head_e_entry = (elffile._parse_elf_header().e_entry)
            elf_head_e_phoff = (elffile._parse_elf_header().e_phoff)
            elf_head_e_shoff = (elffile._parse_elf_header().e_shoff)
            elf_head_e_flags = (elffile._parse_elf_header().e_flags)
            elf_head_e_ehsize = (elffile._parse_elf_header().e_ehsize)
            elf_head_e_phentsize = (elffile._parse_elf_header().e_phentsize)
            elf_head_e_phnum = (elffile._parse_elf_header().e_phnum)
            elf_head_e_shentsize = (elffile._parse_elf_header().e_shentsize)
            elf_head_e_shnum = (elffile._parse_elf_header().e_shnum)
            elf_head_e_shstrndx = (elffile._parse_elf_header().e_shstrndx)
            features_dict['num_sections'] = num_sections
            features_dict['num_segments'] = num_segments
            features_dict['has_dwarf_info'] = has_dwarf_info
            features_dict['dwarf_info_config_machine_arch'] = dwarf_info_config_machine_arch
            features_dict['dwarf_info_config_default_address_size'] = dwarf_info_config_default_address_size
            features_dict['dwarf_info_config_little_endian'] = dwarf_info_config_little_endian
            features_dict['dwarf_info_debug_info_sec_name'] = dwarf_info_debug_info_sec_name
            features_dict['dwarf_info_debug_info_sec_global_offset'] = dwarf_info_debug_info_sec_global_offset
            features_dict['dwarf_info_debug_info_sec_size'] = dwarf_info_debug_info_sec_size
            features_dict['dwarf_info_debug_info_sec_address'] = dwarf_info_debug_info_sec_address
            features_dict['dwarf_info_debug_aranges_sec_name'] = dwarf_info_debug_aranges_sec_name
            features_dict['dwarf_info_debug_aranges_sec_global_offset'] = dwarf_info_debug_aranges_sec_global_offset
            features_dict['dwarf_info_debug_aranges_sec_size'] = dwarf_info_debug_aranges_sec_size
            features_dict['dwarf_info_debug_aranges_sec_address'] = dwarf_info_debug_aranges_sec_address
            features_dict['dwarf_info_debug_abbrev_sec_name'] = dwarf_info_debug_abbrev_sec_name
            features_dict['dwarf_info_debug_abbrev_sec_global_offset'] = dwarf_info_debug_abbrev_sec_global_offset
            features_dict['dwarf_info_debug_abbrev_sec_size'] = dwarf_info_debug_abbrev_sec_size
            features_dict['dwarf_info_debug_abbrev_sec_address'] = dwarf_info_debug_abbrev_sec_address
            features_dict['dwarf_info_debug_frame_sec_name'] = dwarf_info_debug_frame_sec_name
            features_dict['dwarf_info_debug_frame_sec_global_offset'] = dwarf_info_debug_frame_sec_global_offset
            features_dict['dwarf_info_debug_frame_sec_size'] = dwarf_info_debug_frame_sec_size
            features_dict['dwarf_info_debug_frame_sec_address'] = dwarf_info_debug_frame_sec_address
            features_dict['dwarf_info_debug_str_sec_name'] = dwarf_info_debug_str_sec_name
            features_dict['dwarf_info_debug_str_sec_global_offset'] = dwarf_info_debug_str_sec_global_offset
            features_dict['dwarf_info_debug_str_sec_size'] = dwarf_info_debug_str_sec_size
            features_dict['dwarf_info_debug_str_sec_address'] = dwarf_info_debug_str_sec_address
            features_dict['dwarf_info_debug_loc_sec_name'] = dwarf_info_debug_loc_sec_name
            features_dict['dwarf_info_debug_loc_sec_global_offset'] = dwarf_info_debug_loc_sec_global_offset
            features_dict['dwarf_info_debug_loc_sec_size'] = dwarf_info_debug_loc_sec_size
            features_dict['dwarf_info_debug_loc_sec_address'] = dwarf_info_debug_loc_sec_address
            features_dict['dwarf_info_debug_ranges_sec_name'] = dwarf_info_debug_ranges_sec_name
            features_dict['dwarf_info_debug_ranges_sec_global_offset'] = dwarf_info_debug_ranges_sec_global_offset
            features_dict['dwarf_info_debug_ranges_sec_size'] = dwarf_info_debug_ranges_sec_size
            features_dict['dwarf_info_debug_ranges_sec_address'] = dwarf_info_debug_ranges_sec_address
            features_dict['dwarf_info_debug_line_sec_name'] = dwarf_info_debug_line_sec_name
            features_dict['dwarf_info_debug_line_sec_global_offset'] = dwarf_info_debug_line_sec_global_offset
            features_dict['dwarf_info_debug_line_sec_size'] = dwarf_info_debug_line_sec_size
            features_dict['dwarf_info_debug_line_sec_address'] = dwarf_info_debug_line_sec_address
            features_dict['dwarf_info_debug_pubtypes_sec_name'] = dwarf_info_debug_pubtypes_sec_name
            features_dict['dwarf_info_debug_pubtypes_sec_global_offset'] = dwarf_info_debug_pubtypes_sec_global_offset
            features_dict['dwarf_info_debug_pubtypes_sec_size'] = dwarf_info_debug_pubtypes_sec_size
            features_dict['dwarf_info_debug_pubtypes_sec_address'] = dwarf_info_debug_pubtypes_sec_address
            features_dict['dwarf_info_debug_pubnames_sec_name'] = dwarf_info_debug_pubnames_sec_name
            features_dict['dwarf_info_debug_pubnames_sec_global_offset'] = dwarf_info_debug_pubnames_sec_global_offset
            features_dict['dwarf_info_debug_pubnames_sec_size'] = dwarf_info_debug_pubnames_sec_size
            features_dict['dwarf_info_debug_pubnames_sec_address'] = dwarf_info_debug_pubnames_sec_address
            features_dict['has_ehabi_info'] = has_ehabi_info
            features_dict['ehabi_infos'] = ehabi_infos
            features_dict['machine_arch'] = machine_arch
            features_dict['shstrndx'] = shstrndx
            features_dict['identify_file'] = identify_file
            features_dict['sec_header_sh_name'] = sec_header_sh_name
            features_dict['sec_header_sh_type'] = sec_header_sh_type
            features_dict['sec_header_sh_flags'] = sec_header_sh_flags
            features_dict['sec_header_sh_addr'] = sec_header_sh_addr
            features_dict['sec_header_sh_offset'] = sec_header_sh_offset
            features_dict['sec_header_sh_size'] = sec_header_sh_size
            features_dict['sec_header_sh_link'] = sec_header_sh_link
            features_dict['sec_header_sh_info'] = sec_header_sh_info
            features_dict['sec_header_sh_addralign'] = sec_header_sh_addralign
            features_dict['sec_header_sh_entsize'] = sec_header_sh_entsize
            features_dict['elf_head_ident_EI_MAG'] = elf_head_ident_EI_MAG
            features_dict['elf_head_ident_EI_CLASS'] = elf_head_ident_EI_CLASS
            features_dict['elf_head_ident_EI_DATA'] = elf_head_ident_EI_DATA
            features_dict['elf_head_ident_EI_VERSION'] = elf_head_ident_EI_VERSION
            features_dict['elf_head_ident_EI_OSABI'] = elf_head_ident_EI_OSABI
            features_dict['elf_head_ident_EI_ABIVERSION'] = elf_head_ident_EI_ABIVERSION
            features_dict['elf_head_e_type'] = elf_head_e_type
            features_dict['elf_head_e_machine'] = elf_head_e_machine
            features_dict['elf_head_e_version'] = elf_head_e_version
            features_dict['elf_head_e_entry'] = elf_head_e_entry
            features_dict['elf_head_e_phoff'] = elf_head_e_phoff
            features_dict['elf_head_e_shoff'] = elf_head_e_shoff
            features_dict['elf_head_e_flags'] = elf_head_e_flags
            features_dict['elf_head_e_ehsize'] = elf_head_e_ehsize
            features_dict['elf_head_e_phentsize'] = elf_head_e_phentsize
            features_dict['elf_head_e_phnum'] = elf_head_e_phnum
            features_dict['elf_head_e_shentsize'] = elf_head_e_shentsize
            features_dict['elf_head_e_shnum'] = elf_head_e_shnum
            features_dict['elf_head_e_shstrndx'] = elf_head_e_shstrndx
            temp = 0
            for segment in elffile.iter_segments():
                seg_head_p_type = (segment.header.p_type)
                features_dict[f'seg{temp}_head_p_type'] = segment.header.p_type
                seg_head_p_offset = (segment.header.p_offset)
                seg_head_p_filesz = (segment.header.p_filesz)
                seg_head_p_memsz = (segment.header.p_memsz)
                seg_head_p_flags = (segment.header.p_flags)
                seg_head_p_align = (segment.header.p_align)
                seg_head_p_vaddr = (segment.header.p_vaddr)
                seg_head_p_paddr = (segment.header.p_paddr)
                features_dict[f'seg{temp}_{seg_head_p_type}_p_offset'] = seg_head_p_offset
                features_dict[f'seg{temp}_{seg_head_p_type}_p_filesz'] = seg_head_p_filesz
                features_dict[f'seg{temp}_{seg_head_p_type}_p_memsz'] = seg_head_p_memsz
                features_dict[f'seg{temp}_{seg_head_p_type}_p_flags'] = seg_head_p_flags
                features_dict[f'seg{temp}_{seg_head_p_type}_p_align'] = seg_head_p_align
                features_dict[f'seg{temp}_{seg_head_p_type}_p_vaddr'] = seg_head_p_vaddr
                features_dict[f'seg{temp}_{seg_head_p_type}_p_paddr'] = seg_head_p_paddr
                temp += 1
            for section in elffile.iter_sections():
                section_name = (section.name)[1:]
                features_dict[f'section_{section_name}'] = section.name
                sechead_sh_name = (section.header.sh_name)
                sechead_sh_type = (section.header.sh_type)
                sechead_sh_flags = (section.header.sh_flags)
                sechead_sh_addr = (section.header.sh_addr)
                sechead_sh_offset = (section.header.sh_offset)
                sechead_sh_size = (section.header.sh_size)
                sechead_sh_link = (section.header.sh_link)
                sechead_sh_info = (section.header.sh_info)
                sechead_sh_addralign = (section.header.sh_addralign)
                sechead_sh_entsize = (section.header.sh_entsize)
                features_dict[f'section_{section_name}_sh_name'] = sechead_sh_name
                features_dict[f'section_{section_name}_sh_type'] = sechead_sh_type
                features_dict[f'section_{section_name}_sh_flags'] = sechead_sh_flags
                features_dict[f'section_{section_name}_sh_addr'] = sechead_sh_addr
                features_dict[f'section_{section_name}_sh_offset'] = sechead_sh_offset
                features_dict[f'section_{section_name}_sh_size'] = sechead_sh_size
                features_dict[f'section_{section_name}_sh_link'] = sechead_sh_link
                features_dict[f'section_{section_name}_sh_info'] = sechead_sh_info
                features_dict[f'section_{section_name}_sh_addralign'] = sechead_sh_addralign
                features_dict[f'section_{section_name}_sh_entsize'] = sechead_sh_entsize
            features_dict['label'] = label
        return features_dict
    except:
        # print("Read Error")
        print(elf, '0')  # 打印文件名


# utility function to clean the dataset by generating unique numeric value for the string values in the dataset
def get_unique_mappings(feature):
    clean_data = pd.read_csv('./Trojan/Data/trojan_reordered.csv', low_memory=False)
    tmplist = (sorted(clean_data[feature].unique().tolist()))
    tmpdict = {k: (v + 1) for v, k in enumerate(tmplist)}
    return tmpdict


def clean_dataset(label):
    # these are the selected features which we obtained from the dataset during the training phase
    features_list = ['file_name', 'label', 'file_size', 'num_sections', 'num_segments', 'has_dwarf_info',
                     'dwarf_info_config_machine_arch', 'dwarf_info_config_default_address_size',
                     'dwarf_info_config_little_endian', 'dwarf_info_debug_info_sec_name',
                     'dwarf_info_debug_info_sec_global_offset', 'dwarf_info_debug_info_sec_size',
                     'dwarf_info_debug_info_sec_address', 'dwarf_info_debug_aranges_sec_name',
                     'dwarf_info_debug_aranges_sec_global_offset', 'dwarf_info_debug_aranges_sec_size',
                     'dwarf_info_debug_aranges_sec_address', 'dwarf_info_debug_abbrev_sec_name',
                     'dwarf_info_debug_abbrev_sec_global_offset', 'dwarf_info_debug_abbrev_sec_size',
                     'dwarf_info_debug_abbrev_sec_address', 'dwarf_info_debug_frame_sec_name',
                     'dwarf_info_debug_frame_sec_global_offset', 'dwarf_info_debug_frame_sec_size',
                     'dwarf_info_debug_frame_sec_address', 'dwarf_info_debug_str_sec_name',
                     'dwarf_info_debug_str_sec_global_offset', 'dwarf_info_debug_str_sec_size',
                     'dwarf_info_debug_str_sec_address', 'dwarf_info_debug_loc_sec_name',
                     'dwarf_info_debug_loc_sec_global_offset', 'dwarf_info_debug_loc_sec_size',
                     'dwarf_info_debug_loc_sec_address', 'dwarf_info_debug_ranges_sec_name',
                     'dwarf_info_debug_ranges_sec_global_offset', 'dwarf_info_debug_ranges_sec_size',
                     'dwarf_info_debug_ranges_sec_address', 'dwarf_info_debug_line_sec_name',
                     'dwarf_info_debug_line_sec_global_offset', 'dwarf_info_debug_line_sec_size',
                     'dwarf_info_debug_line_sec_address', 'dwarf_info_debug_pubtypes_sec_name',
                     'dwarf_info_debug_pubtypes_sec_global_offset', 'dwarf_info_debug_pubtypes_sec_size',
                     'dwarf_info_debug_pubtypes_sec_address', 'dwarf_info_debug_pubnames_sec_name',
                     'dwarf_info_debug_pubnames_sec_global_offset', 'dwarf_info_debug_pubnames_sec_size',
                     'dwarf_info_debug_pubnames_sec_address', 'has_ehabi_info', 'ehabi_infos', 'machine_arch',
                     'shstrndx', 'sec_header_sh_name', 'sec_header_sh_type', 'sec_header_sh_flags',
                     'sec_header_sh_addr', 'sec_header_sh_offset', 'sec_header_sh_size', 'sec_header_sh_link',
                     'sec_header_sh_info', 'sec_header_sh_addralign', 'sec_header_sh_entsize',
                     'elf_head_ident_EI_CLASS', 'elf_head_ident_EI_DATA', 'elf_head_ident_EI_OSABI',
                     'elf_head_ident_EI_ABIVERSION', 'elf_head_e_type', 'elf_head_e_machine', 'elf_head_e_entry',
                     'elf_head_e_phoff', 'elf_head_e_shoff', 'elf_head_e_flags', 'elf_head_e_ehsize',
                     'elf_head_e_phentsize', 'elf_head_e_phnum', 'elf_head_e_shentsize', 'elf_head_e_shnum',
                     'elf_head_e_shstrndx', 'seg0_head_p_type', 'seg0_PT_LOAD_p_offset', 'seg0_PT_LOAD_p_filesz',
                     'seg0_PT_LOAD_p_memsz', 'seg0_PT_LOAD_p_flags', 'seg0_PT_LOAD_p_align', 'seg0_PT_LOAD_p_vaddr',
                     'seg0_PT_LOAD_p_paddr', 'seg1_head_p_type', 'seg1_PT_LOAD_p_offset', 'seg1_PT_LOAD_p_filesz',
                     'seg1_PT_LOAD_p_memsz', 'seg1_PT_LOAD_p_flags', 'seg1_PT_LOAD_p_align', 'seg1_PT_LOAD_p_vaddr',
                     'seg1_PT_LOAD_p_paddr', 'seg2_head_p_type', 'seg2_PT_GNU_STACK_p_offset',
                     'seg2_PT_GNU_STACK_p_filesz', 'seg2_PT_GNU_STACK_p_memsz', 'seg2_PT_GNU_STACK_p_flags',
                     'seg2_PT_GNU_STACK_p_align', 'seg2_PT_GNU_STACK_p_vaddr', 'seg2_PT_GNU_STACK_p_paddr',
                     'section__sh_name', 'section__sh_type', 'section__sh_flags', 'section__sh_addr',
                     'section__sh_offset', 'section__sh_size', 'section__sh_link', 'section__sh_info',
                     'section__sh_addralign', 'section__sh_entsize', 'section_init', 'section_init_sh_name',
                     'section_init_sh_type', 'section_init_sh_flags', 'section_init_sh_addr', 'section_init_sh_offset',
                     'section_init_sh_size', 'section_init_sh_link', 'section_init_sh_info',
                     'section_init_sh_addralign', 'section_init_sh_entsize', 'section_text', 'section_text_sh_name',
                     'section_text_sh_type', 'section_text_sh_flags', 'section_text_sh_addr', 'section_text_sh_offset',
                     'section_text_sh_size', 'section_text_sh_link', 'section_text_sh_info',
                     'section_text_sh_addralign', 'section_text_sh_entsize', 'section_fini', 'section_fini_sh_name',
                     'section_fini_sh_type', 'section_fini_sh_flags', 'section_fini_sh_addr', 'section_fini_sh_offset',
                     'section_fini_sh_size', 'section_fini_sh_link', 'section_fini_sh_info',
                     'section_fini_sh_addralign', 'section_fini_sh_entsize', 'section_rodata', 'section_rodata_sh_name',
                     'section_rodata_sh_type', 'section_rodata_sh_flags', 'section_rodata_sh_addr',
                     'section_rodata_sh_offset', 'section_rodata_sh_size', 'section_rodata_sh_link',
                     'section_rodata_sh_info', 'section_rodata_sh_addralign', 'section_rodata_sh_entsize',
                     'section_ctors', 'section_ctors_sh_name', 'section_ctors_sh_type', 'section_ctors_sh_flags',
                     'section_ctors_sh_addr', 'section_ctors_sh_offset', 'section_ctors_sh_size',
                     'section_ctors_sh_link', 'section_ctors_sh_info', 'section_ctors_sh_addralign',
                     'section_ctors_sh_entsize', 'section_dtors', 'section_dtors_sh_name', 'section_dtors_sh_type',
                     'section_dtors_sh_flags', 'section_dtors_sh_addr', 'section_dtors_sh_offset',
                     'section_dtors_sh_size', 'section_dtors_sh_link', 'section_dtors_sh_info',
                     'section_dtors_sh_addralign', 'section_dtors_sh_entsize', 'section_data', 'section_data_sh_name',
                     'section_data_sh_type', 'section_data_sh_flags', 'section_data_sh_addr', 'section_data_sh_offset',
                     'section_data_sh_size', 'section_data_sh_link', 'section_data_sh_info',
                     'section_data_sh_addralign', 'section_data_sh_entsize', 'section_bss', 'section_bss_sh_name',
                     'section_bss_sh_type', 'section_bss_sh_flags', 'section_bss_sh_addr', 'section_bss_sh_offset',
                     'section_bss_sh_size', 'section_bss_sh_link', 'section_bss_sh_info', 'section_bss_sh_addralign',
                     'section_bss_sh_entsize', 'section_shstrtab', 'section_shstrtab_sh_name',
                     'section_shstrtab_sh_type', 'section_shstrtab_sh_flags', 'section_shstrtab_sh_addr',
                     'section_shstrtab_sh_offset', 'section_shstrtab_sh_size', 'section_shstrtab_sh_link',
                     'section_shstrtab_sh_info', 'section_shstrtab_sh_addralign', 'section_shstrtab_sh_entsize']

    given_file = './Trojan/Data/%s.csv' % label
    given_data = pd.read_csv(given_file, low_memory=False)
    given_data_columns_list = []
    for i in given_data.columns.values:
        given_data_columns_list.append(i)
    for feature in features_list:
        if feature not in given_data_columns_list:
            # print("{} was not present, adding it to table with values 0...".format(feature))
            given_data[feature] = ''
    for feature in given_data_columns_list:
        if feature not in features_list:
            # print("{} was not present, removing it from table...".format(feature))
            given_data = given_data.drop(feature, axis=1)

    given_data.to_csv('./Trojan/Data/trojan_modified.csv', index=False)
    with open('./Trojan/Data/trojan_modified.csv', 'r') as infile, open('./Trojan/Data/trojan_reordered.csv', 'w',
                                                                        newline='') as outfile:
        fieldnames = features_list
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in csv.DictReader(infile):
            writer.writerow(row)
    clean_data = pd.read_csv('./Trojan/Data/trojan_reordered.csv')

    clean_data['has_dwarf_info'] = clean_data['has_dwarf_info'].replace({True: 1, False: 0})
    clean_data['dwarf_info_config_machine_arch'] = clean_data['dwarf_info_config_machine_arch'].replace(
        get_unique_mappings('dwarf_info_config_machine_arch'))
    clean_data['dwarf_info_config_little_endian'] = clean_data['dwarf_info_config_little_endian'].replace(
        {True: 1, False: 0})
    clean_data['dwarf_info_debug_info_sec_name'] = clean_data['dwarf_info_debug_info_sec_name'].fillna(0)
    clean_data['dwarf_info_debug_info_sec_global_offset'] = clean_data[
        'dwarf_info_debug_info_sec_global_offset'].fillna(0)
    clean_data['dwarf_info_debug_info_sec_size'] = clean_data['dwarf_info_debug_info_sec_size'].fillna(0)
    clean_data['dwarf_info_debug_info_sec_address'] = clean_data['dwarf_info_debug_info_sec_address'].fillna(1)
    clean_data['dwarf_info_debug_aranges_sec_name'] = clean_data['dwarf_info_debug_aranges_sec_name'].fillna(0)
    clean_data['dwarf_info_debug_aranges_sec_global_offset'] = clean_data[
        'dwarf_info_debug_aranges_sec_global_offset'].fillna(0)
    clean_data['dwarf_info_debug_aranges_sec_size'] = clean_data['dwarf_info_debug_aranges_sec_size'].fillna(0)
    clean_data['dwarf_info_debug_aranges_sec_address'] = clean_data['dwarf_info_debug_aranges_sec_address'].fillna(1)
    clean_data['dwarf_info_debug_abbrev_sec_name'] = clean_data['dwarf_info_debug_abbrev_sec_name'].fillna(0)
    clean_data['dwarf_info_debug_abbrev_sec_global_offset'] = clean_data[
        'dwarf_info_debug_abbrev_sec_global_offset'].fillna(0)
    clean_data['dwarf_info_debug_abbrev_sec_size'] = clean_data['dwarf_info_debug_abbrev_sec_size'].fillna(0)
    clean_data['dwarf_info_debug_abbrev_sec_address'] = clean_data['dwarf_info_debug_abbrev_sec_address'].fillna(1)
    clean_data['dwarf_info_debug_frame_sec_name'] = clean_data['dwarf_info_debug_frame_sec_name'].fillna(0)
    clean_data['dwarf_info_debug_frame_sec_global_offset'] = clean_data[
        'dwarf_info_debug_frame_sec_global_offset'].fillna(0)
    clean_data['dwarf_info_debug_frame_sec_size'] = clean_data['dwarf_info_debug_frame_sec_size'].fillna(0)
    clean_data['dwarf_info_debug_frame_sec_address'] = clean_data['dwarf_info_debug_frame_sec_address'].fillna(1)
    clean_data['dwarf_info_debug_str_sec_name'] = clean_data['dwarf_info_debug_str_sec_name'].fillna(0)
    clean_data['dwarf_info_debug_str_sec_global_offset'] = clean_data['dwarf_info_debug_str_sec_global_offset'].fillna(
        0)
    clean_data['dwarf_info_debug_str_sec_size'] = clean_data['dwarf_info_debug_str_sec_size'].fillna(0)
    clean_data['dwarf_info_debug_str_sec_address'] = clean_data['dwarf_info_debug_str_sec_address'].fillna(1)
    clean_data['dwarf_info_debug_loc_sec_name'] = clean_data['dwarf_info_debug_loc_sec_name'].fillna(0)
    clean_data['dwarf_info_debug_loc_sec_global_offset'] = clean_data['dwarf_info_debug_loc_sec_global_offset'].fillna(
        0)
    clean_data['dwarf_info_debug_loc_sec_size'] = clean_data['dwarf_info_debug_loc_sec_size'].fillna(0)
    clean_data['dwarf_info_debug_loc_sec_address'] = clean_data['dwarf_info_debug_loc_sec_address'].fillna(1)
    clean_data['dwarf_info_debug_ranges_sec_name'] = clean_data['dwarf_info_debug_ranges_sec_name'].fillna(0)
    clean_data['dwarf_info_debug_ranges_sec_global_offset'] = clean_data[
        'dwarf_info_debug_ranges_sec_global_offset'].fillna(0)
    clean_data['dwarf_info_debug_ranges_sec_size'] = clean_data['dwarf_info_debug_ranges_sec_size'].fillna(0)
    clean_data['dwarf_info_debug_ranges_sec_address'] = clean_data['dwarf_info_debug_ranges_sec_address'].fillna(1)
    clean_data['dwarf_info_debug_line_sec_name'] = clean_data['dwarf_info_debug_line_sec_name'].fillna(0)
    clean_data['dwarf_info_debug_line_sec_global_offset'] = clean_data[
        'dwarf_info_debug_line_sec_global_offset'].fillna(0)
    clean_data['dwarf_info_debug_line_sec_size'] = clean_data['dwarf_info_debug_line_sec_size'].fillna(0)
    clean_data['dwarf_info_debug_line_sec_address'] = clean_data['dwarf_info_debug_line_sec_address'].fillna(1)
    clean_data['dwarf_info_debug_pubnames_sec_name'] = clean_data['dwarf_info_debug_pubnames_sec_name'].fillna(0)
    clean_data['dwarf_info_debug_pubnames_sec_global_offset'] = clean_data[
        'dwarf_info_debug_pubnames_sec_global_offset'].fillna(0)
    clean_data['dwarf_info_debug_pubnames_sec_size'] = clean_data['dwarf_info_debug_pubnames_sec_size'].fillna(0)
    clean_data['dwarf_info_debug_pubnames_sec_address'] = clean_data['dwarf_info_debug_pubnames_sec_address'].fillna(1)
    clean_data['has_ehabi_info'] = clean_data['has_ehabi_info'].replace({True: 1, False: 0})
    clean_data['ehabi_infos'] = clean_data['ehabi_infos'].fillna(0)
    clean_data['machine_arch'] = clean_data['machine_arch'].replace(get_unique_mappings('machine_arch'))
    clean_data['sec_header_sh_type'] = clean_data['sec_header_sh_type'].replace({'SHT_NULL': 0, 'SHT_STRTAB': 1})
    clean_data['elf_head_ident_EI_CLASS'] = clean_data['elf_head_ident_EI_CLASS'].replace(
        get_unique_mappings('elf_head_ident_EI_CLASS'))
    clean_data['elf_head_ident_EI_DATA'] = clean_data['elf_head_ident_EI_DATA'].replace(
        get_unique_mappings('elf_head_ident_EI_DATA'))
    clean_data['elf_head_ident_EI_OSABI'] = clean_data['elf_head_ident_EI_OSABI'].replace(
        get_unique_mappings('elf_head_ident_EI_OSABI'))
    clean_data['elf_head_e_type'] = clean_data['elf_head_e_type'].replace(get_unique_mappings('elf_head_e_type'))
    clean_data['elf_head_e_machine'] = clean_data['elf_head_e_machine'].replace(
        get_unique_mappings('elf_head_e_machine'))
    clean_data['seg0_head_p_type'] = clean_data['seg0_head_p_type'].replace(get_unique_mappings('seg0_head_p_type'))
    clean_data['seg1_head_p_type'] = clean_data['seg1_head_p_type'].fillna(0)
    clean_data['seg2_head_p_type'] = clean_data['seg2_head_p_type'].fillna(0)
    clean_data['section__sh_name'] = clean_data['section__sh_name'].fillna(1)
    clean_data['section__sh_type'] = clean_data['section__sh_type'].fillna(0)
    clean_data['section__sh_flags'] = clean_data['section__sh_flags'].fillna(1)
    clean_data['section__sh_addr'] = clean_data['section__sh_addr'].fillna(1)
    clean_data['section__sh_offset'] = clean_data['section__sh_offset'].fillna(1)
    clean_data['section__sh_size'] = clean_data['section__sh_size'].fillna(1)
    clean_data['section__sh_link'] = clean_data['section__sh_link'].fillna(1)
    clean_data['section__sh_info'] = clean_data['section__sh_info'].fillna(1)
    clean_data['section__sh_addralign'] = clean_data['section__sh_addralign'].fillna(1)
    clean_data['section__sh_entsize'] = clean_data['section__sh_entsize'].fillna(1)
    clean_data['section_init'] = clean_data['section_init'].fillna(1)
    clean_data['section_init_sh_name'] = clean_data['section_init_sh_name'].fillna(0)
    clean_data['section_init_sh_type'] = clean_data['section_init_sh_type'].fillna(0)
    clean_data['section_init_sh_flags'] = clean_data['section_init_sh_flags'].fillna(0)
    clean_data['section_init_sh_addr'] = clean_data['section_init_sh_addr'].fillna(0)
    clean_data['section_init_sh_offset'] = clean_data['section_init_sh_offset'].fillna(0)
    clean_data['section_init_sh_size'] = clean_data['section_init_sh_size'].fillna(0)
    clean_data['section_init_sh_link'] = clean_data['section_init_sh_link'].fillna(1)
    clean_data['section_init_sh_info'] = clean_data['section_init_sh_info'].fillna(1)
    clean_data['section_init_sh_addralign'] = clean_data['section_init_sh_addralign'].fillna(0)
    clean_data['section_init_sh_entsize'] = clean_data['section_init_sh_entsize'].fillna(1)
    clean_data['section_text'] = clean_data['section_text'].fillna(0)
    clean_data['section_text_sh_name'] = clean_data['section_text_sh_name'].fillna(0)
    clean_data['section_text_sh_type'] = clean_data['section_text_sh_type'].fillna(0)
    clean_data['section_text_sh_flags'] = clean_data['section_text_sh_flags'].fillna(0)
    clean_data['section_text_sh_addr'] = clean_data['section_text_sh_addr'].fillna(0)
    clean_data['section_text_sh_offset'] = clean_data['section_text_sh_offset'].fillna(0)
    clean_data['section_text_sh_size'] = clean_data['section_text_sh_size'].fillna(0)
    clean_data['section_text_sh_link'] = clean_data['section_text_sh_link'].fillna(1)
    clean_data['section_text_sh_info'] = clean_data['section_text_sh_info'].fillna(1)
    clean_data['section_text_sh_addralign'] = clean_data['section_text_sh_addralign'].fillna(0)
    clean_data['section_text_sh_entsize'] = clean_data['section_text_sh_entsize'].fillna(1)
    clean_data['section_fini'] = clean_data['section_fini'].fillna(0)
    clean_data['section_fini_sh_name'] = clean_data['section_fini_sh_name'].fillna(0)
    clean_data['section_fini_sh_type'] = clean_data['section_fini_sh_type'].fillna(0)
    clean_data['section_fini_sh_flags'] = clean_data['section_fini_sh_flags'].fillna(0)
    clean_data['section_fini_sh_addr'] = clean_data['section_fini_sh_addr'].fillna(0)
    clean_data['section_fini_sh_offset'] = clean_data['section_fini_sh_offset'].fillna(0)
    clean_data['section_fini_sh_size'] = clean_data['section_fini_sh_size'].fillna(0)
    clean_data['section_fini_sh_link'] = clean_data['section_fini_sh_link'].fillna(1)
    clean_data['section_fini_sh_info'] = clean_data['section_fini_sh_info'].fillna(1)
    clean_data['section_fini_sh_addralign'] = clean_data['section_fini_sh_addralign'].fillna(0)
    clean_data['section_fini_sh_entsize'] = clean_data['section_fini_sh_entsize'].fillna(0)
    clean_data['section_rodata'] = clean_data['section_rodata'].fillna(0)
    clean_data['section_rodata_sh_name'] = clean_data['section_rodata_sh_name'].fillna(0)
    clean_data['section_rodata_sh_type'] = clean_data['section_rodata_sh_type'].fillna(0)
    clean_data['section_rodata_sh_flags'] = clean_data['section_rodata_sh_flags'].fillna(0)
    clean_data['section_rodata_sh_addr'] = clean_data['section_rodata_sh_addr'].fillna(0)
    clean_data['section_rodata_sh_offset'] = clean_data['section_rodata_sh_offset'].fillna(0)
    clean_data['section_rodata_sh_size'] = clean_data['section_rodata_sh_size'].fillna(0)
    clean_data['section_rodata_sh_link'] = clean_data['section_rodata_sh_link'].fillna(1)
    clean_data['section_rodata_sh_info'] = clean_data['section_rodata_sh_info'].fillna(1)
    clean_data['section_rodata_sh_addralign'] = clean_data['section_rodata_sh_addralign'].fillna(0)
    clean_data['section_rodata_sh_entsize'] = clean_data['section_rodata_sh_entsize'].fillna(2)
    clean_data['section_data'] = clean_data['section_data'].fillna(0)
    clean_data['section_data_sh_name'] = clean_data['section_data_sh_name'].fillna(0)
    clean_data['section_data_sh_type'] = clean_data['section_data_sh_type'].fillna(0)
    clean_data['section_data_sh_flags'] = clean_data['section_data_sh_flags'].fillna(0)
    clean_data['section_data_sh_addr'] = clean_data['section_data_sh_addr'].fillna(0)
    clean_data['section_data_sh_offset'] = clean_data['section_data_sh_offset'].fillna(0)
    clean_data['section_data_sh_size'] = clean_data['section_data_sh_size'].fillna(0)
    clean_data['section_data_sh_link'] = clean_data['section_data_sh_link'].fillna(1)
    clean_data['section_data_sh_info'] = clean_data['section_data_sh_info'].fillna(1)
    clean_data['section_data_sh_addralign'] = clean_data['section_data_sh_addralign'].fillna(0)
    clean_data['section_data_sh_entsize'] = clean_data['section_data_sh_entsize'].fillna(1)
    clean_data['section_bss'] = clean_data['section_bss'].fillna(0)
    clean_data['section_bss_sh_name'] = clean_data['section_bss_sh_name'].fillna(0)
    clean_data['section_bss_sh_type'] = clean_data['section_bss_sh_type'].fillna(0)
    clean_data['section_bss_sh_flags'] = clean_data['section_bss_sh_flags'].fillna(0)
    clean_data['section_bss_sh_addr'] = clean_data['section_bss_sh_addr'].fillna(0)
    clean_data['section_bss_sh_offset'] = clean_data['section_bss_sh_offset'].fillna(0)
    clean_data['section_bss_sh_size'] = clean_data['section_bss_sh_size'].fillna(0)
    clean_data['section_bss_sh_link'] = clean_data['section_bss_sh_link'].fillna(1)
    clean_data['section_bss_sh_info'] = clean_data['section_bss_sh_info'].fillna(1)
    clean_data['section_bss_sh_addralign'] = clean_data['section_bss_sh_addralign'].fillna(0)
    clean_data['section_bss_sh_entsize'] = clean_data['section_bss_sh_entsize'].fillna(1)
    clean_data['section_shstrtab'] = clean_data['section_shstrtab'].fillna(0)
    clean_data['section_shstrtab_sh_name'] = clean_data['section_shstrtab_sh_name'].fillna(0)
    clean_data['section_shstrtab_sh_type'] = clean_data['section_shstrtab_sh_type'].fillna(0)
    clean_data['section_shstrtab_sh_flags'] = clean_data['section_shstrtab_sh_flags'].fillna(1)
    clean_data['section_shstrtab_sh_addr'] = clean_data['section_shstrtab_sh_addr'].fillna(1)
    clean_data['section_shstrtab_sh_offset'] = clean_data['section_shstrtab_sh_offset'].fillna(0)
    clean_data['section_shstrtab_sh_size'] = clean_data['section_shstrtab_sh_size'].fillna(0)
    clean_data['section_shstrtab_sh_link'] = clean_data['section_shstrtab_sh_link'].fillna(1)
    clean_data['section_shstrtab_sh_info'] = clean_data['section_shstrtab_sh_info'].fillna(1)
    clean_data['section_shstrtab_sh_addralign'] = clean_data['section_shstrtab_sh_addralign'].fillna(0)
    clean_data['section_shstrtab_sh_entsize'] = clean_data['section_shstrtab_sh_entsize'].fillna(1)
    clean_data['dwarf_info_debug_info_sec_name'] = clean_data['dwarf_info_debug_info_sec_name'].replace(
        {'.debug_info': 1})
    clean_data['dwarf_info_debug_aranges_sec_name'] = clean_data['dwarf_info_debug_aranges_sec_name'].replace(
        {'.debug_aranges': 1})
    clean_data['dwarf_info_debug_abbrev_sec_name'] = clean_data['dwarf_info_debug_abbrev_sec_name'].replace(
        {'.debug_abbrev': 1})
    clean_data['dwarf_info_debug_frame_sec_name'] = clean_data['dwarf_info_debug_frame_sec_name'].replace(
        {'.debug_frame': 1})
    clean_data['dwarf_info_debug_str_sec_name'] = clean_data['dwarf_info_debug_str_sec_name'].replace({'.debug_str': 1})
    clean_data['dwarf_info_debug_loc_sec_name'] = clean_data['dwarf_info_debug_loc_sec_name'].replace({'.debug_loc': 1})
    clean_data['dwarf_info_debug_ranges_sec_name'] = clean_data['dwarf_info_debug_ranges_sec_name'].replace(
        {'.debug_ranges': 1})
    clean_data['dwarf_info_debug_line_sec_name'] = clean_data['dwarf_info_debug_line_sec_name'].replace(
        {'.debug_line': 1})
    # clean_data[''] = clean_data[''].replace({'.debug_frame': 1})
    clean_data['dwarf_info_debug_frame_sec_name'] = clean_data['dwarf_info_debug_frame_sec_name'].replace(
        {'.debug_frame': 1})
    clean_data['dwarf_info_debug_frame_sec_name'] = clean_data['dwarf_info_debug_frame_sec_name'].replace(
        {'.debug_frame': 1})
    clean_data['dwarf_info_debug_frame_sec_name'] = clean_data['dwarf_info_debug_frame_sec_name'].replace(
        {'.debug_frame': 1})
    clean_data['dwarf_info_debug_pubtypes_sec_name'] = clean_data['dwarf_info_debug_pubtypes_sec_name'].fillna(0)
    clean_data['dwarf_info_debug_pubtypes_sec_global_offset'] = clean_data[
        'dwarf_info_debug_pubtypes_sec_global_offset'].fillna(0)
    clean_data['dwarf_info_debug_pubtypes_sec_size'] = clean_data['dwarf_info_debug_pubtypes_sec_size'].fillna(0)
    clean_data['dwarf_info_debug_pubtypes_sec_address'] = clean_data['dwarf_info_debug_pubtypes_sec_address'].fillna(1)
    clean_data['dwarf_info_debug_pubnames_sec_name'] = clean_data['dwarf_info_debug_pubnames_sec_name'].replace(
        {'.debug_pubnames': 1})
    clean_data['seg0_PT_LOAD_p_offset'] = clean_data['seg0_PT_LOAD_p_offset'].fillna(0)
    clean_data['seg0_PT_LOAD_p_filesz'] = clean_data['seg0_PT_LOAD_p_filesz'].fillna(0)
    clean_data['seg0_PT_LOAD_p_memsz'] = clean_data['seg0_PT_LOAD_p_memsz'].fillna(0)
    clean_data['seg0_PT_LOAD_p_flags'] = clean_data['seg0_PT_LOAD_p_flags'].fillna(0)
    clean_data['seg0_PT_LOAD_p_align'] = clean_data['seg0_PT_LOAD_p_align'].fillna(0)
    clean_data['seg0_PT_LOAD_p_vaddr'] = clean_data['seg0_PT_LOAD_p_vaddr'].fillna(0)
    clean_data['seg0_PT_LOAD_p_paddr'] = clean_data['seg0_PT_LOAD_p_paddr'].fillna(0)
    clean_data['seg1_head_p_type'] = clean_data['seg1_head_p_type'].replace(
        {'PT_INTERP': 1, 'PT_LOAD': 2, 'PT_NOTE': 3, 'PT_PHDR': 4})
    clean_data['seg1_PT_LOAD_p_offset'] = clean_data['seg1_PT_LOAD_p_offset'].fillna(0)
    clean_data['seg1_PT_LOAD_p_filesz'] = clean_data['seg1_PT_LOAD_p_filesz'].fillna(0)
    clean_data['seg1_PT_LOAD_p_memsz'] = clean_data['seg1_PT_LOAD_p_memsz'].fillna(0)
    clean_data['seg1_PT_LOAD_p_flags'] = clean_data['seg1_PT_LOAD_p_flags'].fillna(0)
    clean_data['seg1_PT_LOAD_p_align'] = clean_data['seg1_PT_LOAD_p_align'].fillna(0)
    clean_data['seg1_PT_LOAD_p_vaddr'] = clean_data['seg1_PT_LOAD_p_vaddr'].fillna(0)
    clean_data['seg1_PT_LOAD_p_paddr'] = clean_data['seg1_PT_LOAD_p_paddr'].fillna(0)
    clean_data['seg2_head_p_type'] = clean_data['seg2_head_p_type'].replace(
        {'PT_DYNAMIC': 1, 'PT_GNU_STACK': 2, 'PT_INTERP': 3, 'PT_LOAD': 4, 'PT_NOTE': 5, 'PT_TLS': 6})
    clean_data['seg2_PT_GNU_STACK_p_offset'] = clean_data['seg2_PT_GNU_STACK_p_offset'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_filesz'] = clean_data['seg2_PT_GNU_STACK_p_filesz'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_memsz'] = clean_data['seg2_PT_GNU_STACK_p_memsz'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_flags'] = clean_data['seg2_PT_GNU_STACK_p_flags'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_align'] = clean_data['seg2_PT_GNU_STACK_p_align'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_vaddr'] = clean_data['seg2_PT_GNU_STACK_p_vaddr'].fillna(0)
    clean_data['seg2_PT_GNU_STACK_p_paddr'] = clean_data['seg2_PT_GNU_STACK_p_paddr'].fillna(0)
    clean_data['section__sh_type'] = clean_data['section__sh_type'].replace({'SHT_NULL': 1})
    clean_data['section_init'] = clean_data['section_init'].replace({1: 0, '.init': 1})
    clean_data['section_init_sh_type'] = clean_data['section_init_sh_type'].replace(
        {'SHT_NOBITS': 1, 'SHT_PROGBITS': 2})
    clean_data['section_text'] = clean_data['section_text'].replace({'.text': 1})
    clean_data['section_text_sh_type'] = clean_data['section_text_sh_type'].replace(
        {'SHT_NOBITS': 1, 'SHT_PROGBITS': 2})
    clean_data['section_fini'] = clean_data['section_fini'].replace({'.fini': 1})
    clean_data['section_fini_sh_type'] = clean_data['section_fini_sh_type'].replace(
        {'SHT_NOBITS': 1, 'SHT_PROGBITS': 2})
    clean_data['section_rodata'] = clean_data['section_rodata'].replace({'.rodata': 1})
    clean_data['section_rodata_sh_type'] = clean_data['section_rodata_sh_type'].replace(
        {'SHT_NOBITS': 1, 'SHT_PROGBITS': 2})
    clean_data['section_ctors'] = clean_data['section_ctors'].fillna(0)
    clean_data['section_ctors_sh_name'] = clean_data['section_ctors_sh_name'].fillna(0)
    clean_data['section_ctors_sh_type'] = clean_data['section_ctors_sh_type'].fillna(0)
    clean_data['section_ctors_sh_flags'] = clean_data['section_ctors_sh_flags'].fillna(0)
    clean_data['section_ctors_sh_addr'] = clean_data['section_ctors_sh_addr'].fillna(0)
    clean_data['section_ctors_sh_offset'] = clean_data['section_ctors_sh_offset'].fillna(0)
    clean_data['section_ctors_sh_size'] = clean_data['section_ctors_sh_size'].fillna(0)
    clean_data['section_ctors_sh_link'] = clean_data['section_ctors_sh_link'].fillna(0)
    clean_data['section_ctors_sh_info'] = clean_data['section_ctors_sh_info'].fillna(0)
    clean_data['section_ctors_sh_addralign'] = clean_data['section_ctors_sh_addralign'].fillna(0)
    clean_data['section_ctors_sh_entsize'] = clean_data['section_ctors_sh_entsize'].fillna(0)
    clean_data['section_dtors'] = clean_data['section_dtors'].fillna(0)
    clean_data['section_dtors_sh_name'] = clean_data['section_dtors_sh_name'].fillna(0)
    clean_data['section_dtors_sh_type'] = clean_data['section_dtors_sh_type'].fillna(0)
    clean_data['section_dtors_sh_flags'] = clean_data['section_dtors_sh_flags'].fillna(0)
    clean_data['section_dtors_sh_addr'] = clean_data['section_dtors_sh_addr'].fillna(0)
    clean_data['section_dtors_sh_offset'] = clean_data['section_dtors_sh_offset'].fillna(0)
    clean_data['section_dtors_sh_size'] = clean_data['section_dtors_sh_size'].fillna(0)
    clean_data['section_dtors_sh_link'] = clean_data['section_dtors_sh_link'].fillna(0)
    clean_data['section_dtors_sh_info'] = clean_data['section_dtors_sh_info'].fillna(0)
    clean_data['section_dtors_sh_addralign'] = clean_data['section_dtors_sh_addralign'].fillna(0)
    clean_data['section_dtors_sh_entsize'] = clean_data['section_dtors_sh_entsize'].fillna(0)
    clean_data['section_data'] = clean_data['section_data'].replace({'.data': 1})
    clean_data['section_data_sh_type'] = clean_data['section_data_sh_type'].replace(
        {'SHT_NOBITS': 1, 'SHT_PROGBITS': 2})
    clean_data['section_bss'] = clean_data['section_bss'].replace({'.bss': 1})
    clean_data['section_bss_sh_type'] = clean_data['section_bss_sh_type'].replace({'SHT_NOBITS': 1})
    clean_data['section_shstrtab'] = clean_data['section_shstrtab'].replace({'.shstrtab': 1})
    clean_data['section_shstrtab_sh_type'] = clean_data['section_shstrtab_sh_type'].replace({'SHT_STRTAB': 1})
    clean_data['ehabi_infos'] = clean_data['ehabi_infos'].astype(bool).astype(int)

    clean_data.drop_duplicates(inplace=True)  # drop the duplicate lines

    clean_data.to_csv('./Trojan/Data/%s.csv' % label, index=False)  # save the cleaned data to perfect.csv

def writefile(filename,ftp_data,file_path):
    with open(file_path + filename, 'w') as f:
        f.write(str(ftp_data))
    print("successfully write my file")

    # 读取文件 调整内容
    lines = []
    with open(file_path + filename, 'w') as f:
        f.readline()
        line = f.readline()
        if line:
            line = line[1:]  # 删除第二行第一个字符
            line = line.strip("\t")
            line = line[:-3]
            lines.append(line)
        for line in f:
            line = line.strip("\t")
            line = line[:-3]
            print("第n行", line)
            lines.append(line)

    # 创建新文件并写入内容
    with open(file_path+'new_data.txt', 'w') as f:
        for line in lines:
            f.write(line + "\n")

    # 删除原文件
    os.remove(file_path + filename)
    # 修改新文件名称为原文件名
    if os.path.exists(file_path + filename):
        # 删除文件
        os.remove(file_path + filename)
    os.rename(file_path + 'new_data.txt', filename)
