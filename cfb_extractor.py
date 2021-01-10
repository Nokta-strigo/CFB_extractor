#!/usr/bin/python3
from struct import pack, unpack, iter_unpack
from collections import deque
from enum import Enum, IntEnum
from os import listdir, path, makedirs
from shutil import rmtree
from math import ceil
import uuid


class WrongCFBFile (Exception):
    pass

class DirectoryEntryTypes(Enum):
    UNKNOWN = 0x00
    STORAGE = 0x01
    STREAM = 0x02
    ROOT_STORAGE = 0x05

    def __str__(self):
        return self.name.capitalize()

class SectorNumbers(IntEnum):
    FREESECT = 0xFFFFFFFF
    END_OF_CHAIN = 0xFFFFFFFE
    FATSECT = 0xFFFFFFFD
    DIFSECT = 0xFFFFFFFC
    MAX_SEC_NUM = 0xFFFFFFFA

    def is_valid(sec_num):
        return sec_num <= 0xFFFFFFFA


class SeverityLevels(IntEnum):
    SILENT = 0
    CRIT_ERROR = 1
    ERROR = 2
    INFO = 3
    VERBOSE = 4

debug_level = SeverityLevels.ERROR

def escape_file_name(file_name:str) -> str:
    """Escape all "dangerous" characters is file_name"""
    file_name = file_name.replace('\\', '\\x5C').replace('/', '\\x2F')
    return file_name.__repr__().strip("'").replace('_', '__').replace('\\', '_')


def log(msg:str, severity_level:SeverityLevels=SeverityLevels.ERROR):
    if severity_level <= debug_level:
        print(msg)
    if severity_level == SeverityLevels.CRIT_ERROR:
        raise Exception(msg)


class CFB:
    # These fields are not filled during initialization
    dangling_streams = None
    dangling_mini_streams = None
    free_streams = None
    free_mini_streams = None

    def __init__(self, binary_data, ignore_magic=False):
        self.binary_data = binary_data
        # read compound file header
        if len(binary_data) < 512:
            log("File is too short: %i bytes" % len(binary_data), SeverityLevels.CRIT_ERROR)
        if binary_data[:8] != bytes.fromhex('d0cf11e0a1b11ae1'):
            if ignore_magic: log("Header signature wrong: {:X}".format(binary_data[:8]))
            else: log("Header signature wrong: {:X}".format(binary_data[:8]), SeverityLevels.CRIT_ERROR)
        if binary_data[8:24] != b'\x00' * 16:
            log("Header CLSID is not 0")
        self.minor_version, self.major_version = unpack("<HH", binary_data[24:28])
        log("Version is {0}.{1} (hex: {0:X}.{1:X})".format(self.major_version, self.minor_version), SeverityLevels.VERBOSE)
        if self.major_version not in (3, 4):
            log("Can't parse only v3 and v4 files.", SeverityLevels.CRIT_ERROR)

        bom, self.sector_shift_exp, self.mini_sector_shift_exp = unpack("<HHH", binary_data[28:34])
        if bom != 0xFFFE:
            log("Wrong byte Order", SeverityLevels.ERROR)
            log("BOM is {}".format(bom), SeverityLevels.ERROR)
        if not (self.sector_shift_exp == 0x09 and self.major_version == 3 or self.sector_shift_exp == 0x0C and self.major_version == 4):
            log("Sector shift must be 2^9=512 for v3 and 2^12=4096 for v4", SeverityLevels.CRIT_ERROR)
        self.sector_size = 2 ** self.sector_shift_exp
        if self.mini_sector_shift_exp != 0x06:
            log("Mini sector shift must be 2^6=64", SeverityLevels.CRIT_ERROR)
        self.mini_sector_size = 2 ** self.mini_sector_shift_exp
        log("Sector size 2^{}={} bytes\nMiniSector size 2^{}={}".format(self.sector_shift_exp, self.sector_size, self.mini_sector_shift_exp, self.mini_sector_size), SeverityLevels.INFO)

        if binary_data[34:40] != b'\x00' * 6: log("Reserved bytes [34:40] are not 0")

        self.number_of_directory_sectors, self.number_of_FAT_sectors, self.first_directory_sector_location,\
        self.transaction_signature_number, self.mini_stream_cutoff_size, self.first_Mini_FAT_sector_location,\
        self.number_of_Mini_FAT_sectors, self.first_DIFAT_sector_location, self.number_of_DIFAT_sectors\
            = unpack("<IIIIIIIII", binary_data[40:76])
        if self.major_version != 3 or self.number_of_directory_sectors != 0:
            log("Number of directory sectors is {}, must be 0 for version 3".format(self.number_of_directory_sectors))
        if self.mini_stream_cutoff_size != 0x1000:
            log("Mini stream cutoff size is {}, must be equal 4096".format(self.mini_stream_cutoff_size), SeverityLevels.ERROR)

        self.DIFAT = list(unpack("<" + "I" * 109, binary_data[76:512]))

        if self.major_version == 4 and (len(binary_data) < 4096 or binary_data[512:4096] != b'\x00' * 3584):
            log("Space between header and end of the 1st sector must be zero filled. It's content: {}".format(self.binary_data[512:4096]))

        if len(binary_data) % self.sector_size != 0:
            log("File size {} is not multiple of sector size {}".format(self.binary_data, self.sector_size), SeverityLevels.CRIT_ERROR)
        self.max_sector_index = len(binary_data)//self.sector_size - 2  # maximum valid sector index

        self.DIFAT_sectors = []  # is not used for parsing, only for validation
        # read DIFAT sectors (if there are more then 109 DIFAT records)
        if self.first_DIFAT_sector_location <= SectorNumbers.MAX_SEC_NUM:
            n_sec = 0
            cur_difat_sec = self.first_DIFAT_sector_location
            log("There are DIFAT {} sectors out of header. Reading them...".format(self.number_of_DIFAT_sectors), SeverityLevels.VERBOSE)
            while cur_difat_sec <= SectorNumbers.MAX_SEC_NUM:
                if cur_difat_sec in self.DIFAT_sectors:
                    log("There's a loop in DIFAT chain on {} step. Chain: {}\t Next sector: {}".format(n_sec, self.DIFAT_sectors, cur_difat_sec), SeverityLevels.CRIT_ERROR)
                self.DIFAT_sectors.append(cur_difat_sec)
                n_sec += 1
                entries = list(unpack("<" + "I" * (self.sector_size//4), self.sector(cur_difat_sec)))
                self.DIFAT += entries[:-1]
                cur_difat_sec = entries[-1]
            if n_sec != self.number_of_DIFAT_sectors:
                log("Number DIFAT sectors in header: {}, number of DIFAT sectors in chain:")

        # Execute DIFAT validity checks that do not need FAT"""
        if len(self.DIFAT) < self.number_of_FAT_sectors:
            log("Number of DIFAT records {} is less then number of FAT sectors in the header {}".format(len(self.DIFAT), self.number_of_FAT_sectors))
        for i in range(self.number_of_FAT_sectors):
            if self.DIFAT[i] > self.max_sector_index:
                log("Unexpected value {:X}\tin DIFAT record #{} (must point to a valid sector)".format(self.DIFAT[i], i))
        for i in range(self.number_of_FAT_sectors, len(self.DIFAT)):
            if self.DIFAT[i] != SectorNumbers.FREESECT:
                log("Unexpected value {:X}\tin DIFAT record #{} (must be FREESECT)".format(self.DIFAT[i], i))
        n_DIFAT_sectors_needed = int(ceil((self.number_of_FAT_sectors - 109) / (self.sector_size//4 - 1)))
        if self.number_of_DIFAT_sectors != n_DIFAT_sectors_needed:
            log("Need {} DIFAT sectors, number DIFAT sectors in header is {}".format(n_DIFAT_sectors_needed, self.number_of_DIFAT_sectors))

        # read FAT
        log("Reading FAT...", SeverityLevels.VERBOSE)
        self.FAT = []
        self.FAT_sectors = []  # is not used for parsing, only for validation
        for i in range(self.number_of_FAT_sectors):
            if self.DIFAT[i] > 0xFFFFFFFA:
                log("Unexpected value {:X} of DIFAT record {}".format(self.DIFAT[i], i), SeverityLevels.CRIT_ERROR)
            self.FAT_sectors.append(self.DIFAT[i])
            self.FAT += unpack("<" + "I" * (self.sector_size//4), self.sector(self.DIFAT[i]))

        # read miniFAT
        log("Reading miniFAT...", SeverityLevels.VERBOSE)
        self.miniFAT = []
        cur_sec = self.first_Mini_FAT_sector_location
        while cur_sec != SectorNumbers.END_OF_CHAIN:
            self.miniFAT += unpack("<" + "I" * (self.sector_size//4), self.sector(cur_sec))
            cur_sec = self.FAT[cur_sec]

        # read directory
        log("Reading directory...", SeverityLevels.VERBOSE)
        directory_binary = self.read_sector_chain(self.first_directory_sector_location)
        self.directory_entries = []
        self.directory_entries_id_by_name = {}
        for i in range(0, len(directory_binary), 128):
            de = DirectoryEntry(directory_binary[i:i + 128], self)
            self.directory_entries.append(de)
            self.directory_entries_id_by_name[de.name_text] = i//128

        # read ministream
        log("Reading miniStream...", SeverityLevels.VERBOSE)
        self.ministream = self.read_normal_stream(self.directory_entries[0].starting_sector_location, self.directory_entries[0].stream_size)

        log("Parsing of main CFB structures finished.", SeverityLevels.VERBOSE)

        pass

    def sector(self, sector_number):
        if 0 <= sector_number <= self.max_sector_index:
            return self.binary_data[self.sec_num_to_offset(sector_number):self.sec_num_to_offset(sector_number + 1)]
        else:
            raise WrongCFBFile("Sector {} out of file".format(sector_number))

    def sec_num_to_offset(self, sector_number):
        return (sector_number + 1) * self.sector_size

    def read_sector_chain(self, start_sector_index):
        chain = bytearray()
        read_sectors_indexes = set()
        cur_sector = start_sector_index
        while cur_sector != SectorNumbers.END_OF_CHAIN:
            chain += self.sector(cur_sector)
            read_sectors_indexes.add(cur_sector)
            next_sector = self.FAT[cur_sector]
            if next_sector in read_sectors_indexes:
                raise WrongCFBFile("Detected loop in sector chain, starting from sector {}".format(start_sector_index))
            cur_sector = next_sector
        return bytes(chain)

    def read_normal_stream(self, starting_sector_location, stream_size):
        stream = self.read_sector_chain(starting_sector_location)
        if len(stream) / self.sector_size != ceil(stream_size / self.sector_size):
            print("Stream at {} has size of {} while it's real size is {}".format(starting_sector_location, stream_size,
                                                                                  len(stream)))
        return stream[:stream_size]

    def read_from_mini_stream(self, starting_sector_location, stream_size):
        stream = bytes()
        read_mini_sectors_indexes = set()
        cur_mini_sec = starting_sector_location
        while cur_mini_sec != SectorNumbers.END_OF_CHAIN:
            read_mini_sectors_indexes.add(cur_mini_sec)
            stream += self.ministream[cur_mini_sec * self.mini_sector_size:(cur_mini_sec + 1) * self.mini_sector_size]
            cur_mini_sec = self.miniFAT[cur_mini_sec]
            if cur_mini_sec in read_mini_sectors_indexes:
                raise WrongCFBFile("Detected loop in mini sector chain, starting from mini sector {}".format(starting_sector_location))
        if len(stream) / self.mini_sector_size != ceil(stream_size / self.mini_sector_size):
            print("Mini stream at {} has size of {} while it's real size is {}".format(starting_sector_location,
                                                                                       stream_size, len(stream)))
        return stream[:stream_size]

    def read_stream(self, directory_entry=None, starting_sector_location=None, stream_size=None):
        if directory_entry is not None:
            starting_sector_location = directory_entry.starting_sector_location
            stream_size = directory_entry.stream_size
        if stream_size >= self.mini_stream_cutoff_size:  # the stream is stored in normal stream
            return self.read_normal_stream(starting_sector_location, stream_size)
        else:  # the stream is stored in ministream
            return self.read_from_mini_stream(starting_sector_location, stream_size)

    def directory_entry_by_name(self, de_name):
        return self.directory_entries[self.directory_entries_id_by_name[de_name]]

    def check_FAT_DIFAT_validity(self):
        log("Checking FAT structure", SeverityLevels.INFO)
        err_fat_entries = {}
        for i, sn in enumerate(self.FAT):
            if sn > self.max_sector_index and sn <= SectorNumbers.MAX_SEC_NUM:
                err_fat_entries[i] = sn
                log("Erroneous value {} in FAT record {}".format(sn, i))

            if i in self.DIFAT_sectors and sn != SectorNumbers.DIFSECT:
                log("FAT record {} correcponding to DIFAT sector is set to {}, instead if DIFSECT".format(i, sn))
            elif i not in self.DIFAT_sectors and sn == SectorNumbers.DIFSECT:
                log("FAT record {} not correcponding to DIFAT sector is set to DIFSECT".format(i))

            if i in self.FAT_sectors and sn != SectorNumbers.FATSECT:
                log("FAT record {} correcponding to FAT sector is set to {}, instead if FATSECT".format(i, sn))
            elif i not in self.FAT_sectors and sn == SectorNumbers.FATSECT:
                log("FAT record {} not correcponding to FAT sector is set to FATSECT".format(i))

            if i > self.max_sector_index and sn != SectorNumbers.FREESECT:
                log("FAT record {} correcponding after-end-of-file sector is set to {} instead of FREESECT".format(i, sn))

        if len(err_fat_entries) != 0:
            log("There are {} invalid sector numbers of {}".format(len(err_fat_entries), len(self.FAT)))
            log(str(err_fat_entries))
        log("FAT structure check finished", SeverityLevels.INFO)

    @staticmethod
    def get_all_streams(data, sector_size, fat):
        """Build list of streams and mark every sector with streams it belongs to"""
        n_sectors = len(data)//sector_size
        streams = {}  # {id: deque of sectors the stream consists of}
        sector_use = [[] for i in range(n_sectors)]  # [list of stream ids the sector belongs to (must be 0 or 1 in valid CFB)]
        free_sectors = []
        # for cur_sec_i in list(range(0, n_sectors, 2)) + list(range(1, n_sectors, 2)):
        for cur_sec_i in range(n_sectors):
            at_the_stream_beginning = []  # list of streams starting with the sector (must be 0 or 1 allways)
            at_the_stream_end = []  # list of streams ending with the sector (must be 0 or 1 in valid CFB)
            for sid, s in streams.items():
                if fat[cur_sec_i] == s[0]:
                    s.appendleft(cur_sec_i)
                    sector_use[cur_sec_i].append(sid)
                    at_the_stream_beginning.append(sid)
                if fat[s[-1]] == cur_sec_i:
                    s.append(cur_sec_i)
                    sector_use[cur_sec_i].append(sid)
                    at_the_stream_end.append(sid)
            if len(at_the_stream_end) > 0 and len(at_the_stream_beginning) == 1:
                if len(at_the_stream_end) > 1:
                    log("Sector {} seems to belong to several streams".format(cur_sec_i))
                stream1 = at_the_stream_beginning[0]
                shared_sec = streams[stream1].popleft()  # the 1st sector is present in both streams, kill the dub
                sector_use[shared_sec].remove(stream1)
                for sec_n in streams[stream1]:
                    sector_use[sec_n].remove(stream1)
                for stream0 in at_the_stream_end:
                    if stream0 == stream1:
                        log("There's a loop in stream: {}".format(streams[stream0]))
                    for sec_n in streams[stream1]:
                        sector_use[sec_n].append(stream0)
                    streams[stream0] += streams[stream1]
                streams.pop(stream1)
            elif len(at_the_stream_end) == 0 and len(at_the_stream_beginning) == 0:
                """the sector is part of steam that has not been seen previously"""
                assert cur_sec_i not in streams
                stream_uniq_id = cur_sec_i  # using cur_sec_i as uniq stream id
                streams[stream_uniq_id] = deque([cur_sec_i])
                sector_use[cur_sec_i].append(stream_uniq_id)

        # Sort out free sectors
        for sid, s in list(streams.items()):
            if len(s) == 1 and fat[s[0]] == SectorNumbers.FREESECT:
                free_sectors.append(s[0])
                sector_use[s[0]] = SectorNumbers.FREESECT
                streams.pop(sid)

        return streams, sector_use, free_sectors

    def search_for_dangling_streams(self):
        if len(self.binary_data) % self.sector_size != 0:
            raise WrongCFBFile("Length of binary data is not multiple of sector size")
        streams, sector_use, self.free_streams = self.get_all_streams(self.binary_data[self.sector_size:], self.sector_size, self.FAT)

        self.dangling_streams = {s[0]:s for s in streams.values()}
        # remove known streams
        if self.first_DIFAT_sector_location in self.dangling_streams:
            self.dangling_streams.pop(self.first_DIFAT_sector_location)
        if self.first_directory_sector_location in self.dangling_streams:
            self.dangling_streams.pop(self.first_directory_sector_location)
        if self.first_Mini_FAT_sector_location in self.dangling_streams:
            self.dangling_streams.pop(self.first_Mini_FAT_sector_location)
        for sec in self.FAT_sectors:
            if sec in self.dangling_streams:
                self.dangling_streams.pop(sec)
        for dir_stream in self.directory_entries:
            if dir_stream.stream_size >= self.mini_stream_cutoff_size and \
               dir_stream.starting_sector_location in self.dangling_streams:
                self.dangling_streams.pop(dir_stream.starting_sector_location)
        return streams, sector_use

    def search_for_dangling_mini_streams(self):
        if len(self.ministream) % self.mini_sector_size != 0:
            raise WrongCFBFile("Length of ministream binary data {} is not multiple of ministream sector size {}".
                               format(len(self.ministream), self.mini_sector_size))
        streams, sector_use, self.free_mini_streams = self.get_all_streams(self.ministream, self.mini_sector_size, self.miniFAT)

        self.dangling_mini_streams = {s[0]:s for s in streams.values()}
        # remove known streams
        for dir_stream in self.directory_entries:
            if dir_stream.stream_size < self.mini_stream_cutoff_size and \
               dir_stream.starting_sector_location in self.dangling_mini_streams:
                self.dangling_mini_streams.pop(dir_stream.starting_sector_location)
        return streams, sector_use

    def save_all_dangling_stream(self, base_path):
        if self.dangling_streams is None:
            self.search_for_dangling_streams()
        if self.dangling_mini_streams is None:
            self.search_for_dangling_mini_streams()

        if len(self.dangling_streams) == 0 and len(self.dangling_mini_streams) == 0:
            return

        dir_path = path.join(base_path, 'dangling_streams')
        if not path.exists(dir_path):
            makedirs(dir_path)

        for sid, s in self.dangling_streams.items():
            with open(path.join(dir_path, "{}.stream".format(sid)), 'wb') as f:
                for sec in s:
                    f.write(self.sector(sec))

        for sid, s in self.dangling_mini_streams.items():
            with open(path.join(dir_path, "{}.mini.stream".format(sid)), 'wb') as f:
                for sec in s:
                    f.write(self.sector(sec))

    def save_all_connected_streams(self, base_path, start_from_de_id=0, entry_ids_to_process=None):
        """Recursive function to save directory entries from SFB as a subtree on filesystem."""
        if entry_ids_to_process is None:
            entry_ids_to_process = set(range(len(self.directory_entries)))
        entry_queue_id = [start_from_de_id]
        while len(entry_queue_id) > 0:
            curr_entry_id = entry_queue_id.pop(0)
            curr_de = self.directory_entries[curr_entry_id]
            if curr_entry_id not in entry_ids_to_process:
                print("Is there a loop in directory entries structure? #{}\t{}".format(curr_entry_id, curr_de.name_text))
            entry_ids_to_process.remove(curr_entry_id)
            de_path = path.join(base_path, escape_file_name(curr_de.name_text))
            if curr_de.object_type == DirectoryEntryTypes.ROOT_STORAGE or curr_de.object_type == DirectoryEntryTypes.STORAGE:
                makedirs(de_path, exist_ok=True)
                if SectorNumbers.is_valid(curr_de.child_id):
                    self.save_all_connected_streams(de_path, curr_de.child_id, entry_ids_to_process)
            elif curr_de.object_type == DirectoryEntryTypes.STREAM:
                with open(de_path, 'wb') as f:
                    f.write(self.read_stream(curr_de))
            else:
                pass
            if curr_de.sibling_right_id <= 0xFFFFFFFA:
                entry_queue_id.append(curr_de.sibling_right_id)
            if curr_de.sibling_left_id <= 0xFFFFFFFA:
                entry_queue_id.append(curr_de.sibling_left_id)

        for e_id in list(entry_ids_to_process):
            if self.directory_entries[e_id].is_valid_empty_object():
                entry_ids_to_process.remove(e_id)

        if start_from_de_id == 0 and len(entry_ids_to_process) > 0:  # it's the root directory entry and we haven't saved all directory entries
            while len(entry_ids_to_process) > 0:
                curr_entry_id = list(entry_ids_to_process)[0]
                curr_de = self.directory_entries[curr_entry_id]
                if curr_de.object_type == DirectoryEntryTypes.UNKNOWN and len(curr_de.name) == 0 and curr_de.stream_size == 0:  # don't want to save empty "padding" entry.
                    entry_ids_to_process.remove(curr_entry_id)
                    continue
                log("There are {} directory entries that are not connected to the Root Entry. Writing them to the folder '__disconnected__'".format(
                        len(entry_ids_to_process)), SeverityLevels.INFO)
                self.save_all_connected_streams(path.join(base_path, "__disconnected__"), curr_entry_id, entry_ids_to_process)

    def __repr__(self):
        return "Version\t{}:{}".format(self.major_version, self.minor_version)

    def __str__(self):
        s = "Version is {0}.{1} (hex: {0:X}.{1:X})\n".format(self.major_version, self.minor_version)
        s += self.str_directory_structure()
        return s

    def str_directory_structure(self, directory_entry=None, out="", level=0):
        """recursive depth first search"""
        if directory_entry is None:
            directory_entry = self.directory_entries[0]
        prefix = ' ' * level
        if directory_entry.object_type == DirectoryEntryTypes.ROOT_STORAGE or directory_entry.object_type == DirectoryEntryTypes.STORAGE:
            out += '{}{}:{}\t{}\n'.format(prefix, directory_entry.object_type, directory_entry.name_text, directory_entry.clsid_id)
            if directory_entry.child_id <= 0xFFFFFFFA:
                out = self.str_directory_structure(self.directory_entries[directory_entry.child_id], out, level + 1)
        elif directory_entry.object_type == DirectoryEntryTypes.STREAM:
            out += '{}{}:{}[{}]\t{}\n'.format(prefix, directory_entry.object_type, directory_entry.name_text, directory_entry.stream_size, '', self.read_stream(directory_entry)[:128])
        else:
            out += '{}{}:{}\n'.format(prefix, directory_entry.object_type, directory_entry.name_text)
        if directory_entry.sibling_left_id <= 0xFFFFFFFA:
            out = self.str_directory_structure(self.directory_entries[directory_entry.sibling_left_id], out, level)
        if directory_entry.sibling_right_id <= 0xFFFFFFFA:
            out = self.str_directory_structure(self.directory_entries[directory_entry.sibling_right_id], out, level)
        return out


class DirectoryEntry:
    def __init__(self, binary_data, parent_cfb: CFB):
        if len(binary_data) != 128:
            log("Directory entry len is {}, not equal 128".format(len(binary_data)), SeverityLevels.CRIT_ERROR)
        self.parent_cfb = parent_cfb
        self.name = binary_data[:64]
        self.name_text = self.name.decode("UTF-16").strip('\x00')
        log("Parsing directory object named \"{}\"".format(self.name_text), SeverityLevels.VERBOSE)
        self.name_len = unpack("<H", binary_data[64:66])[0]
        try: self.object_type = DirectoryEntryTypes(binary_data[66])
        except ValueError: log("Directory entry {} object type {} is wrong".format(self.name_text, self.object_type), SeverityLevels.CRIT_ERROR)
        if (self.object_type == DirectoryEntryTypes.ROOT_STORAGE) ^ (self.name_text == "Root Entry"):
            log("Type: {}, name: {}".format(self.object_type, self.name_text))
        self.color_flag = binary_data[67]
        if self.color_flag not in (0, 1):
            log("Directory entry color is {}, must be 0 or 1".format(self.color_flag))
        self.sibling_left_id, self.sibling_right_id, self.child_id = unpack("<III", binary_data[68:80])
        clsid_id_bytes = binary_data[80:96]
        self.clsid_id = uuid.UUID(bytes=clsid_id_bytes)
        if self.object_type == DirectoryEntryTypes.STREAM and clsid_id_bytes != bytes(16):
            log("CLSID for stream object is {}, must be 0".format(self.clsid_id))
        self.state_bits = unpack("<I", binary_data[96:100])[0]
        if self.object_type == DirectoryEntryTypes.STREAM and self.state_bits != 0:
            print("State bits for stream object is not 0")
        self.creation_time = binary_data[100:108]
        if self.object_type == DirectoryEntryTypes.STREAM and self.creation_time != bytes(8):
            raise WrongCFBFile("Creation time for stream object is not 0")
        self.modified_time = binary_data[108:116]
        if self.object_type == DirectoryEntryTypes.STREAM and self.modified_time != bytes(8):
            raise WrongCFBFile("Modified for stream object is not 0")
        self.starting_sector_location = unpack("<I", binary_data[116:120])[0]
        if self.object_type == DirectoryEntryTypes.STORAGE and self.starting_sector_location != 0 and self.starting_sector_location != SectorNumbers.END_OF_CHAIN:
            # for some reason Libre Office sometimes set starting sector location to 0xFFFFFFFE for storage entries
            raise WrongCFBFile("Starting sector location for storage object is not 0")
        if parent_cfb.major_version == 3:
            self.stream_size = unpack("<Q", binary_data[120:128])[0] & 0xFFFFFFFF
            if self.stream_size > 0x80000000:
                raise WrongCFBFile("Stream size {} too big for v3 file".format(self.stream_size))
            if unpack("<Q", binary_data[120:128])[0] & 0xFFFFFFFF00000000 != 0:
                print("Non zero most significant 4 bytes in v3 stream size")
        elif parent_cfb.major_version == 4:
            self.stream_size = unpack("<Q", binary_data[120:128])[0]
        else:
            raise WrongCFBFile("Unknown major version")
        if self.object_type == DirectoryEntryTypes.STORAGE and self.stream_size != 0:
            raise WrongCFBFile("Stream size for storage object is not 0")
        if (len(self.name_text) + 1) * 2 != self.name_len and not self.is_valid_empty_object():
            log("Directory entry name length is {} must be {}".format((len(self.name_text) + 1) * 2, self.name_len))
        log("Finished parsing directory object named \"{}\"".format(self.name_text), SeverityLevels.VERBOSE)

    def is_valid_empty_object(self):
        return self.object_type == DirectoryEntryTypes.UNKNOWN and self.starting_sector_location == SectorNumbers.END_OF_CHAIN and \
               self.stream_size == self.name_len == self.state_bits == 0 and \
               self.name == bytes(len(self.name)) and self.clsid_id == uuid.UUID(bytes=bytes(16)) and \
               self.child_id == self.sibling_left_id == self.sibling_right_id == SectorNumbers.FREESECT and \
               self.creation_time == self.modified_time == bytes(8)

    def read_stream(self):
        return self.parent_cfb.read_stream(self)

    def __repr__(self):
        return "{}:\t{}\t{}".format(self.object_type, self.name_text, self.stream_size)


if __name__ == "__main__":
    from argparse import ArgumentParser
    arg_parser = ArgumentParser(description='Util to check validity, view directory structure and extract stream data from CFB files. '
                                            'Often extracted streams are not human-readable and need more processing to be useful. '
                                            'CFB is a universal file format, used in MSOffice before 2007 (doc, xls, ...) '
                                            'and less widely in Office 2007+ (for example vbaProject.bin is CFB file).')
    arg_parser.add_argument('inputfile', help="Input file name. If it's a directory, will try to parce all the files right in the directory.", nargs='*')
    arg_parser.add_argument('-s', action='store_true', help="Save objects in file to directory tree. Will create directory "
                                                            "<input_file_name>.extracted in the same folder as input file.")
    arg_parser.add_argument('-d', action='store_true', help="Save all dangling (not connected to directory tree) streams "
                                                            "and ministreams.  Will create directory <input_file_name>.extracted in the same folder as input file. "
                                                            "The streams are saved into 'dangling_streams' subdirectory. Name of the file - number of the 1st sector of the stream.")
    arg_parser.add_argument('-f', action='store_true', help="Clean output directory for -s or -d options if exists")
    arg_parser.add_argument('-v', action='count', default=0, help="Be Verbose (use several times to be more verbose)")
    arg_parser.add_argument('-q', action='count', default=0, help="Be quite, output nothing on errors")
    arg_parser.add_argument('--no-magic', action='store_true', help="Parse file even if magic is wrong")
    args = arg_parser.parse_args()
    if len(args.inputfile) == 1 and path.isdir(args.inputfile[0]):
        dir = args.inputfile[0]
        args.inputfile = filter(lambda x: path.isfile(x), map(lambda x: path.join(dir, x), listdir(dir)))
    debug_level = max(0, min(4, 2 - args.q + args.v))

    for file_name in args.inputfile:
        print("Parsing {}".format(file_name))
        data = open(file_name, 'rb').read()
        try:
            cfb = CFB(data, args.no_magic)
            cfb.check_FAT_DIFAT_validity()
        except:
            continue
        if debug_level >= SeverityLevels.INFO:
            print(cfb)
        if args.s or args.d:
            out_dir = file_name + '.extracted'
            if path.exists(out_dir):
                if args.f:
                    rmtree(out_dir)
                else:
                    print("Directory {} already exists, skipping. Use -f to clean existing output directory.".format(out_dir))
                    continue
            makedirs(out_dir)
            if args.s:
                cfb.save_all_connected_streams(out_dir)
            if args.d:
                cfb.save_all_dangling_stream(out_dir)
