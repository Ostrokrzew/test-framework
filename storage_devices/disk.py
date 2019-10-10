#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#


from enum import Enum
from test_utils.size import Size, Unit
from test_tools import disk_utils
from storage_devices.partition import Partition
from storage_devices.device import Device
from core.test_properties import TestProperties
import re
import time


class DiskType(Enum):
    optane = 0
    nand = 1
    sata = 2
    hdd4k = 3
    hdd = 4


class Disk(Device):
    def __init__(self, path, disk_type: DiskType, serial_number, block_size):
        Device.__init__(self, path)
        self.serial_number = serial_number
        self.block_size = Unit(block_size)
        self.disk_type = disk_type
        self.partition_table = None
        self.partitions = []
        self.discover_partitions()

    @classmethod
    def cast_to_disk(cls, disk):
        return cls(disk.system_path, disk.disk_type, disk.serial_number, disk.block_size)

    def __parse_partition_info(self, partition_info: str):
        # parted output has following order:
        #   Number  Start   End     Size    File system  Name     Flags
        # however 'File system' and 'Flags' coulmns might be empty. When detecting partition type
        # ('Name' column), it's id within preprocessed line can be 4 or 5 depending if 'File system'
        # column is empty or not.
        part_line = re.sub(' +', ' ', partition_info).strip().split(' ')
        part_id = int(part_line[0])
        try:
            part_type = disk_utils.PartitionType[part_line[4]]
        except KeyError:
            part_type = disk_utils.PartitionType[part_line[5]]

        return part_id, part_type


    def discover_partitions(self):
        output = TestProperties.executor.execute(f"parted --script {self.system_path} print")
        time.sleep(1)  # parted command makes partitions invisible for a short while
        if output.exit_code != 0:
            return
        is_part_line = False
        for line in output.stdout.split('\n'):
            if line.strip():
                if is_part_line:
                    part_id, part_type = self.__parse_partition_info(line)
                    if part_type != disk_utils.PartitionType.extended:
                        self.partitions.append(Partition(self, part_type, part_id))
                elif line.startswith("Number"):
                    is_part_line = True

    def create_partitions(
            self,
            sizes: [],
            partition_table_type=disk_utils.PartitionTable.msdos
    ):
        if disk_utils.create_partition_table(self, partition_table_type):
            self.partition_table = partition_table_type
            partition_type = disk_utils.PartitionType.primary

            partition_number_offset = 0
            for s in sizes:
                size = Size(
                    s.get_value(self.block_size) - self.block_size.value, self.block_size)
                if partition_table_type == disk_utils.PartitionTable.msdos and \
                        len(sizes) > 4 and len(self.partitions) == 3:
                    disk_utils.create_partition(self,
                                                Size.zero(),
                                                4,
                                                disk_utils.PartitionType.extended,
                                                Unit.MebiByte,
                                                True)
                    partition_type = disk_utils.PartitionType.logical
                    partition_number_offset = 1

                partition_number = len(self.partitions) + 1 + partition_number_offset
                if disk_utils.create_partition(self,
                                               size,
                                               partition_number,
                                               partition_type,
                                               Unit.MebiByte,
                                               True):
                    new_part = Partition(self,
                                         partition_type,
                                         partition_number)
                    self.partitions.append(new_part)

    def remove_partitions(self):
        for part in self.partitions:
            if part.is_mounted():
                part.unmount()
        if disk_utils.remove_partitions(self):
            self.partitions.clear()

    def __str__(self):
        disk_str = f'system path: {self.system_path}, type: {self.disk_type}, ' \
            f'serial: {self.serial_number}, size: {self.size}, ' \
            f'block size: {self.block_size}, partitions:\n'
        for part in self.partitions:
            disk_str += f'\t{part}'
        return disk_str
