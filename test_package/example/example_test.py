#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import pytest
from test_tools.disk_utils import Filesystem
from test_utils.size import Size, Unit
from core.test_run import TestRun
from test_package.conftest import base_prepare
from test_utils.filesystem.file import File
from test_utils.filesystem.directory import Directory
from test_tools import fs_utils


def setup_module():
    TestRun.LOGGER.warning("Entering setup method")


@pytest.mark.parametrize('prepare_and_cleanup',
                         [{"cache_type": "nand", "cache_count": 1}],
                         indirect=True)
def test_create_example_partitions(prepare_and_cleanup):
    prepare()
    TestRun.LOGGER.info("Test run")
    TestRun.LOGGER.info(f"DUT info: {TestRun.dut}")
    test_disk = TestRun.dut.disks[0]
    part_sizes = []
    for i in range(1, 6):
        part_sizes.append(Size(10 * i + 100, Unit.MebiByte))
    test_disk.create_partitions(part_sizes)
    TestRun.LOGGER.info(f"DUT info: {TestRun.dut}")
    test_disk.partitions[0].create_filesystem(Filesystem.ext3)


@pytest.mark.parametrize('prepare_and_cleanup',
                         [{"cache_type": "nand", "cache_count": 1}],
                         indirect=True)
def test_create_example_files(prepare_and_cleanup):
    prepare()
    TestRun.LOGGER.info("Test run")
    file1 = File.create_file("example_file")
    file1.write("Test file\ncontent line\ncontent")
    content_before_change = file1.read()
    TestRun.LOGGER.info(f"File content: {content_before_change}")
    fs_utils.replace_in_lines(file1, 'content line', 'replaced line')

    content_after_change = file1.read()
    assert content_before_change != content_after_change

    file2 = file1.copy('/tmp', force=True)
    assert file1.md5sum() == file2.md5sum()

    file2.chmod_numerical(123)
    fs_utils.remove(file2.full_path, True)
    dir1 = Directory("~")
    dir_content = dir1.ls()
    file1.chmod(fs_utils.Permissions['r'] | fs_utils.Permissions['w'], fs_utils.PermissionsUsers(7))
    for item in dir_content:
        TestRun.LOGGER.info(f"Item {str(item)} - {type(item).__name__}")
    fs_utils.remove(file1.full_path, True)


def prepare():
    base_prepare()
