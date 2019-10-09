#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from test_tools import fs_utils
from test_utils.filesystem.fs_item import FsItem


class Directory(FsItem):
    def __init__(self, full_path):
        FsItem.__init__(self, full_path)

    def ls(self):
        output = fs_utils.ls(f"{self.full_path}")
        return fs_utils.parse_ls_output(output, self.full_path)

    @staticmethod
    def create_directory(path: str, parents: bool = False):
        fs_utils.create_directory(path, parents)
        output = fs_utils.ls_item(path)
        return fs_utils.parse_ls_output(output)[0]
