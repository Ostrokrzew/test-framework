#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#


import logging
import pytest
from api.cas import casadm, casadm_parser
from test_package.conftest import base_prepare
from core.test_properties import TestProperties
from storage_devices.disk import DiskType

LOGGER = logging.getLogger(__name__)


@pytest.mark.parametrize("shortcut", [True, False])
@pytest.mark.parametrize('prepare_and_cleanup',
                         [{"core_count": 0, "cache_count": 1, "cache_type": "optane"}, ],
                         indirect=True)
def test_cli_start_stop_default_value(prepare_and_cleanup, shortcut):
    prepare()
    cache_device = next(
        disk for disk in TestProperties.dut.disks if disk.disk_type == DiskType.optane)
    casadm.start_cache(cache_device, shortcut=shortcut, force=True)

    caches = casadm_parser.get_caches()
    assert len(caches) == 1
    assert caches[0].cache_device.system_path == cache_device.system_path

    casadm.stop_cache(cache_id=caches[0].cache_id, shortcut=shortcut)

    output = casadm.list_caches(shortcut=shortcut)
    caches = casadm_parser.get_caches()
    assert len(caches) == 0
    assert output.stdout == "No caches running"


@pytest.mark.parametrize("shortcut", [True, False])
@pytest.mark.parametrize('prepare_and_cleanup',
                         [{"core_count": 1, "cache_count": 1, "cache_type": "optane"}],
                         indirect=True)
def test_cli_add_remove_default_value(prepare_and_cleanup, shortcut):
    prepare()
    cache_device = next(
        disk for disk in TestProperties.dut.disks if disk.disk_type == DiskType.optane)
    cache = casadm.start_cache(cache_device, shortcut=shortcut, force=True)

    core_device = next(
        disk for disk in TestProperties.dut.disks if disk.disk_type != DiskType.optane)
    casadm.add_core(cache, core_device, shortcut=shortcut)

    caches = casadm_parser.get_caches()
    assert len(caches[0].get_core_devices()) == 1
    assert caches[0].get_core_devices()[0].core_device.system_path == core_device.system_path

    casadm.remove_core(cache.cache_id, 1, shortcut=shortcut)
    caches = casadm_parser.get_caches()
    assert len(caches) == 1
    assert len(caches[0].get_core_devices()) == 0

    casadm.stop_cache(cache_id=cache.cache_id, shortcut=shortcut)

    output = casadm.list_caches(shortcut=shortcut)
    caches = casadm_parser.get_caches()
    assert len(caches) == 0
    assert output.stdout == "No caches running"


def prepare():
    base_prepare()
