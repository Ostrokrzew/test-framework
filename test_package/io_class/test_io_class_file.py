#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from test_utils.os_utils import drop_caches
from .test_io_classification import *


@pytest.mark.parametrize(
    "prepare_and_cleanup", [{"core_count": 1, "cache_count": 1}], indirect=True
)
def test_ioclass_file_extension(prepare_and_cleanup):
    cache, core = prepare()
    iterations = 50
    ioclass_id = 1
    tested_extension = "tmp"
    wrong_extensions = ["tm", "tmpx", "txt", "t", "", "123"]
    dd_size = Size(4, Unit.KibiByte)
    dd_count = 10

    ioclass_config.add_ioclass(
        ioclass_id=ioclass_id,
        eviction_priority=1,
        allocation=True,
        rule=f"extension:{tested_extension}&done",
        ioclass_config_path=ioclass_config_path,
    )
    casadm.load_io_classes(cache_id=cache.cache_id, file=ioclass_config_path)

    TestProperties.LOGGER.info(
        f"Preparing filesystem and mounting {core.system_path} at {mountpoint}"
    )

    core.create_filesystem(Filesystem.ext3)
    core.mount(mountpoint)

    cache.flush_cache()

    # Check if file with proper extension is cached
    dd = (
        Dd()
        .input("/dev/zero")
        .output(f"{mountpoint}/test_file.{tested_extension}")
        .count(dd_count)
        .block_size(dd_size)
    )
    TestProperties.LOGGER.info(f"Writing to file with cached extension.")
    for i in range(iterations):
        dd.run()
        sync()
        stats = cache.get_cache_statistics(per_io_class=True, io_class_id=ioclass_id)
        assert stats["dirty"].get_value(Unit.Blocks4096) == (i + 1) * dd_count

    cache.flush_cache()

    # Check if file with improper extension is not cached
    TestProperties.LOGGER.info(f"Writing to file with no cached extension.")
    for ext in wrong_extensions:
        dd = (
            Dd()
            .input("/dev/zero")
            .output(f"{mountpoint}/test_file.{ext}")
            .count(dd_count)
            .block_size(dd_size)
        )
        dd.run()
        sync()
        stats = cache.get_cache_statistics(per_io_class=True, io_class_id=ioclass_id)
        assert stats["dirty"].get_value(Unit.Blocks4096) == 0


@pytest.mark.parametrize(
    "prepare_and_cleanup", [{"core_count": 1, "cache_count": 1}], indirect=True
)
def test_ioclass_file_extension_preexisting_filesystem(prepare_and_cleanup):
    """Create files on filesystem, add device with filesystem as a core,
        write data to files and check if they are cached properly"""
    cache, core = prepare()
    ioclass_id = 1
    extensions = ["tmp", "tm", "out", "txt", "log", "123"]
    dd_size = Size(4, Unit.KibiByte)
    dd_count = 10

    TestProperties.LOGGER.info(f"Preparing files on raw block device")
    casadm.remove_core(cache.cache_id, core_id=core.core_id)
    core.core_device.create_filesystem(Filesystem.ext3)
    core.core_device.mount(mountpoint)

    # Prepare files
    for ext in extensions:
        dd = (
            Dd()
            .input("/dev/zero")
            .output(f"{mountpoint}/test_file.{ext}")
            .count(dd_count)
            .block_size(dd_size)
        )
        dd.run()
    core.core_device.unmount()

    # Prepare ioclass config
    rule = "|".join([f"extension:{ext}" for ext in extensions])
    ioclass_config.add_ioclass(
        ioclass_id=ioclass_id,
        eviction_priority=1,
        allocation=True,
        rule=f"{rule}&done",
        ioclass_config_path=ioclass_config_path,
    )

    # Prepare cache for test
    TestProperties.LOGGER.info(f"Adding device with preexisting data as a core")
    core = casadm.add_core(cache, core_dev=core.core_device)
    casadm.load_io_classes(cache_id=cache.cache_id, file=ioclass_config_path)

    core.mount(mountpoint)
    cache.flush_cache()

    # Check if files with proper extensions are cached
    TestProperties.LOGGER.info(f"Writing to file with cached extension.")
    for ext in extensions:
        dd = (
            Dd()
            .input("/dev/zero")
            .output(f"{mountpoint}/test_file.{ext}")
            .count(dd_count)
            .block_size(dd_size)
        )
        dd.run()
        sync()
        stats = cache.get_cache_statistics(per_io_class=True, io_class_id=ioclass_id)
        assert (
            stats["dirty"].get_value(Unit.Blocks4096)
            == (extensions.index(ext) + 1) * dd_count
        )


@pytest.mark.parametrize(
    "prepare_and_cleanup", [{"core_count": 1, "cache_count": 1}], indirect=True
)
def test_ioclass_file_offset(prepare_and_cleanup):
    cache, core = prepare()

    ioclass_id = 1
    iterations = 100
    dd_size = Size(4, Unit.KibiByte)
    dd_count = 1
    min_cached_offset = 16384
    max_cached_offset = 65536

    ioclass_config.add_ioclass(
        ioclass_id=ioclass_id,
        eviction_priority=1,
        allocation=True,
        rule=f"file_offset:gt:{min_cached_offset}&file_offset:lt:{max_cached_offset}&done",
        ioclass_config_path=ioclass_config_path,
    )
    casadm.load_io_classes(cache_id=cache.cache_id, file=ioclass_config_path)

    TestProperties.LOGGER.info(
        f"Preparing filesystem and mounting {core.system_path} at {mountpoint}"
    )
    core.create_filesystem(Filesystem.ext3)
    core.mount(mountpoint)

    cache.flush_cache()

    # Since ioclass rule consists of strict inequalities, 'seek' can't be set to first
    # nor last sector
    min_seek = int((min_cached_offset + Unit.Blocks4096.value) / Unit.Blocks4096.value)
    max_seek = int(
        (max_cached_offset - min_cached_offset - Unit.Blocks4096.value)
        / Unit.Blocks4096.value
    )
    TestProperties.LOGGER.info(f"Writing to file within cached offset range")
    for i in range(iterations):
        file_offset = random.choice(range(min_seek, max_seek))
        dd = (
            Dd()
            .input("/dev/zero")
            .output(f"{mountpoint}/tmp_file")
            .count(dd_count)
            .block_size(dd_size)
            .seek(file_offset)
        )
        dd.run()
        sync()
        stats = cache.get_cache_statistics(per_io_class=True, io_class_id=ioclass_id)
        assert (
            stats["dirty"].get_value(Unit.Blocks4096) == 1
        ), f"Offset not cached: {file_offset}"
        cache.flush_cache()

    min_seek = 0
    max_seek = int(min_cached_offset / Unit.Blocks4096.value)
    TestProperties.LOGGER.info(f"Writing to file outside of cached offset range")
    for i in range(iterations):
        file_offset = random.choice(range(min_seek, max_seek))
        dd = (
            Dd()
            .input("/dev/zero")
            .output(f"{mountpoint}/tmp_file")
            .count(dd_count)
            .block_size(dd_size)
            .seek(file_offset)
        )
        dd.run()
        sync()
        stats = cache.get_cache_statistics(per_io_class=True, io_class_id=ioclass_id)
        assert (
            stats["dirty"].get_value(Unit.Blocks4096) == 0
        ), f"Inappropriately cached offset: {file_offset}"


@pytest.mark.parametrize(
    "prepare_and_cleanup", [{"core_count": 1, "cache_count": 1}], indirect=True
)
def test_ioclass_file_size(prepare_and_cleanup):
    def load_file_size_io_classes():
        # IO class order intentional, do not change
        base_size_bytes = int(base_size.get_value(Unit.Byte))
        ioclass_config.add_ioclass(
            ioclass_id=1,
            eviction_priority=1,
            allocation=True,
            rule=f"file_size:eq:{base_size_bytes}",
            ioclass_config_path=ioclass_config_path,
        )
        ioclass_config.add_ioclass(
            ioclass_id=2,
            eviction_priority=1,
            allocation=True,
            rule=f"file_size:lt:{base_size_bytes}",
            ioclass_config_path=ioclass_config_path,
        )
        ioclass_config.add_ioclass(
            ioclass_id=3,
            eviction_priority=1,
            allocation=True,
            rule=f"file_size:gt:{base_size_bytes}",
            ioclass_config_path=ioclass_config_path,
        )
        ioclass_config.add_ioclass(
            ioclass_id=4,
            eviction_priority=1,
            allocation=True,
            rule=f"file_size:le:{int(base_size_bytes / 2)}",
            ioclass_config_path=ioclass_config_path,
        )
        ioclass_config.add_ioclass(
            ioclass_id=5,
            eviction_priority=1,
            allocation=True,
            rule=f"file_size:ge:{2 * base_size_bytes}",
            ioclass_config_path=ioclass_config_path,
        )
        casadm.load_io_classes(cache_id=cache.cache_id, file=ioclass_config_path)

    def create_files_and_check_classification():
        TestProperties.LOGGER.info("Creating files belonging to different IO classes "
                                   "(classification by writes).")
        for size in size_to_class.keys():
            ioclass_id = size_to_class[size]
            occupancy_before = cache.get_cache_statistics(
                per_io_class=True, io_class_id=ioclass_id)["occupancy"]
            file_path = f"{mountpoint}/test_file_{size.get_value()}"
            Dd().input("/dev/zero").output(file_path).oflag("sync").block_size(size).count(1).run()
            occupancy_after = cache.get_cache_statistics(
                per_io_class=True, io_class_id=ioclass_id)["occupancy"]
            if occupancy_after != occupancy_before + size:
                pytest.xfail("File not cached properly!\n"
                             f"Expected {occupancy_before + size}\n"
                             f"Actual {occupancy_after}")
            test_files.append(File(file_path).refresh_item())
        sync()
        drop_caches(3)

    def reclassify_files():
        TestProperties.LOGGER.info("Reading files belonging to different IO classes "
                                   "(classification by reads).")
        for file in test_files:
            ioclass_id = size_to_class[file.size]
            occupancy_before = cache.get_cache_statistics(
                per_io_class=True, io_class_id=ioclass_id)["occupancy"]
            Dd().input(file.full_path).output("/dev/null").block_size(file.size).run()
            occupancy_after = cache.get_cache_statistics(
                per_io_class=True, io_class_id=ioclass_id)["occupancy"]
            if occupancy_after != occupancy_before + file.size:
                pytest.xfail("File not reclassified properly!\n"
                             f"Expected {occupancy_before + file.size}\n"
                             f"Actual {occupancy_after}")
        sync()
        drop_caches(3)

    def remove_files_classification():
        TestProperties.LOGGER.info("Moving all files to 'unclassified' IO class")
        ioclass_config.remove_ioclass_config(ioclass_config_path=ioclass_config_path)
        ioclass_config.create_ioclass_config(
            add_default_rule=False, ioclass_config_path=ioclass_config_path
        )
        ioclass_config.add_ioclass(
            ioclass_id=0,
            eviction_priority=22,
            allocation=False,
            rule="unclassified",
            ioclass_config_path=ioclass_config_path,
        )
        casadm.load_io_classes(cache_id=cache.cache_id, file=ioclass_config_path)
        occupancy_before = cache.get_cache_statistics(
            per_io_class=True, io_class_id=0)["occupancy"]
        for file in test_files:
            Dd().input(file.full_path).output("/dev/null").block_size(file.size).run()
            occupancy_after = cache.get_cache_statistics(
                per_io_class=True, io_class_id=0)["occupancy"]
            if occupancy_after != occupancy_before + file.size:
                pytest.xfail("File not reclassified properly!\n"
                             f"Expected {occupancy_before + file.size}\n"
                             f"Actual {occupancy_after}")
            occupancy_before = occupancy_after
        sync()
        drop_caches(3)

    def restore_classification_config():
        TestProperties.LOGGER.info("Restoring IO class configuration")
        ioclass_config.remove_ioclass_config(ioclass_config_path=ioclass_config_path)
        ioclass_config.create_ioclass_config(
            add_default_rule=False, ioclass_config_path=ioclass_config_path
        )
        ioclass_config.add_ioclass(
            ioclass_id=0,
            eviction_priority=22,
            allocation=False,
            rule="unclassified",
            ioclass_config_path=ioclass_config_path,
        )
        load_file_size_io_classes()

    cache, core = prepare()
    cache.flush_cache()
    Udev.disable()
    base_size = Size(random.randint(50, 1000) * 2, Unit.Blocks4096)
    size_to_class = {
        base_size: 1,
        base_size - Unit.Blocks4096: 2,
        base_size + Unit.Blocks4096: 3,
        base_size / 2: 4,
        base_size / 2 - Unit.Blocks4096: 4,
        base_size / 2 + Unit.Blocks4096: 2,
        base_size * 2: 5,
        base_size * 2 - Unit.Blocks4096: 3,
        base_size * 2 + Unit.Blocks4096: 5,
    }

    load_file_size_io_classes()

    for filesystem in [Filesystem.xfs, Filesystem.ext3, Filesystem.ext4]:
        TestProperties.LOGGER.info(f"Preparing {filesystem.name} filesystem "
                                   f"and mounting {core.system_path} at {mountpoint}")
        core.create_filesystem(filesystem)
        core.mount(mountpoint)
        sync()

        test_files = []
        create_files_and_check_classification()

        remove_files_classification()

        restore_classification_config()
        reclassify_files()

        # cleanup
        remove_files_classification()
        restore_classification_config()

        core.unmount()
