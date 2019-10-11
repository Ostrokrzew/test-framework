#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from enum import IntEnum, Enum
from test_utils.size import Size, Unit
from datetime import timedelta


class CacheLineSize(IntEnum):
    LINE_4KiB = Size(4, Unit.KibiByte)
    LINE_8KiB = Size(8, Unit.KibiByte)
    LINE_16KiB = Size(16, Unit.KibiByte)
    LINE_32KiB = Size(32, Unit.KibiByte)
    LINE_64KiB = Size(64, Unit.KibiByte)
    DEFAULT = LINE_4KiB


class CacheMode(Enum):
    WT = 0
    WB = 1
    WA = 2
    PT = 3
    WO = 4
    DEFAULT = WT


class SeqCutOffPolicy(Enum):
    full = 0
    always = 1
    never = 2
    DEFAULT = full


class EvictionPolicy(Enum):
    lru = 0
    lmp = 1
    nop = 2


class MetadataMode(Enum):
    normal = 0
    atomic = 1


class CleaningPolicy(Enum):
    alru = 0
    nop = 1
    acp = 2
    DEFAULT = alru


class CacheStatus(Enum):
    not_running = 0
    running = 1
    stopping = 2
    initializing = 3
    flushing = 4
    incomplete = 5


class Time(timedelta):
    def total_milliseconds(self):
        return self.total_seconds() * 1000


class FlushParametersAlru:
    def __init__(self):
        self.activity_threshold = None
        self.flush_max_buffers = None
        self.staleness_time = None
        self.wake_up_time = None

    @staticmethod
    def default_alru_params():
        alru_params = FlushParametersAlru()
        alru_params.activity_threshold = Time(milliseconds=10000)
        alru_params.flush_max_buffers = 100
        alru_params.staleness_time = Time(seconds=120)
        alru_params.wake_up_time = Time(seconds=20)
        return alru_params


class FlushParametersAcp:
    def __init__(self):
        self.flush_max_buffers = None
        self.wake_up_time = None

    @staticmethod
    def default_acp_params():
        acp_params = FlushParametersAcp()
        acp_params.flush_max_buffers = 128
        acp_params.wake_up_time = Time(milliseconds=10)
        return acp_params


class SeqCutOffParameters:
    def __init__(self):
        self.policy = None
        self.threshold = None

    @staticmethod
    def default_seq_cut_off_params():
        seq_cut_off_params = SeqCutOffParameters()
        seq_cut_off_params.policy = SeqCutOffPolicy.full
        seq_cut_off_params.threshold = Size(1024, Unit.KibiByte)


# TODO: Use case for this will be to iterate over configurations (kernel params such as
# TODO: io scheduler, metadata layout) and prepare env before starting cache
class CacheConfig:
    def __init__(self):
        pass
