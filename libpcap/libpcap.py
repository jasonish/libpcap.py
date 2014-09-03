# Copyright (c) 2014 Jason Ish
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import print_function

import ctypes
import ctypes.util

PCAP_ERRBUF_SIZE = 256

libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library("c"))
libpcap = ctypes.cdll.LoadLibrary(ctypes.util.find_library("pcap"))
libpcap.pcap_geterr.restype = ctypes.c_char_p
pcap_errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)

class pcap_pkthdr(ctypes.Structure):
    """Internal class representing struct pcap_pkthdr. """
    _fields_ = [
        ("ts_sec", ctypes.c_ulong),
        ("ts_usec", ctypes.c_ulong),
        ("caplen", ctypes.c_uint32),
        ("pktlen", ctypes.c_uint32),
    ]

    def __repr__(self):
        return str({"ts_sec": self.ts_sec,
                    "ts_usec": self.ts_usec,
                    "caplen": self.caplen,
                    "pktlen": self.pktlen})

class Pcap:

    def __init__(self, pcap_t):
        self.pcap_t = pcap_t
        self.pkt_header = ctypes.pointer(pcap_pkthdr())
        self.pkt_data = ctypes.c_void_p()

    def get_error(self):
        return libpcap.pcap_geterr(self.pcap_t)

    def datalink(self):
        return libpcap.pcap_datalink(self.pcap_t)

    def set_filter(self, filter_string):
        """ Compile and set a BPF filter. """
        bpf_program = ctypes.c_void_p()
        r = libpcap.pcap_compile(
            self.pcap_t, 
            ctypes.byref(bpf_program), 
            filter_string.encode(), 1, 0)
        if r != 0:
            raise Exception("failed to compile filter: %s: %s" % (
                filter_string, self.get_error()))
        if libpcap.pcap_setfilter(self.pcap_t, ctypes.byref(bpf_program)) != 0:
            raise Exception("failed to set filter: %s" % (
                self.get_error()))

    def next(self):
        """Read the next packet."""
        rc = libpcap.pcap_next_ex(
            self.pcap_t,
            ctypes.byref(self.pkt_header),
            ctypes.byref(self.pkt_data))
        if rc == 1:
            return {
                "ts_sec": self.pkt_header.contents.ts_sec,
                "ts_usec": self.pkt_header.contents.ts_usec,
                "caplen": self.pkt_header.contents.caplen,
                "pktlen": self.pkt_header.contents.pktlen,
                "data": ctypes.string_at(self.pkt_data,
                                         self.pkt_header.contents.caplen),
            }
        elif rc in [-2, 0]:
            # Timeout or EOF.
            return None
        else:
            raise Exception(libpcap.geterr(self.pcap_t))

def open_live(device, snaplen=65535, promisc=True, to_ms=100, bpf_filter=None):
    """Open a device for packet capture."""
    pcap_t = libpcap.pcap_open_live(
        device.encode(), snaplen, promisc, to_ms, pcap_errbuf)
    if not pcap_t:
        raise Exception("Error opening %s: %s" % (device, pcap_errbuf.value))
    pcap = Pcap(pcap_t)
    if bpf_filter:
        pcap.set_filter(bpf_filter)
    return pcap

def open_offline(filename, bpf_filter=None):
    """Open a pcap savefile for reading."""
    pcap_t = libpcap.pcap_open_offline(filename, pcap_errbuf)
    if not pcap_t:
        raise Exception(pcap_errbuf.value)
    pcap = Pcap(pcap_t)
    if bpf_filter:
        pcap.set_filter(bpf_filter)
    return pcap
