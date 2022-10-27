import io
import os
import time

from scapy.all import TCP, IP, IPv6
from scapy.utils import PcapReader

from systest_utils.encryption_checks import is_file_encrypted


class ScapyWrapper(object):
    """
    Cyber Armor wrapper for scapy (a python package) for easy check encryption of TCP traffic.
    """

    @staticmethod
    def get_tcp_packets(packs, fltr={}):
        """
        Get only tcp packets from a list of packets.

        Parameters:
            packs: an iterator of packets.

        Return value:
            A list of only the tcp packets of the given list.
        """
        return [pack[0] for pack in packs if ScapyWrapper.is_tcp_packet_match(pack[0], fltr)]

    @staticmethod
    def get_tcp_packet_data(pack):
        """
        Get the data that has been transferred above tcp protocol of a tcp packet.

        Parameters:
            pack: tcp packet.

        Return value:
            The data that has been transferred above tcp protocol of the given packet
            as bytes.
        """
        return pack[0][TCP].payload

    @staticmethod
    def get_tcp_packet_src(pack):
        """
        Get the IP address and the port of the source of a tcp packet.

        Parameters:
            pack: tcp packet.

        Return value:
            The IP address and the port of the source of the given packet as
            touple in the pattern of (addr, port).
        """
        port = pack[0][TCP].sport
        addr = pack[0][IP].src if IP in pack[0] else pack[0][IPv6].src
        return addr, port

    @staticmethod
    def get_tcp_packet_dst(pack):
        """
        Get the IP address and the port of the destination of a tcp packet.

        Parameters:
            pack: tcp packet.

        Return value:
            The IP address and the port of the destination of the given packet as
            touple in the pattern of (addr, port).
        """
        port = pack[0][TCP].dport
        addr = pack[0][IP].dst if IP in pack[0] else pack[0][IPv6].dst
        return addr, port

    @staticmethod
    def is_tcp_packet_encrypted(pack, ent=6, min_size=1024):
        """
        Check if the data that has been transferred above tcp protocol of a tcp packet
        is entropied enough to be considered as encrypted.

        Parameters:
            pack: tcp packet.
            ent: level of entropy to be considered as encrypted.
            min_size: minimum size of data to check its encryption. under that size,
                      the return value is always True.

        Return value:
            True if the data is encrypted, False if not.
        """
        tcp_data = bytes(ScapyWrapper.get_tcp_packet_data(pack))

        if len(tcp_data) < min_size:
            return True

        # Logger.logger.debug('Testing tcp encryption on tcp packet')
        data_obj = io.BytesIO(tcp_data)
        return is_file_encrypted(fileobj=data_obj, ent=ent)

    @staticmethod
    def is_tcp_packet_match(pack, fltr):
        """
        Check if a TCP packet match to filter of source and destination addresss and ports.

        Prameters:
            pack: a Scapy packet object.
            fltr: the filter need to be in the form of {'src_ips':[],'dst_ips':[],'src_ports':[],'dst_ports':[]}

        Return value:
            True if the packet match the filter, False if not.
        """
        return TCP in pack[0] and \
               ((pack[0][IP].src if IP in pack else pack[0][IPv6].src) in fltr[
                   'src_ips'] if 'src_ips' in fltr else True) and \
               ((pack[0][IP].dst if IP in pack else pack[0][IPv6].src) in fltr[
                   'dst_ips'] if 'dst_ips' in fltr else True) and \
               (pack[0][TCP].sport in fltr['src_ports'] if 'src_ports' in fltr else True) and \
               (pack[0][TCP].dport in fltr['dst_ports']
                if 'dst_ports' in fltr else True)

    @staticmethod
    def is_pcap_tcp_encrypted(lst, fltr={}, ent=6, min_size=128):
        """
        Check if the data that has been transferred above tcp protocol of all the
        tcp packets inside a scapy packets list is entropied enough to be consider
        as encrypted.

        Parameters:
            lst: iterator of packets.
            fltr: a filter of source or destination ip address or port (or a combination)
                  to be applied on the list of the packets.
            min_size: minimum size of data to check its encryption. All the packets under
                      that size, will not be checked.

        Return value:
            True if the data is encrypted, False if not.
        """
        for pack in lst:
            if not ScapyWrapper.is_tcp_packet_match(pack, fltr):
                continue

            if not ScapyWrapper.is_tcp_packet_encrypted(pack, ent=ent, min_size=min_size):
                return False
        return True

    @staticmethod
    def is_pcap_file_encrypted(path, fltr={}, ent=6, min_size=1024):
        """
        Check if the data that has been transferred above tcp protocol of all the
        tcp packets inside a pcap file is entropied enough to be considered as encrypted.

        Parameters:
            scapy_reader: scapy packets list object (scapy.plist.PacketList).
            fltr: a filter of source or destination ip address or port (or a combination)
                  to be applied on the list of the packets.
            min_size: minimum size of data to check its encryption. All the packets under
                      that size, will not be checked.

        Return value:
            A generator that on every call to next clear the packets buffer and check
            if they are encrypted.

        An example of use the entire solution:
        >>> d = DockerUtils()
        >>> pcap_path = d.start_tcp_dump()
        >>> g = ScapyWrraper.is_pcap_file_encrypted(pcap_path)
        >>> next(g)
        False

        >>> mysql_handler.insert('a'*2000)
        >>> next(g)
        True

        >>> d.stop_tcp_dump()
        >>> os.remove(pcap_path)
        ...
        """
        time.sleep(10)
        reader = PcapReader(path)
        while True:
            lst = reader.read_all()
            yield ScapyWrapper.is_pcap_tcp_encrypted(lst, fltr=fltr, ent=ent, min_size=min_size)
