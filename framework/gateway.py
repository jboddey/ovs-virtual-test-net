import os
import logger
from scapy.all import *

LOGGER = logger.get_logger('gateway')


class Gateway:

    def __init__(self, runner, port_no, vlan):
        self.runner = runner
        self.device_ready = False
        self.port_no = port_no
        self.device_ip = None
        self.vlan = vlan
        self.gw_iface = "tr-data-{}".format(port_no)
        self.inst_dir = "{}/gw{}".format("inst", port_no)
        
        LOGGER.info('Starting gateway on port %s', port_no)

        # Create temporary data dir
        if not os.path.isdir(self.inst_dir):
            os.makedirs(self.inst_dir)
 
        self._prepare_device()
        
        
    def _prepare_device(self):
    
        # Begin startup packet capture
        ## TODO: Make timeout configurable
        self._start_capture('startup', packet_callback=self._startup_listener, timeout=30)

        if not self.device_ready:
            LOGGER.info("Device timeout whilst waiting for device startup")
            self.runner.close_port(self.port_no)
            self.device_ready = False
            return False
        else:
            LOGGER.info("Completed startup capture")

        ## TODO: Make timeout configurable
        monitor_timeout = 10
        LOGGER.info("Monitoring device behaviour for %s seconds", monitor_timeout)
        self._start_capture('monitor', timeout=monitor_timeout)
        LOGGER.info("Finished monitoring device.")
        
        return True

    # Begin packet capture whilst device is obtaining IP lease
    def _start_capture(self, name, stop_filter=None, packet_callback=None, timeout=None):
        LOGGER.info("Beginning {} capture on {} interface".format(name, self.gw_iface))
        capture_file = "{}/{}.pcap".format(self.inst_dir, name)
        capture = sniff(iface=self.gw_iface, prn=packet_callback, stop_filter=stop_filter, timeout=timeout)
        wrpcap(capture_file, capture)

    # Record device IP address
    def _startup_listener(self, packet):
        device_has_ip = (packet.haslayer(DHCP) and ([x[1] for x in packet[DHCP].options if x[0] == 'message-type'][0]) == 5)
        if device_has_ip:
            self.device_ip = packet[IP].dst
            LOGGER.info("Device on port {} received IP {}".format(self.port_no, self.device_ip))
            output = self.runner.ping_test(self.device_ip)
            self.device_ready = True
            # TODO: Check if ping is failed

    def _run_command(self, command):
        process = subprocess.Popen(command.split())
        return process.communicate()
            
        
        
