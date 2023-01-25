"""Runner"""

from scapy.all import *
import time
import logger
import docker
import subprocess
from gateway import Gateway
from config import Config

LOGGER = logger.get_logger('runner')
TEST_LIST_FILE = 'config/modules.json'

class PortInfo:
    active = False
    port_no = None
    vxlan = None

class IpInfo:
    ip_addr = None

class Device:

    def __init__(self):
        self.mac = None
        self.port_info = None
        self.ip_info = None
        
class TestModule:

    def __init__(self, name):
        self.name = name
        self.name_short = None
        self.module_url = None

class Devices:
    
    def __init__(self):
        self._devices = {}

    def new_device(self, mac, port_info):
        assert mac not in self._devices, "Device with mac: %s is already added." % mac
        device = Device()
        device.mac = mac
        self._devices[mac] = device
        device.port_info = port_info
        return device

    def create_if_absent(self, target_mac, vlan):
        port_info = PortInfo()
        port_info.active = True
 
        # Get offset from config
        port_info.port_no = vlan - 100
        port_info.vxlan = vlan

        device = self.new_device(target_mac, port_info)
        return device

    def get(self, device_mac):
        return self._devices.get(device_mac)

    def get_port(self, port_no):
        for mac in self._devices:
            if self._devices[mac].port_info.port_no == port_no:
                return self._devices[mac]

class Runner:

    def __init__(self):
        self._devices = Devices()
        self._gateways = set()
        self._docker = docker.from_env()
        self._test_modules = set()
        self.config = Config()
        
        self._init_test_list()

    def main_loop(self):
        LOGGER.info("Entering main event loop.")
        LOGGER.info("Listening for devices on data bridge %s", self.config.get("data_bridge"))
        # TODO: Add troubleshooting message?
        
        t = AsyncSniffer(iface=self.config.get("data_bridge"), prn=self.device_listener)
        t.start()
        
        # Timeout after 5 minutes
        time.sleep(300)
        
        t.stop()
        LOGGER.info("Test Run is done. Cleaning up environment")

    def _handle_device_learn(self, target_mac, vid):

        if not self._devices.get(target_mac):
            LOGGER.info("Learning %s on vid %s", target_mac, vid)
        else:
            return

        # Create gateway
        gateway = self._create_gateway(vid-100, vid)
        
        if not gateway.device_ready:
            return
        
        # Create device
        device = self._devices.create_if_absent(target_mac, vlan=vid)
        
        # Test device
        self._device_test_loop(device)

    def _create_gateway(self, port_no, vlan):
    
        LOGGER.info("Creating bridge for device on port %s", port_no)
        self.run_command("cmd/create_bridge {}".format(port_no))

        LOGGER.info("Launching gw%s container", port_no)
        self._start_gateway_container(port_no)
        
        gateway = Gateway(self, port_no, vlan)
        self._gateways.add(gateway)
        
        return gateway
        
    def _start_gateway_container(self, port_no):
    
        container_name = "gw-{}".format(port_no)
        self._docker.containers.run(image="test-run/gateway",
                                    auto_remove=True,
                                    remove=True,
                                    privileged=True,
                                    environment=["PORT_NO={}".format(port_no)],
                                    network="none",
                                    name="tr-{}".format(container_name),
                                    cap_add=["NET_ADMIN"],
                                    detach=True)
                                    
        LOGGER.info("Attaching gateway container to device bridge on port %s", port_no)
        self.run_command("cmd/add_container_to_data_bridge {} {}".format(container_name, port_no))
        LOGGER.info("Attaching gateway container to control bridge")
        self.run_command("cmd/add_container_to_control_bridge {} {}".format(container_name, port_no))

    def run_command(self, command):
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        return process.communicate()

    def device_listener(self, packet):
        if packet.haslayer(Dot1Q) and not packet.src.startswith("9a:02:57:1e:8f"):
            if self._devices.get(packet.src) is None:
                vlan_id = packet[Dot1Q].vlan
                port_no = vlan_id - 100
                if self._devices.get_port(port_no) is None:
                    self._handle_device_learn(packet.src, vlan_id)
                    
    def ping_test(self, dst, count=5):
        LOGGER.info('Test ping -> %s', dst)
        output, error = self.run_command("ping -c {} {}".format(count, dst))
        return output
        
    def close_port(self, port_no):
        LOGGER.info("Closing down port %s", port_no)
        self.run_command("cmd/clean_port {}".format(port_no))
        
    def _init_test_list(self):
        data = self.config.get_json_data(TEST_LIST_FILE)
        modules_dict = data['modules']
        for module in modules_dict:
            LOGGER.debug("Found module %s", module['name'])
            test_module = TestModule(module['name'])
            ## TODO: Check if module URL has been specified
            test_module.name_short = module['name_short']
            test_module.module_url = module['module_url']
            self._test_modules.add(test_module)
            
        running_with_modules = "Running with test modules: "
        for module in self._test_modules:
            running_with_modules += module.name_short + " "
        LOGGER.info(running_with_modules)    
       
    def get_test_modules(self):
        return self._test_modules
        
    def _device_test_loop(self, device):
    
        LOGGER.info("Running configured tests on device %s", device.mac)
        
        for module in self.get_test_modules():
            LOGGER.info("Starting test module %s on device %s", module.name_short, device.mac)
            self._run_test(device, module)
            
        LOGGER.info("Completed testing on device %s", device.mac)
            
    def _run_test(self, device, module):
    
        container_name = "{}{}".format(module.name_short, device.port_info.port_no)
        
        LOGGER.info("Launching container %s", container_name)
        
        container = self._docker.containers.run(image="test-run/{}".format(module.name_short),
                                    remove=True,
                                    network="none",
                                    detach=True,
                                    name="tr-{}".format(container_name),
                                    cap_add=["NET_ADMIN"]) 
                                    
        self.run_command("cmd/add_container_to_data_bridge {} {}".format(container_name, device.port_info.port_no))
        
        container.attach()
                                    
        LOGGER.info("Finished module %s", module.name_short)

runner = Runner()
runner.main_loop()
