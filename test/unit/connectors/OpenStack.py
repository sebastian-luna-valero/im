#! /usr/bin/env python
#
# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import unittest
import os
import logging
import logging.config
from StringIO import StringIO

sys.path.append(".")
sys.path.append("..")
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.OpenStack import OpenStackCloudConnector
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestOSTConnector(unittest.TestCase):
    """
    Class to test the IM connectors
    """

    @classmethod
    def setUpClass(cls):
        cls.log = StringIO()
        ch = logging.StreamHandler(cls.log)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)

        logging.RootLogger.propagate = 0
        logging.root.setLevel(logging.ERROR)

        logger = logging.getLogger('CloudConnector')
        logger.setLevel(logging.DEBUG)
        logger.propagate = 0
        logger.addHandler(ch)

    @classmethod
    def clean_log(cls):
        cls.log = StringIO()

    @staticmethod
    def get_ost_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "OpenStack"
        cloud_info.protocol = "https"
        cloud_info.server = "server.com"
        cloud_info.port = 5000
        inf = MagicMock()
        inf.id = "1"
        one_cloud = OpenStackCloudConnector(cloud_info, inf)
        return one_cloud

    @patch('IM.connectors.OpenStack.novacli')
    def test_10_concrete(self, client):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'ost://server.com/ami-id' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        client_mock = MagicMock()
        client.Client.return_value = client_mock
        node_size = MagicMock()
        node_size.ram = 512
        node_size.vcpus = 1
        node_size.name = "small"
        client_mock.flavors.list.return_value = [node_size]

        concrete = ost_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('IM.connectors.OpenStack.novacli')
    @patch('IM.connectors.OpenStack.neutroncli')
    def test_20_launch(self, neutroncli, novacli):
        radl_data = """
            network net1 (outbound = 'yes' and provider_id = 'public' and outports = '8080')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'ost://server.com/ami-id' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        client_mock = MagicMock()
        novacli.Client.return_value = client_mock

        neutroncli_mock = MagicMock()
        neutroncli.Client.return_value = neutroncli_mock

        node_size = MagicMock()
        node_size.ram = 512
        node_size.vcpus = 1
        node_size.name = "small"
        client_mock.flavors.list.return_value = [node_size]

        net = {'network': {'name': 'netname'}}
        subnet = {'subnets': [{'network_id': 'netid', 'cidr': '10.0.0.0/24', 'id': 'subid', 'name': 'subname'}]}
        neutroncli_mock.list_subnets.return_value = subnet
        neutroncli_mock.show_network.return_value = net

        sg = MagicMock()
        sg.name = "sg"
        client_mock.security_groups.create.return_value = sg
        client_mock.security_groups.list.return_value = []
        client_mock.security_group_rules.create.return_value = True

        keypair = MagicMock()
        keypair.public_key = "public"
        client_mock.keypairs.create.return_value = keypair

        node = MagicMock()
        node.id = "ost1"
        node.name = "ost1name"
        client_mock.servers.create.return_value = node

        res = ost_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('IM.connectors.OpenStack.novacli')
    def test_30_updateVMInfo(self, client):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, radl, radl, ost_cloud)

        client_mock = MagicMock()
        client.Client.return_value = client_mock

        node = MagicMock()
        node.id = "1"
        node.status = "ACTIVE"
        node.flavor = {'id': 'small'}
        node.addresses = {'os-lan': [{'addr': '10.0.0.1', 'OS-EXT-IPS:type': 'fixed'}]}
        client_mock.servers.get.return_value = node

        node_size = MagicMock()
        node_size.ram = 512
        node_size.vcpus = 1
        node_size.name = "small"
        client_mock.flavors.get.return_value = node_size

        volume = MagicMock()
        volume.id = "vol1"
        client_mock.volumes.create_server_volume.return_value = True
        client_mock.volumes.create.return_value = volume

        pool = MagicMock()
        pool.name = "pool1"
        client_mock.floating_ips.create.return_value = True
        client_mock.floating_ip_pools.list.return_value = [pool]

        success, vm = ost_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('IM.connectors.OpenStack.novacli')
    def test_40_stop(self, client):
        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, "", "", ost_cloud)

        client_mock = MagicMock()
        client.Client.return_value = client_mock

        node = MagicMock()
        node.id = "1"
        node.status = "ACTIVE"
        node.flavor = {'id': 'small'}
        node.addresses = {'os-lan': [{'addr': '10.0.0.1', 'OS-EXT-IPS:type': 'fixed'}]}
        node.suspend.return_value = True
        client_mock.servers.get.return_value = node

        success, _ = ost_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('IM.connectors.OpenStack.novacli')
    def test_50_start(self, client):
        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, "", "", ost_cloud)

        client_mock = MagicMock()
        client.Client.return_value = client_mock

        node = MagicMock()
        node.id = "1"
        node.status = "ACTIVE"
        node.flavor = {'id': 'small'}
        node.addresses = {'os-lan': [{'addr': '10.0.0.1', 'OS-EXT-IPS:type': 'fixed'}]}
        node.suspend.return_value = True
        client_mock.servers.get.return_value = node

        success, _ = ost_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('IM.connectors.OpenStack.novacli')
    def test_55_alter(self, client):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'one://server.com/1' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        new_radl_data = """
            system test (
            cpu.count>=2 and
            memory.size>=2048m
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, radl, radl, ost_cloud)

        client_mock = MagicMock()
        client.Client.return_value = client_mock

        node = MagicMock()
        node.id = "1"
        node.status = "ACTIVE"
        node.flavor = {'id': 'small'}
        node.addresses = {'os-lan': [{'addr': '10.0.0.1', 'OS-EXT-IPS:type': 'fixed'}]}
        node.resize.return_value = True
        node.confirm_resize.return_value = True
        client_mock.servers.get.return_value = node

        node_size = MagicMock()
        node_size.ram = 512
        node_size.vcpus = 1
        node_size.name = "small"
        client_mock.flavors.get.return_value = node_size

        success, _ = ost_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('IM.connectors.OpenStack.novacli')
    @patch('time.sleep')
    def test_60_finalize(self, sleep, client):
        auth = Authentication([{'id': 'ost', 'type': 'OpenStack', 'username': 'user',
                                'password': 'pass', 'tenant': 'tenant', 'host': 'https://server.com:5000'}])
        ost_cloud = self.get_ost_cloud()

        radl_data = """
            system test (
            cpu.count>=2 and
            memory.size>=2048m
            )"""
        radl = radl_parse.parse_radl(radl_data)

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", ost_cloud.cloud, radl, radl, ost_cloud)

        client_mock = MagicMock()
        client.Client.return_value = client_mock

        node = MagicMock()
        node.id = "1"
        node.status = "ACTIVE"
        node.flavor = {'id': 'small'}
        node.addresses = {'os-lan': [{'addr': '10.0.0.1', 'OS-EXT-IPS:type': 'fixed'}]}
        node.delete.return_value = True
        client_mock.servers.get.return_value = node

        sg = MagicMock()
        sg.id = sg.name = "sg1"
        sg.delete.return_value = True
        client_mock.security_groups.list.return_value = [sg]

        keypair = MagicMock()
        keypair.delete.return_value = True
        client_mock.keypairs.get.return_value = keypair
        vm.keypair = ""

        client_mock.floating_ips.list.return_value = []

        success, _ = ost_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()


if __name__ == '__main__':
    unittest.main()
