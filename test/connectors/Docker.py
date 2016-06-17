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
from IM.connectors.Docker import DockerCloudConnector
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestDockerConnector(unittest.TestCase):
    """
    Class to test the IM connectors
    """

    @classmethod
    def setUpClass(cls):
        cls.last_op = None, None
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
    def get_docker_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "Kubernetes"
        cloud_info.protocol = "http"
        cloud_info.server = "server.com"
        cloud_info.port = 2375
        cloud = DockerCloudConnector(cloud_info)
        return cloud

    def test_10_concrete(self):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'docker://someimage' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        concrete = docker_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    def get_response(self):
        method, url = self.__class__.last_op

        resp = MagicMock()

        if method == "GET":
            if url == "/api/":
                resp.status = 200
                resp.read.return_value = '{"versions": "v1"}'
            if url == "/containers/1/json":
                resp.status = 200
                resp.read.return_value = '{"State": {"Running": 1}, "NetworkSettings": {"IPAddress": "10.0.0.1"}}'
        elif method == "POST":
            if url == "/containers/create":
                resp.status = 201
                resp.read.return_value = '{"Id": "id"}'
            elif url.endswith("/start"):
                resp.status = 204
            elif url.endswith("/stop"):
                resp.status = 204
        elif method == "DELETE":
            if url.endswith("/containers/1"):
                resp.status = 204

        return resp

    def request(self, method, url, body=None, headers={}):
        self.__class__.last_op = method, url

    @patch('httplib.HTTPConnection')
    def test_20_launch(self, connection):
        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'docker://someimage' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.putrequest.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        res = docker_cloud.launch(InfrastructureInfo(), radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('httplib.HTTPConnection')
    def test_30_updateVMInfo(self, connection):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'docker://someimage' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", docker_cloud.cloud, radl, radl, docker_cloud)

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        success, vm = docker_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('httplib.HTTPConnection')
    def test_40_stop(self, connection):
        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", docker_cloud.cloud, "", "", docker_cloud)

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        success, _ = docker_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('httplib.HTTPConnection')
    def test_50_start(self, connection):
        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", docker_cloud.cloud, "", "", docker_cloud)

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        success, _ = docker_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()

    @patch('httplib.HTTPConnection')
    def test_60_finalize(self, connection):
        auth = Authentication([{'id': 'docker', 'type': 'Docker', 'host': 'http://server.com:2375'}])
        docker_cloud = self.get_docker_cloud()

        inf = MagicMock()
        inf.get_next_vm_id.return_value = 1
        vm = VirtualMachine(inf, "1", docker_cloud.cloud, "", "", docker_cloud)

        conn = MagicMock()
        connection.return_value = conn

        conn.request.side_effect = self.request
        conn.getresponse.side_effect = self.get_response

        success, _ = docker_cloud.finalize(vm, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.clean_log()


if __name__ == '__main__':
    unittest.main()
