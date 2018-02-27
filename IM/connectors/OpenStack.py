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

import time
import os
import tempfile
from netaddr import IPNetwork, IPAddress

try:
    from novaclient import client as novacli
    from novaclient.exceptions import NotFound
    from neutronclient.v2_0 import client as neutroncli
except Exception as ex:
    print("WARN: libcloud library not correctly installed. OpenStackCloudConnector will not work!.")
    print(ex)

from IM.config import Config
from IM.uriparse import uriparse
from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from radl.radl import Feature


class OpenStackCloudConnector(CloudConnector):
    """
    Cloud Launcher to OpenStack using python-novaclient
    """

    type = "OpenStack"
    """str with the name of the provider."""
    DEFAULT_USER = 'cloudadm'
    """ default user to SSH access the VM """
    MAX_ADD_IP_COUNT = 5
    """ Max number of retries to get a public IP """
    CONFIG_DRIVE = False
    """ Enable config drive """

    VM_STATE_MAP = {
        'BUILDING': VirtualMachine.PENDING,
        'ACTIVE': VirtualMachine.RUNNING,
        'DELETED': VirtualMachine.OFF,
        'SOFT_DELETED': VirtualMachine.OFF,
        'ERROR': VirtualMachine.FAILED,
        'STOPPED': VirtualMachine.STOPPED,
        'SUSPENDED': VirtualMachine.STOPPED,
        'PAUSED': VirtualMachine.STOPPED,
        'RESIZED': VirtualMachine.STOPPED,
        'RESCUED': VirtualMachine.STOPPED,
        'SHELVED': VirtualMachine.STOPPED
    }

    def __init__(self, cloud_info, inf):
        self.auth = None
        self.novaclient = None
        self.netronclient = None
        CloudConnector.__init__(self, cloud_info, inf)

    def get_client(self, auth_data, type="nova"):
        """
        Get the OST client from the auth data

        Arguments:
                - auth(Authentication): parsed authentication tokens.

        Returns: a :py:class:`novaclient.client.Client` or None in case of error
        """
        auths = auth_data.getAuthInfo(self.type, self.cloud.server)
        if not auths:
            raise Exception("No auth data has been specified to OpenStack.")
        else:
            auth = auths[0]

        if self.novaclient and self.netronclient and self.auth.compare(auth_data, self.type):
            pass
        else:
            self.auth = auth_data

            protocol = self.cloud.protocol
            if not protocol:
                protocol = "http"

            parameters = {"auth_version": '2.0_password',
                          "auth_url": protocol + "://" + self.cloud.server + ":" + str(self.cloud.port),
                          "auth_token": None,
                          "service_type": None,
                          "service_name": None,
                          "service_region": 'RegionOne',
                          "base_url": None,
                          "domain": None}

            if 'username' in auth and 'password' in auth and 'tenant' in auth:
                for param in parameters:
                    if param in auth:
                        parameters[param] = auth[param]
            elif 'proxy' in auth:
                (fproxy, proxy_filename) = tempfile.mkstemp()
                os.write(fproxy, auth['proxy'].encode())
                os.close(fproxy)
                auth['username'] = ''
                auth['password'] = proxy_filename
                parameters["auth_version"] = '2.0_voms'

                for param in parameters:
                    if param in auth:
                        parameters[param] = auth[param]
            else:
                self.log_error(
                    "No correct auth data has been specified to OpenStack: username, password and tenant or proxy")
                raise Exception(
                    "No correct auth data has been specified to OpenStack: username, password and tenant or proxy")

            version = "2.0"
            nova = novacli.Client(version,
                                  username=auth['username'],
                                  api_key=auth['password'],
                                  project_id=auth['tenant'],
                                  auth_url=parameters["auth_url"],
                                  region_name=parameters["service_region"],
                                  service_name=parameters["service_name"],
                                  bypass_url=parameters["base_url"],
                                  insecure=True)

            self.novaclient = nova

            neutron = neutroncli.Client(auth_url=parameters["auth_url"],
                                        username=auth['username'],
                                        password=auth['password'],
                                        tenant_name=auth['tenant'],
                                        region_name=parameters["service_region"],
                                        insecure=True)

            self.netronclient = neutron

        if type == "nova":
            return self.novaclient
        elif type == "neutron":
            return self.netronclient
        else:
            self.log_error("Invalid type: %s" % type)
            return None

    def get_instance_type(self, flavors, radl):
        """
        Get the flavor type to launch to OST

        Arguments:
           - size(list of :py:class: `novaclient.flavors.Flavor`): List of sizes on a provider
           - radl(str): RADL document with the requirements of the VM to get the instance type
        Returns: a :py:class:`novaclient.flavors.Flavor` with the instance type to launch
        """
        instance_type_name = radl.getValue('instance_type')

        memory = 1
        memory_op = ">="
        if radl.getFeature('memory.size'):
            memory = radl.getFeature('memory.size').getValue('M')
            memory_op = radl.getFeature('memory.size').getLogOperator()
        cpu = 1
        cpu_op = ">="
        if radl.getFeature('cpu.count'):
            cpu = radl.getValue('cpu.count')
            cpu_op = radl.getFeature('cpu.count').getLogOperator()

        # get the node size with the lowest vcpus and memory
        flavors.sort(key=lambda x: (x.vcpus, x.ram))
        for flavor in flavors:
            str_compare = "flavor.ram " + memory_op + " memory"
            str_compare += " and flavor.vcpus " + cpu_op + " cpu"
            if eval(str_compare):
                if not instance_type_name or flavor.name == instance_type_name:
                    return flavor

        self.log_error("No compatible flavor found")
        return None

    def concreteSystem(self, radl_system, auth_data):
        image_urls = radl_system.getValue("disk.0.image.url")
        if not image_urls:
            return [radl_system.clone()]
        else:
            if not isinstance(image_urls, list):
                image_urls = [image_urls]

            res = []
            for str_url in image_urls:
                url = uriparse(str_url)
                protocol = url[0]

                src_host = url[1].split(':')[0]
                # TODO: check the port
                if protocol == "ost" and self.cloud.server == src_host:
                    client = self.get_client(auth_data)

                    res_system = radl_system.clone()
                    instance_type = self.get_instance_type(client.flavors.list(), res_system)
                    self.update_system_info_from_instance(res_system, instance_type)

                    res_system.addFeature(
                        Feature("disk.0.image.url", "=", str_url), conflict="other", missing="other")

                    res_system.addFeature(
                        Feature("provider.type", "=", self.type), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "provider.host", "=", self.cloud.server), conflict="other", missing="other")
                    res_system.addFeature(Feature(
                        "provider.port", "=", self.cloud.port), conflict="other", missing="other")

                    username = res_system.getValue('disk.0.os.credentials.username')
                    if not username:
                        res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

                    res.append(res_system)

            return res

    def get_node_with_id(self, node_id, auth_data):
        """
        Get the node with the specified ID

        Arguments:
           - node_id(str): ID of the node to get
           - auth(Authentication): parsed authentication tokens.
        Returns: a :py:class:`novaclient.servers.Server` with the node info
        """
        client = self.get_client(auth_data)
        try:
            node = client.servers.get(node_id)
        except NotFound:
            node = None

        return node

    def updateVMInfo(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            vm.state = self.VM_STATE_MAP.get(node.status, VirtualMachine.UNKNOWN)

            flavorId = node.flavor['id']
            client = self.get_client(auth_data)
            flavor = client.flavors.get(flavorId)
            self.update_system_info_from_instance(vm.info.systems[0], flavor)

            self.setIPsFromInstance(vm, node, auth_data)
            self.attach_volumes(vm, node, auth_data)
        else:
            self.log_warn("Error updating the instance %s. VM not found." % vm.id)
            return (False, "Error updating the instance %s. VM not found." % vm.id)

        return (True, vm)

    def wait_volume(self, volume, client, state='available', timeout=60):
        """
        Wait a volume (with the state extra parameter) to be in certain state.
        Arguments:
           - volume(:py:class:`novaclient.volumes.Volume`): volume object or boolean.
           - state(str): State to wait for (default value 'available').
           - timeout(int): Max time to wait in seconds (default value 60).
        """
        if volume:
            cont = 0
            err_states = ["error"]
            while volume.status != state and volume.status not in err_states and cont < timeout:
                cont += 2
                time.sleep(2)
                volume = client.volumes.get(volume.id)
            return volume.extra['state'] == state
        else:
            return False

    def attach_volumes(self, vm, node, auth_data):
        """
        Attach a the required volumes (in the RADL) to the launched node

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`novaclient.servers.Server`): node object.
        """
        try:
            if node.status == 'ACTIVE' and "volumes" not in vm.__dict__.keys():
                vm.volumes = []
                cont = 1
                while (vm.info.systems[0].getValue("disk." + str(cont) + ".size") and
                       vm.info.systems[0].getValue("disk." + str(cont) + ".device")):
                    disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
                    disk_device = vm.info.systems[0].getValue("disk." + str(cont) + ".device")
                    self.log_debug("Creating a %d GB volume for the disk %d" % (int(disk_size), cont))
                    volume_name = "im-%d" % int(time.time() * 100.0)

                    client = self.get_client(auth_data)
                    volume = client.volumes.create(int(disk_size), display_name=volume_name)
                    success = self.wait_volume(volume, client)
                    if success:
                        # Add the volume to the VM to remove it later
                        vm.volumes.append(volume)
                        self.log_debug("Attach the volume ID " + str(volume.id))
                        client.volumes.create_server_volume(node.id, volume.id, "/dev/" + disk_device)
                    else:
                        self.log_error("Error waiting the volume ID " + str(
                            volume.id) + " not attaching to the VM and destroying it.")
                        volume.delete()

                    cont += 1
            return True
        except Exception:
            self.log_exception(
                "Error creating or attaching the volume to the node")
            return False

    def map_radl_ost_networks(self, radl_nets, ost_nets):
        """
        Generate a mapping between the RADL networks and the OST networks

        Arguments:
           - radl_nets(list of :py:class:`radl.network` objects): RADL networks.
           - ost_nets(a list of tuples (net_name, is_public)): OST networks.

         Returns: a dict with key the RADL network id and value a tuple (ost_net_name, is_public)
        """

        res = {}
        for ip, (net_name, is_public) in ost_nets.items():
            if net_name:
                for radl_net in radl_nets:
                    net_provider_id = radl_net.getValue('provider_id')
                    subnet_cidr = radl_net.getValue('cidr')
                    if net_provider_id:
                        if net_name == net_provider_id:
                            if subnet_cidr:
                                if IPAddress(ip) in IPNetwork(subnet_cidr):
                                    res[radl_net.id] = ip
                                    break
                            else:
                                res[radl_net.id] = ip
                                break
                    else:
                        if radl_net.id not in res and radl_net.isPublic() == is_public:
                            res[radl_net.id] = ip
                            if radl_net.getValue('provider_id') is None:
                                radl_net.setValue('provider_id', net_name)
                            break
            else:
                # It seems to be a floating IP
                for radl_net in radl_nets:
                    if radl_net.id not in res and radl_net.isPublic() == is_public:
                        res[radl_net.id] = ip
                        break

        return res

    def setIPsFromInstance(self, vm, node, auth_data):
        """
        Adapt the RADL information of the VM to the real IPs assigned by the cloud provider

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`novaclient.servers.Server`): object to connect to OST instance.
        """

        public_ips = []
        ip_net_map = {}
        for net_name, ips in node.addresses.items():
            for ipo in ips:
                ip = ipo['addr']
                is_private = any([IPAddress(ip) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS])
                if ipo['OS-EXT-IPS:type'] == 'floating':
                    # in this case it always has to be public
                    ip_net_map[ip] = (None, not is_private)
                else:
                    ip_net_map[ip] = (net_name, not is_private)
                if not is_private:
                    public_ips.append(ip)

        map_nets = self.map_radl_ost_networks(vm.info.networks, ip_net_map)

        system = vm.info.systems[0]
        i = 0
        while system.getValue("net_interface." + str(i) + ".connection"):
            net_name = system.getValue("net_interface." + str(i) + ".connection")
            if net_name in map_nets:
                ip = map_nets[net_name]
                system.setValue("net_interface." + str(i) + ".ip", ip)
            i += 1

        self.manage_elastic_ips(vm, node, public_ips, auth_data)

    def update_system_info_from_instance(self, system, flavor):
        """
        Update the features of the system with the information of the flavor
        """
        if flavor:
            system.addFeature(Feature("memory.size", "=", flavor.ram, 'M'), conflict="other", missing="other")
            system.addFeature(Feature("instance_type", "=", flavor.name), conflict="other", missing="other")
            system.addFeature(Feature("cpu.count", "=", flavor.vcpus), conflict="me", missing="other")

    def get_networks(self, auth_data, radl):
        """
        Get the list of networks to connect the VM
        """
        neutronc = self.get_client(auth_data, "neutron")

        nets = []

        ost_nets = []
        for subnet in neutronc.list_subnets()['subnets']:
            os_net = neutronc.show_network(subnet['network_id'])['network']
            ip = os.path.dirname(subnet['cidr'])
            is_public = not any([IPAddress(ip) in IPNetwork(mask) for mask in Config.PRIVATE_NET_MASKS])
            ost_nets.append((subnet['id'], subnet['name'], os_net['name'], subnet['cidr'], is_public))

        used_nets = []
        for radl_net in radl.networks:
            # check if this net is connected with the current VM
            num_net = radl.systems[0].getNumNetworkWithConnection(radl_net.id)
            net_provider_id = radl_net.getValue('provider_id')
            if num_net is not None:
                os_net_assigned = None

                # First check if the user has specified a provider ID
                if net_provider_id:
                    for sub_id, sub_name, net_name, sub_cidr, is_public in ost_nets:
                        if sub_name == net_provider_id:
                            os_net_assigned = (sub_id, net_name, sub_name, sub_cidr)
                            used_nets.append(sub_name)
                else:
                    # if not select the first not used net
                    for sub_id, sub_name, net_name, sub_cidr, is_public in ost_nets:
                        if sub_name not in used_nets and radl_net.isPublic() == is_public:
                            os_net_assigned = (sub_id, net_name, sub_name, sub_cidr)
                            used_nets.append(sub_name)
                            break

                if os_net_assigned:
                    sub_id, net_name, sub_name, sub_cidr = os_net_assigned
                    nets.append({'net-%s' % radl_net.id: sub_id})
                    radl_net.setValue('provider_id', net_name)
                    radl_net.setValue('subnet_id', sub_name)
                    radl_net.setValue('cidr', sub_cidr)

        return nets

    def get_cloud_init_data(self, radl):
        """
        Get the cloud init data specified by the user in the RADL
        """
        configure_name = None
        if radl.contextualize.items:
            system_name = radl.systems[0].name

            for item in radl.contextualize.items.values():
                if item.system == system_name and item.get_ctxt_tool() == "cloud_init":
                    configure_name = item.configure

        if configure_name:
            return radl.get_configure_by_name(configure_name).recipes
        else:
            return None

    def get_image_id(self, path):
        """
        Get the ID of the image to use from the location of the VMI

        Arguments:
           - path(str): URL with the location of the VMI
        Returns: a str with the ID
        """
        return uriparse(path)[2][1:]

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        client = self.get_client(auth_data)

        system = radl.systems[0]
        image_id = self.get_image_id(system.getValue("disk.0.image.url"))
        image = client.images.get(image_id)

        instance_type = self.get_instance_type(client.flavors.list(), system)
        if not instance_type:
            raise Exception("No flavor found for the specified VM requirements.")

        name = system.getValue("instance_name")
        if not name:
            name = system.getValue("disk.0.image.name")
        if not name:
            name = "userimage"

        nets = self.get_networks(auth_data, radl)

        sg = self.create_security_group(client, inf, radl)

        args = {'flavor': instance_type.id,
                'image': image.id,
                'networks': nets,
                'security_groups': [sg.id],
                'name': "%s-%s" % (name, int(time.time() * 100))}

        keypair = None
        keypair_name = None
        keypair_created = False
        public_key = system.getValue("disk.0.os.credentials.public_key")
        if public_key:
            try:
                keypair = client.keypairs.get(public_key)
            except NotFound:
                pass
            if keypair:
                system.setUserKeyCredentials(system.getCredentials().username, None, keypair.private_key)
            else:
                keypair_name = "im-%d" % int(time.time() * 100.0)
                self.log_debug("Create keypair: %s" % keypair_name)
                keypair = client.keypairs.create(keypair_name, public_key)
                keypair_created = True

        elif not system.getValue("disk.0.os.credentials.password"):
            keypair_name = "im-%d" % int(time.time() * 100.0)
            self.log_debug("Create keypair: %s" % keypair_name)
            keypair = client.keypairs.create(keypair_name)
            keypair_created = True
            public_key = keypair.public_key
            system.setUserKeyCredentials(system.getCredentials().username, None, keypair.private_key)

        if keypair_name:
            args['key_name'] = keypair_name

        user = system.getValue('disk.0.os.credentials.username')
        if not user:
            user = self.DEFAULT_USER
            system.setValue('disk.0.os.credentials.username', user)

        cloud_init = self.get_cloud_init_data(radl)
        if public_key:
            cloud_init = self.gen_cloud_config(public_key, user, cloud_init)

        if cloud_init:
            args['userdata'] = cloud_init

        if self.CONFIG_DRIVE:
            args['ex_config_drive'] = self.CONFIG_DRIVE

        res = []
        i = 0
        all_failed = True
        while i < num_vm:
            self.log_debug("Creating node")

            node = None
            msg = "Error creating the node. "
            try:
                node = client.servers.create(**args)
            except Exception, ex:
                msg += str(ex)

            if node:
                vm = VirtualMachine(inf, node.id, self.cloud, radl, requested_radl, self.cloud.getCloudConnector(inf))
                vm.info.systems[0].setValue('instance_id', str(node.id))
                vm.info.systems[0].setValue('instance_name', str(node.name))
                # Add the keypair name to remove it later
                if keypair_name:
                    vm.keypair = keypair_name
                self.log_info("Node successfully created.")
                all_failed = False
                inf.add_vm(vm)
                res.append((True, vm))
            else:
                res.append((False, msg))
            i += 1

        # if all the VMs have failed, remove the sgs and keypair
        if all_failed:
            if keypair_created:
                self.log_debug("Deleting keypair: %s." % keypair_name)
                keypair.delete()
            if sg:
                self.log_debug("Deleting security group: %s." % sg.id)
                sg.delete()

        return res

    def manage_elastic_ips(self, vm, node, public_ips, auth_data):
        """
        Manage the elastic IPs

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`novaclient.servers.Server`): node object.
        """
        n = 0
        requested_ips = []
        while vm.getRequestedSystem().getValue("net_interface." + str(n) + ".connection"):
            net_conn = vm.getRequestedSystem().getValue('net_interface.' + str(n) + '.connection')
            net = vm.info.get_network_by_id(net_conn)
            if net.isPublic():
                fixed_ip = vm.getRequestedSystem().getValue("net_interface." + str(n) + ".ip")
                pool_name = net.getValue("pool_name")
                requested_ips.append((fixed_ip, pool_name))
            n += 1

        for num, elem in enumerate(sorted(requested_ips, reverse=True)):
            ip, pool_name = elem
            if ip:
                # It is a fixed IP
                if ip not in public_ips:
                    # It has not been created yet, do it
                    self.log_debug("Asking for a fixed ip: %s." % ip)
                    self.add_elastic_ip(vm, node, ip, pool_name, auth_data)
            else:
                if num >= len(public_ips):
                    self.log_debug("Asking for public IP %d and there are %d" % (
                        num + 1, len(public_ips)))
                    self.add_elastic_ip(vm, node, None, pool_name, auth_data)

    def get_floating_ip(self, pool_name, auth_data):
        """
        Get a floating IP
        """
        self.log_debug("Asking for pool name: %s." % pool_name)

        client = self.get_client(auth_data)
        if pool_name:
            try:
                return client.floating_ips.create(pool_name)
            except NotFound:
                self.log_error("Error adding a Floating IP: No free IP in pool %s." % pool_name)
        else:
            for pool in client.floating_ip_pools.list():
                try:
                    return client.floating_ips.create(pool.name)
                except NotFound:
                    self.log_debug("Error adding a Floating IP: No free IP in pool %s." % pool_name)

        self.log_error("Error adding a Floating IP: No frees IP")
        return None

    def add_elastic_ip(self, vm, node, fixed_ip, pool_name, auth_data):
        """
        Add an elastic IP to an instance

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - node(:py:class:`novaclient.servers.Server`): node object to attach the volumes.
           - fixed_ip(str, optional): specifies a fixed IP to add to the instance.
        Returns: a :py:class:` novaclient.floating_ips.FloatingIP` added or None if some problem occur.
        """
        if vm.state == VirtualMachine.RUNNING:
            try:
                # TODO: see to set a fixed_ip
                floating_ip = self.get_floating_ip(pool_name, auth_data)
                try:
                    node.add_floating_ip(floating_ip)
                    return floating_ip
                except:
                    self.log_exception("Error attaching a Floating IP to the node.")
                    floating_ip.delete()
                    return None
            except Exception:
                self.log_exception("Error adding an Floating IP to VM ID: " + str(vm.id))
                return None
        else:
            self.log_debug("The VM is not running, not adding an Floating IP.")
            return None

    def _get_security_group(self, client, sg_name):
        try:
            sg = None
            for elem in client.security_groups.list():
                if elem.name == sg_name:
                    sg = elem
                    break
            return sg
        except Exception:
            self.log_exception("Error getting security groups.")
            return None

    def create_security_group(self, client, inf, radl):
        res = None
        # Use the InfrastructureInfo lock to assure that only one VM create the SG
        with inf._lock:
            sg_name = "im-" + str(inf.id)
            sg = self._get_security_group(client, sg_name)

            if not sg:
                self.log_debug("Creating security group: " + sg_name)
                sg = client.security_groups.create(sg_name, "Security group created by the IM")
            else:
                return sg

            res = sg

        public_net = None
        for net in radl.networks:
            if net.isPublic():
                public_net = net

        if public_net:
            outports = public_net.getOutPorts()
            if outports:
                for outport in outports:
                    if outport.is_range():
                        try:
                            client.security_group_rules.create(sg.id, outport.get_protocol(),
                                                               outport.get_port_init(),
                                                               outport.get_port_end(), '0.0.0.0/0')
                        except Exception as ex:
                            self.log_warn("Exception adding SG rules: " + str(ex))
                    else:
                        if outport.get_remote_port() != 22:
                            try:
                                client.security_group_rules.create(sg.id, outport.get_protocol(),
                                                                   outport.get_remote_port(),
                                                                   outport.get_remote_port(), '0.0.0.0/0')
                            except Exception as ex:
                                self.log_warn("Exception adding SG rules: " + str(ex))

        try:
            client.security_group_rules.create(sg.id, 'tcp', 22, 22, '0.0.0.0/0')

            # open all the ports for the VMs in the security group
            client.security_group_rules.create(sg.id, 'tcp', 1, 65535, group_id=sg.id)
            client.security_group_rules.create(sg.id, 'udp', 1, 65535, group_id=sg.id)
        except Exception, addex:
            self.logger.warn("Exception adding SG rules. Probably the rules exists:" + str(addex))

        return res

    def finalize(self, vm, last, auth_data):
        if vm.id:
            node = self.get_node_with_id(vm.id, auth_data)
        else:
            self.log_warn("No VM ID. Ignoring")
            node = None

        if node:
            client = self.get_client(auth_data)
            sgs = node.list_security_group()
            floating_ips = client.floating_ips.list()

            success = False
            try:
                node.delete()
                success = True
            except:
                self.log_exception("Error destroying VM " + str(vm.id))

            try:
                public_key = vm.getRequestedSystem().getValue('disk.0.os.credentials.public_key')
                if (vm.keypair and public_key is None or len(public_key) == 0 or
                        (len(public_key) >= 1 and public_key.find('-----BEGIN CERTIFICATE-----') != -1)):
                    # only delete in case of the user do not specify the
                    # keypair name
                    client.keypairs.get(vm.keypair).delete()
            except:
                self.log_exception("Error deleting keypairs.")

            try:
                self.delete_floating_ips(node, vm, floating_ips)
            except:
                self.log_exception("Error deleting elastic ips.")

            if not success:
                return (False, "Error destroying node: " + vm.id)

            self.log_info("VM " + str(vm.id) + " successfully destroyed")
        else:
            self.log_warn("VM " + str(vm.id) + " not found.")

        try:
            # Delete the attached volumes
            self.delete_volumes(vm, auth_data)
        except:
            self.log_exception("Error deleting volumes.")

        try:
            # Delete the SG if this is the last VM
            if last:
                self.delete_security_group(sgs, vm.inf, vm.id, client)
            else:
                # If this is not the last vm, we skip this step
                self.log_info("There are active instances. Not removing the SG")
        except:
            self.log_exception("Error deleting security groups.")

        return (True, "")

    def delete_floating_ips(self, node, vm, floating_ips):
        """
        remove the floating IPs of a VM

        Arguments:
           - node(:py:class:`novaclient.servers.Server``): node object to attach the volumes.
           - vm(:py:class:`IM.VirtualMachine`): VM information.
        """
        try:
            self.log_debug("Remove Floating IPs")
            for floating_ip in floating_ips:
                if floating_ip.instance_id == node.id:
                    # delete the ip
                    floating_ip.delete()
        except Exception:
            self.log_exception("Error removing Elastic/Floating IPs to VM ID: " + str(vm.id))

    def delete_security_group(self, sgs, inf, vm_id, client, timeout=60):
        """
        Delete the SG of this infrastructure if this is the last VM
        """
        if sgs:
            # There will be only one
            sg = sgs[0]

            some_vm = False
            for vm in inf.get_vm_list():
                if vm.id != vm_id:
                    some_vm = True

            if not some_vm:
                # wait it to terminate and then remove the SG
                cont = 0
                deleted = False
                while not deleted and cont < timeout:
                    time.sleep(5)
                    cont += 5
                    try:
                        sg.delete()
                        deleted = True
                    except Exception, ex:
                        # Check if it has been deleted yet
                        sg = self._get_security_group(client, sg.name)
                        if not sg:
                            self.logger.debug(
                                "Error deleting the SG. But it does not exist. Ignore. " + str(ex))
                            deleted = True
                        else:
                            self.logger.exception("Error deleting the SG.")
            else:
                # If there are more than 1, we skip this step
                self.logger.debug("There are active instances. Not removing the SG")
        else:
            self.logger.warn("No Security Groups to delete")

    def gen_cloud_config(self, public_key, user=None, cloud_config_str=None):
        """
        Generate the cloud-config file to be used in the user_data of the OCCI VM
        """
        if not user:
            user = self.DEFAULT_USER
        config = """#cloud-config
users:
  - name: %s
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock-passwd: true
    ssh-import-id: %s
    ssh-authorized-keys:
      - %s
""" % (user, user, public_key)
        if cloud_config_str:
            config += "\n%s\n\n" % cloud_config_str.replace("\\n", "\n")
        return config

    def delete_volumes(self, vm, auth_data, timeout=300):
        """
        Delete the volumes of a VM
        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM information.
           - timeout(int): Time needed to delete the volume.
        """
        all_ok = True
        if "volumes" in vm.__dict__.keys() and vm.volumes:
            client = self.get_client(auth_data)
            for volume in vm.volumes:
                try:
                    success = self.wait_volume(volume, client, timeout=timeout)
                    if not success:
                        self.logger.error("Error waiting the volume ID " + str(volume.id))
                    success = volume.delete()
                    if not success:
                        self.logger.error("Error destroying the volume: " + str(volume.id))
                except:
                    self.logger.exception("Error destroying the volume: " + str(volume.id) + " from the node: " + vm.id)
                    success = False

                if not success:
                    all_ok = False
        return all_ok

    def start(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            try:
                node.resume()
                return (True, "")
            except Exception, ex:
                self.log_exception("Error starting VM: " % str(ex))
                return (False, "Error starting VM: " % str(ex))
        else:
            return (False, "VM not found with id: " + vm.id)

    def stop(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            try:
                node.suspend()
                return (True, "")
            except Exception, ex:
                self.log_exception("Error stopping VM: " % str(ex))
                return (False, "Error stopping VM: " % str(ex))
        else:
            return (False, "VM not found with id: " + vm.id)

    def alterVM(self, vm, radl, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            client = self.get_client(auth_data)
            instance_type = self.get_instance_type(client.flavors.list(), radl.systems[0])

            try:
                node.resize(instance_type)
                node.confirm_resize()
            except Exception, ex:
                self.log_exception("Error resizing VM.")
                return (False, "Error resizing VM: " + str(ex))

            return (True, "")
        else:
            return (False, "VM not found with id: " + vm.id)
