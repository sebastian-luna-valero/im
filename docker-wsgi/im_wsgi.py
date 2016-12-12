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

import bottle
import logging
import logging.config
from IM.REST import (RESTAddResource, RESTAlterVM, RESTCreateInfrastructure, RESTGetInfrastructureInfo,
                     RESTGetInfrastructureList, RESTGetVMInfo, RESTGetInfrastructureProperty,
                     RESTGeVersion, RESTReconfigureInfrastructure, RESTRemoveResource, RESTStartInfrastructure,
                     RESTStartVM, RESTStopVM, RESTDestroyInfrastructure, RESTGetVMProperty)

logging.config.fileConfig('/etc/im/logging.conf')
logger = logging.getLogger('InfrastructureManager')

@bottle.route('/infrastructures/:id', method='DELETE')
def WSGIDestroyInfrastructure(id=None):
    return RESTDestroyInfrastructure(id)


@bottle.route('/infrastructures/:id', method='GET')
def WSGIGetInfrastructureInfo(id=None):
    return RESTGetInfrastructureInfo(id)


@bottle.route('/infrastructures/:id/:prop', method='GET')
def WSGIGetInfrastructureProperty(id=None, prop=None):
    return RESTGetInfrastructureProperty(id, prop)


@bottle.route('/infrastructures', method='GET')
def WSGIGetInfrastructureList():
    return RESTGetInfrastructureList()


@bottle.route('/infrastructures', method='POST')
def WSGICreateInfrastructure():
    return RESTCreateInfrastructure()


@bottle.route('/infrastructures/:infid/vms/:vmid', method='GET')
def WSGIGetVMInfo(infid=None, vmid=None):
    return RESTGetVMInfo(infid, vmid)


@bottle.route('/infrastructures/:infid/vms/:vmid/:prop', method='GET')
def WSGIGetVMProperty(infid=None, vmid=None, prop=None):
    return RESTGetVMProperty(infid, vmid, prop)


@bottle.route('/infrastructures/:id', method='POST')
def WSGIAddResource(id=None):
    return RESTAddResource(id)


@bottle.route('/infrastructures/:infid/vms/:vmid', method='DELETE')
def WSGIRemoveResource(infid=None, vmid=None):
    return RESTRemoveResource(infid, vmid)


@bottle.route('/infrastructures/:infid/vms/:vmid', method='PUT')
def WSGIAlterVM(infid=None, vmid=None):
    return RESTAlterVM(infid, vmid)


@bottle.route('/infrastructures/:id/reconfigure', method='PUT')
def WSGIReconfigureInfrastructure(id=None):
    return RESTReconfigureInfrastructure(id)


@bottle.route('/infrastructures/:id/start', method='PUT')
def WSGIStartInfrastructure(id=None):
    return RESTStartInfrastructure(id)


@bottle.route('/infrastructures/:id/stop', method='PUT')
def WSGIStopInfrastructure(id=None):
    return RESTStopInfrastructure(id)


@bottle.route('/infrastructures/:infid/vms/:vmid/start', method='PUT')
def WSGIStartVM(infid=None, vmid=None, prop=None):
    return RESTStartVM()


@bottle.route('/infrastructures/:infid/vms/:vmid/stop', method='PUT')
def WSGIStopVM(infid=None, vmid=None, prop=None):
    return RESTStopVM(infid, vmid, prop)


@bottle.route('/version', method='GET')
def RESTGeVersion():
    try:
        from IM import __version__ as version
        return format_output(version, field_name="version")
    except Exception, ex:
        return return_error(400, "Error getting IM version: " + str(ex))


@bottle.error(403)
def error_mesage_403(error):
    return return_error(403, error.body)


@bottle.error(404)
def error_mesage_404(error):
    return return_error(404, error.body)


@bottle.error(405)
def error_mesage_405(error):
    return return_error(405, error.body)


@bottle.error(500)
def error_mesage_500(error):
    return return_error(500, error.body)

application = bottle.default_app()