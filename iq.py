# -*- coding: utf-8 -*-
# Copyright 2015 Bahtiar `kalkin-` Gadimov <bahtiar@gadimov.de>
#
# This file is part of Gajim.
#
# Gajim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; version 3 only.
#
# Gajim is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Gajim.  If not, see <http://www.gnu.org/licenses/>.
#

from nbxmpp.protocol import NS_PUBSUB, Iq
from nbxmpp.simplexml import Node

from common import gajim

NS_OMEMO = 'eu.siacs.conversations.axolotl'
NS_DEVICE_LIST = NS_OMEMO + '.devicelist'
NS_BUNDLES = NS_OMEMO + '.bundles'


class PublishNode(Node):
    def __init__(self, node_str, data):
        assert node_str is not None and data is Node
        Node.__init__(self, tag='publish', attrs={'node': node_str})
        self.addChild('item').addChild(node=data)


class PubsubNode(Node):
    def __init__(self, data):
        assert data is Node
        Node.__init__(self, tag='pubsub', attrs={'xmlns': NS_PUBSUB})
        self.addChild(node=data)


class DeviceListAnnouncement(Iq):
    def __init__(self, device_list):
        id_ = gajim.get_an_id()
        attrs = {'id': id_}
        Iq.__init__(self, typ='set', attrs=attrs)

        list_node = Node('list')
        for device in device_list:
            list_node.addChild('device').setAttr('id', device)

        publish = PublishNode(NS_DEVICE_LIST, list_node)
        pubsub = PubsubNode(publish)

        self.addChild(node=pubsub)


class BundleInformationQuery(Iq):
    def __init__(self, contact_jid, device_id):
        id_ = gajim.get_an_id()
        attrs = {'id': id_}
        Iq.__init__(self, typ='get', attrs=attrs, to=contact_jid)
        items = Node('items', attrs={'node': NS_BUNDLES + ':' + device_id})
        pubsub = PubsubNode(items)
        self.addChild(node=pubsub)
