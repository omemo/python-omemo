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

import logging
import random
from base64 import b64decode, b64encode

from nbxmpp.protocol import NS_PUBSUB, Iq
from nbxmpp.simplexml import Node

from common import gajim
from plugins.helpers import log_calls

NS_OMEMO = 'eu.siacs.conversations.axolotl'
NS_DEVICE_LIST = NS_OMEMO + '.devicelist'
NS_NOTIFY = NS_DEVICE_LIST + '+notify'
NS_BUNDLES = NS_OMEMO + '.bundles:'
log = logging.getLogger('gajim.plugin_system.omemo')


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


class OmemoMessage(Node):
    def __init__(self, msg_dict):
        # , contact_jid, key, iv, payload, dev_id, my_dev_id):
        log.debug('Creating_msg' + str(msg_dict))
        Node.__init__(self, 'encrypted', attrs={'xmlns': NS_OMEMO})
        header = Node('header', attrs={'sid': msg_dict['sid']})
        for rid, key in msg_dict['keys'].items():
            header.addChild('key', attrs={'rid': rid}).addData(b64encode(key))

        header.addChild('iv').addData(b64encode(msg_dict['iv']))
        self.addChild(node=header)
        self.addChild('payload').addData(b64encode(msg_dict['payload']))


class BundleInformationQuery(Iq):
    def __init__(self, contact_jid, device_id):
        id_ = gajim.get_an_id()
        attrs = {'id': id_}
        Iq.__init__(self, typ='get', attrs=attrs, to=contact_jid)
        items = Node('items', attrs={'node': NS_BUNDLES + str(device_id)})
        pubsub = PubsubNode(items)
        self.addChild(node=pubsub)


class BundleInformationAnnouncement(Iq):
    def __init__(self, state_bundle, device_id):
        id_ = gajim.get_an_id()
        attrs = {'id': id_}
        Iq.__init__(self, typ='set', attrs=attrs)
        bundle_node = self.make_bundle_node(state_bundle)
        publish = PublishNode(NS_BUNDLES + str(device_id), bundle_node)
        pubsub = PubsubNode(publish)
        self.addChild(node=pubsub)

    def make_bundle_node(self, state_bundle):
        result = Node('bundle', attrs={'xmlns': NS_OMEMO})
        prekey_pub_node = result.addChild(
            'signedPreKeyPublic',
            attrs={'signedPreKeyId': state_bundle['signedPreKeyId']})
        prekey_pub_node.addData(state_bundle['signedPreKeyPublic'])

        prekey_sig_node = result.addChild('signedPreKeySignature')
        prekey_sig_node.addData(state_bundle['signedPreKeySignature'])

        identity_key_node = result.addChild('identityKey')
        identity_key_node.addData(state_bundle['identityKey'])
        prekeys = result.addChild('prekeys')

        for key in state_bundle['prekeys']:
            prekeys.addChild('preKeyPublic',
                             attrs={'preKeyId': key[0]}).addData(key[1])
        return result


@log_calls('OmemoPlugin')
def unpack_message(msg):
    encrypted_node = msg.getTag('encrypted', namespace=NS_OMEMO)
    if not encrypted_node:
        log.debug('Message does not have encrypted node')

    return unpack_encrypted(encrypted_node)


@log_calls('OmemoPlugin')
def unpack_device_bundle(bundle, device_id):
    pubsub = bundle.getTag('pubsub', namespace=NS_PUBSUB)
    if not pubsub:
        log.warn('OMEMO device bundle has no pubsub node')
        return
    items = pubsub.getTag('items', attrs={'node': NS_BUNDLES + str(device_id)})
    if not items:
        log.warn('OMEMO device bundle has no items node')
        return

    item = items.getTag('item')
    if not item:
        log.warn('OMEMO device bundle has no item node')
        return

    bundle = item.getTag('bundle', namespace=NS_OMEMO)
    if not bundle:
        log.warn('OMEMO device bundle has no bundle node')
        return

    signed_prekey_node = bundle.getTag('signedPreKeyPublic')
    if not signed_prekey_node:
        log.warn('OMEMO device bundle has no signedPreKeyPublic node')
        return

    result = {}
    result['signedPreKeyPublic'] = decode_data(signed_prekey_node)
    if not result['signedPreKeyPublic']:
        log.warn('OMEMO device bundle has no signedPreKeyPublic data')
        return

    if not signed_prekey_node.getAttr('signedPreKeyId'):
        log.warn('OMEMO device bundle has no signedPreKeyId')
        return
    result['signedPreKeyId'] = int(signed_prekey_node.getAttr(
        'signedPreKeyId'))

    signed_signature_node = bundle.getTag('signedPreKeySignature')
    if not signed_signature_node:
        log.warn('OMEMO device bundle has no signedPreKeySignature node')
        return

    result['signedPreKeySignature'] = decode_data(signed_signature_node)
    if not result['signedPreKeySignature']:
        log.warn('OMEMO device bundle has no signedPreKeySignature data')
        return

    identity_key_node = bundle.getTag('identityKey')
    if not identity_key_node:
        log.warn('OMEMO device bundle has no identityKey node')
        return

    result['identityKey'] = decode_data(identity_key_node)
    if not result['identityKey']:
        log.warn('OMEMO device bundle has no identityKey data')
        return

    prekeys = bundle.getTag('prekeys')
    if not prekeys or len(prekeys.getChildren()) == 0:
        log.warn('OMEMO device bundle has no prekys')
        return

    picked_key_node = random.SystemRandom().choice(prekeys.getChildren())

    if not picked_key_node.getAttr('preKeyId'):
        log.warn('OMEMO PreKey has no id set')
        return
    result['preKeyId'] = int(picked_key_node.getAttr('preKeyId'))

    result['preKeyPublic'] = decode_data(picked_key_node)
    if not result['preKeyPublic']:
        return
    return result


@log_calls('OmemoPlugin')
def unpack_encrypted(encrypted_node):
    """ Unpacks the encrypted node, decodes the data and returns a msg_dict.
    """
    if not encrypted_node.getNamespace() == NS_OMEMO:
        log.warn("Encrypted node with wrong NS")
        return

    header_node = encrypted_node.getTag('header')
    if not header_node:
        log.warn("OMEMO message without header")
        return

    if not header_node.getAttr('sid'):
        log.warn("OMEMO message without sid in header")
        return

    sid = int(header_node.getAttr('sid'))

    iv_node = header_node.getTag('iv')
    if not iv_node:
        log.warn("OMEMO message without iv")
        return

    iv = decode_data(iv_node)
    if not iv:
        log.warn("OMEMO message without iv data")

    payload_node = encrypted_node.getTag('payload')
    payload = None
    if payload_node:
        payload = decode_data(payload_node)

    key_nodes = header_node.getTags('key')
    if len(key_nodes) < 1:
        log.warn("OMEMO message without keys")
        return

    keys = {}
    for kn in key_nodes:
        rid = kn.getAttr('rid')
        if not rid:
            log.warn('Omemo key without rid')
            continue

        if not kn.getData():
            log.warn('Omemo key without data')
            continue

        keys[int(rid)] = decode_data(kn)

    result = {'sid': sid, 'iv': iv, 'keys': keys, 'payload': payload}
    log.debug('Parsed OMEMO message')
    log.debug(result)
    return result


def unpack_device_list_update(event):
    """ Unpacks the device list update received in a MessageReceivedEvent.

        Parameters
        ----------
        event : MessageReceivedEvent
                The event received from gajim
        Returns
        -------
        [int]
            List of device ids or empty list if nothing found
    """
    event_node = event.stanza.getTag('event')
    account = event.conn.name
    result = []

    if not event_node:
        log.warn(account + ' → Device list update event node empty!')
        return result

    items = event_node.getTag('items', {'node': NS_DEVICE_LIST})
    if not items or len(items.getChildren()) != 1:
        log.debug(
            account +
            ' → Device list update items node empty or not omemo device update')
        return result

    list_node = items.getChildren()[0].getTag('list')
    if not items or len(items.getChildren()) == 0:
        log.warn(account + ' → Device list update list node empty!')
        return result

    devices_nodes = list_node.getChildren()

    for dn in devices_nodes:
        _id = dn.getAttr('id')
        if _id:
            result.append(int(_id))

    return result


def decode_data(node):
    """ Fetch the data from specified node and b64decode it. """
    data = node.getData()
    log.debug(data)
    if not data:
        log.warn("No node data")
        return
    try:
        return b64decode(data)
    except:
        log.warn('b64decode broken')
        return


def successful(stanza):
    """ Check if stanza type is result.  """
    return stanza.getAttr('type') == 'result'
