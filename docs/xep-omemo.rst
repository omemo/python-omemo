=====================
XEP: OMEMO Encryption
=====================
Abstract::
    This specification defines a protocol for end-to-end encryption in
    one-on-one chats that may have multiple clients per account.
Copyright::
    © 1999 - 2015 XMPP Standards Foundation. `SEE LEGAL NOTICES`.
Status::
    ProtoXEP
Type::
    Standards Track
Version::
    0.0.1
Last Updated:
    2015-10-25

.. warning::
    WARNING: This document has not yet been accepted for consideration or
    approved in any official manner by the XMPP Standards Foundation, and this
    document is not yet an XMPP Extension Protocol (XEP). If this document is
    accepted as a XEP by the XMPP Council, it will be published at
    <https://xmpp.org/extensions/> and announced on the <standards@xmpp.org>
    mailing list.

1. Introduction
===============
1.1 Motivation
--------------
There are two main end-to-end encryption schemes in common use in the XMPP
ecosystem, Off-the-Record (OTR) messaging (`Current Off-the_Record Messaging
Usage (XEP-0364) <https://xmpp.org/extensions/xep-0364.html>`_) and OpenPGP
(`Current Jabber OpenPGP Usage (XEP-0027)
<https://xmpp.org/extensions/xep-0027.html>`_). OTR has significant usability
drawbacks for inter-client mobility. As OTR sessions exist between exactly two
clients, the chat history will not be synchronized across other clients of the
involved parties. Furthermore, OTR chats are only possible if both participants
are currently online, due to how the rolling key agreement scheme of OTR works.
OpenPGP, while not suffering from these mobility issues, does not provide any
kind of forward secrecy and is vulnerable to replay attacks. Additionally, PGP
over XMPP uses a custom wireformat which is defined by convention rather than
standardization, and involves quite a bit of external complexity.

This XEP defines a protocol that leverages axolotl encryption to provide
multi-end to multi-end encryption, allowing messages to be synchronized
securely across multiple clients, even if some of them are offline.

1.2 Overview
------------
The general idea behind this protocol is to maintain separate, long-standing
axolotl-encrypted sessions with each device of each contact (as well as with
each of our other devices), which are used as secure key transport channels. In
this scheme, each message is encrypted with a fresh, randomly generated
encryption key. An encrypted header is added to the message for each device that
is supposed to receive it. These headers simply contain the key that the payload
message is encrypted with, and they are seperately encrypted using the session
corresponding to the counterpart device. The encrypted payload is sent together
with the headers as a <message> stanza. Individual recipient devices can decrypt
the header item intended for them, and use the contained payload key to decrypt
the payload message.

As the encrypted payload is common to all recipients, it only has to be included
once, reducing overhead. Furthermore, axolotl's transparent handling of messages
that were lost or received out of order, as well as those sent while the
recipient was offline, is maintained by this protocol. As a result, in
combination with `Message Carbons (XEP-0280)
<https://xmpp.org/extensions/xep-0280.html>`_ and `Message Archive Management
(XEP-0313) <https://xmpp.org/extensions/xep-0313.html>`_, the desired property of
inter-client history synchronization is achieved.

OMEMO version 0 uses v3 messages of the axolotl protocol. Instead of an axolotl
key server, PEP (`Personal Eventing Protocol (XEP-0163)
<https://xmpp.org/extensions/xep-0163.html>`_) is used to publish key data. 

2. Requirements
===============
* Provide forward secrecy
* Ensure chat messages can be deciphered by all (capable) clients of both
* parties
* Be usable regardless of the participants' online statuses
* Provide a method to exchange auxilliary keying material. This
* could for example be used to secure encrypted file transfers.

3. Glossary
===========
3.1 General Terms
-----------------
Device::
    A communication end point, i.e. a specific client instance
OMEMO element::
    An `<encrypted>` element in the `urn:xmpp:omemo:0` namespace. Can be either
    MessageElement or a KeyTransportElement
MessageElement::
    An OMEMO element that contains a chat message. Its `<payload>`, when
    decrypted, corresponds to a `<message>`'s `<body>`.
KeyTransportElement::
    An OMEMO element that does not have a `<payload>`. It contains a fresh
    encryption key, which can be used for purposes external to this XEP.
Bundle::
    A collection of publicly accessible data that can be used to build a
    session with a device, namely its public IdentityKey, a signed PreKey with
    corresponding signature, and a list of (single use) PreKeys.
rid::
    The device id of the intended recipient of the containing `<key>`
sid::
    The device id of the sender of the containing OMEMO element

3.2 Axolotl-specific
--------------------
IdentityKey::
    Per-device public/private key pair used to authenticate communications
PreKey::
    A Diffie-Hellman public key, published in bulk and ahead of time
PreKeyWhisperMessage::
    An encrypted message that includes the initial key exchange. This is used
    to transparently build sessions with the first exchanged message.
WhisperMessage::
    An encrypted message


4. Use Cases
============
4.1 Setup
---------

The first thing that needs to happen if a client wants to start using OMEMO is
they need to generate an IdentityKey and a Device ID. The IdentityKey is a
Curve25519 public/private Key pair. The Device ID is a randomly generated
integer between 1 and 2^31 - 1.

4.2 Discovering peer support
----------------------------

In order to determine whether a given contact has devices that support OMEMO,
the devicelist node in PEP is consulted. Devices MUST subscribe to
`'urn:xmpp:omemo:0:devicelist` via PEP, so that they are informed whenever their
contacts add a new device. They MUST cache the most up-to-date version of the
devicelist.

.. highlight:: xml
*Example 1. Devicelist update received by subscribed clients*
::
    <message from='juliet@capulet.lit'
            to='romeo@montague.lit'
            type='headline'
            id='update_01'>
    <event xmlns='http://jabber.org/protocol/pubsub#event'>
        <items node='urn:xmpp:omemo:0:devicelist'>
        <item>
            <list xmlns='urn:xmpp:omemo:0'>
            <device id='12345' />
            <device id='4223' />
            </list>
        </item>
        </items>
    </event>
    </message>

4.3 Announcing support
----------------------

In order for other devices to be able to initiate a session with a given
device, it first has to announce itself by adding its device ID to the
devicelist PEP node.

.. highlight:: xml
*Example 2. Adding the own device ID to the list*
::
    <iq from='juliet@capulet.lit' type='set' id='announce1'>
    <pubsub xmlns='http://jabber.org/protocol/pubsub'>
        <publish node='urn:xmpp:omemo:0:devicelist'>
        <item>
            <list xmlns='urn:xmpp:omemo:0'>
            <device id='12345' />
            <device id='4223' />
            <device id='31415' />
            </list>
        </item>
        </publish>
    </pubsub>
    </iq>

This step presents the risk of introducing a race condition: Two devices might
simultaneously try to announce themselves, unaware of the other's existence.
The second device would overwrite the first one. To mitigate this, devices MUST
check that their own device ID is contained in the list whenever they receive a
PEP update from their own account. If they have been removed, they MUST
reannounce themselves.

Furthermore, a device MUST announce it's IdentityKey, a signed PreKey, and a
list of PreKeys in a separate, per-device PEP node. The list SHOULD contain 100
PreKeys, but MUST contain no less than 20.

.. highlight:: xml
*Example 3. Announcing bundle information*
::
    <iq from='juliet@capulet.lit' type='set' id='announce2'>
    <pubsub xmlns='http://jabber.org/protocol/pubsub'>
        <publish node='urn:xmpp:omemo:0:bundles:31415'>
        <item>
            <bundle xmlns='urn:xmpp:omemo:0'>
            <signedPreKeyPublic signedPreKeyId='1'>
                BASE64ENCODED...
            </signedPreKeyPublic>
            <signedPreKeySignature>
                BASE64ENCODED...
            </signedPreKeySignature>
            <identityKey>
                BASE64ENCODED...
            </identityKey>
            <prekeys>
                <preKeyPublic preKeyId='1'>
                BASE64ENCODED...
                </preKeyPublic>
                <preKeyPublic preKeyId='2'>
                BASE64ENCODED...
                </preKeyPublic>
                <preKeyPublic preKeyId='3'>
                BASE64ENCODED...
                </preKeyPublic>
                <!-- ... -->
            </prekeys>
            </bundle>
        </item>
        </publish>
    </pubsub>
    </iq>

4.4 Building a session
----------------------

In order to build a session with a device, their bundle information is fetched.

.. highlight:: xml
*Example 4. Fetching a device's bundle information*
::
    <iq type='get'
        from='romeo@montague.lit'
        to='juliet@capulet.lit'
        id='fetch1'>
    <pubsub xmlns='http://jabber.org/protocol/pubsub'>
        <items node='urn:xmpp:omemo:0:bundles:31415'/>
    </pubsub>
    </iq>

A random preKeyPublic entry is selected, and used to build an axolotl session.

4.5 Sending a message
---------------------

In order to send a chat message, its `<body>` first has to be encrypted. The
client MUST use fresh, randomly generated key/IV pairs with AES-128 in
Galois/Counter Mode (GCM). For each intended recipient device, i.e. both own
devices as well as devices associated with the contact, this key is encrypted
using the corresponding long-standing axolotl session. Each encrypted payload
key is tagged with the recipient device's ID. This is all serialized into a
MessageElement, which is transmitted in a `<message>` as follows:

.. highlight:: xml
*Example 5. Sending a message*
::
    <message to='juliet@capulet.lit' from='romeo@montague.lit' id='send1'>
    <encrypted xmlns='urn:xmpp:omemo:0'>
        <header sid='27183'>
        <key rid='31415'>BASE64ENCODED...</key>
        <key rid='12321'>BASE64ENCODED...</key>
        <!-- ... -->
        <iv>BASE64ENCODED...</iv>
        </header>
        <payload>BASE64ENCODED</payload>
    </encrypted>
    <store xmlns='urn:xmpp:hints'/>
    </message>

4.6 Sending a key
-----------------

The client may wish to transmit keying material to the contact. This first has
to be generated. The client MUST generate a fresh, randomly generated key/IV
pair. For each intended recipient device, i.e. both own devices as well as
devices associated with the contact, this key is encrypted using the
corresponding long-standing axolotl session. Each encrypted payload key is
tagged with the recipient device's ID. This is all serialized into a
KeyTransportElement, omitting the `<payload>` as follows:

.. highlight:: xml
*Example 6. Sending a key*
::
    <encrypted xmlns='urn:xmpp:omemo:0'>
    <header sid='27183'>
        <key rid='31415'>BASE64ENCODED...</key>
        <key rid='12321'>BASE64ENCODED...</key>
        <!-- ... -->
        <iv>BASE64ENCODED...</iv>
    </header>
    </encrypted>

This KeyTransportElement can then be sent over any applicable transport mechanism.

4.7 Receiving a message
-----------------------

When an OMEMO element is received, the client MUST check whether there is a
`<key>` element with an rid attribute matching its own device ID. If this is
not the case, the element MUST be silently discarded. If such an element
exists, the client checks whether the element's contents are a
PreKeyWhisperMessage.

If this is the case, a new session is built from this received element. The
client SHOULD then republish their bundle information, replacing the used
PreKey, such that it won't be used again by a different client. If the client
already has a session with the sender's device, it MUST replace this session
with the newly built session. The client MUST delete the private key belonging
to the PreKey after use.

If the element's contents are a WhisperMessage, and the client has a session
with the sender's device, it tries to decrypt the WhisperMessage using this
session. If the decryption fails or if the element's contents are not a
WhisperMessage either, the OMEMO element MUST be silently discarded.

If the OMEMO element contains a `<payload>`, it is an OMEMO message element. The
client tries to decrypt the base 64 encoded contents using the key extracted
from the `<key>` element. If the decryption fails, the client MUST silently
discard the OMEMO message. If it succeeds, the decrypted contents are treated
as the `<body>` of the received message.

If the OMEMO element does not contain a `<payload>`, the client has received a
KeyTransportElement. The key extracted from the `<key>` element can then be used
for other purposes (e.g. encrypted file transfer).

5. Business Rules
=================

Before publishing a freshly generated Device ID for the first time, a device
MUST check whether that Device ID already exists, and if so, generate a new
one.

Clients SHOULD NOT immediately fetch the bundle and build a session as soon as
a new device is announced. Before the first message is exchanged, the contact
does not know which PreKey has been used (or, in fact, that any PreKey was used
at all). As they have not had a chance to remove the used PreKey from their
bundle announcement, this could lead to collisions where both Alice and Bob
pick the same PreKey to build a session with a specific device. As each PreKey
SHOULD only be used once, the party that sends their initial
PreKeyWhisperMessage later loses this race condition. This means that they
think they have a valid session with the contact, when in reality their
messages MAY be ignored by the other end. By postponing building sessions, the
chance of such issues occurring can be drastically reduced. It is RECOMMENDED
to construct sessions only immediately before sending a message.

As there are no explicit error messages in this protocol, if a client does
receive a PreKeyWhisperMessage using an invalid PreKey, they SHOULD respond
with a KeyTransportElement, sent in a `<message>` using a PreKeyWhisperMessage.
By building a new session with the original sender this way, the invalid
session of the original sender will get overwritten with this newly created,
valid session.

If a PreKeyWhisperMessage is received as part of a `Message Archive Management
(XEP-0313) <https://xmpp.org/extensions/xep-0313.html>`_ catch-up and used to establish a new session with the sender,
the client SHOULD postpone deletion of the private key corresponding to the
used PreKey until after MAM catch-up is completed. If this is done, the client
MUST then also send a KeyTransportMessage using a PreKeyWhisperMessage before
sending any payloads using this session, to trigger re-keying. (as above) This
practice can mitigate the previously mentioned race condition by preventing
message loss.

As the asynchronous nature of OMEMO allows decryption at a later time to
currently offline devices client SHOULD include a `Message Processing Hints
(XEP-0334) <https://xmpp.org/extensions/xep-0334.html>`_ `<store />` hint in
their OMEMO messages. Otherwise, server implementations of `Message Archive
Management (XEP-0313) <https://xmpp.org/extensions/xep-0313.html>`_ will
generally not retain OMEMO messages, since they do not contain a `<body />`

6. Implementation Notes
=======================

For details on axoltol, see the specification and reference implementation.

The axolotl library's reference implementation (and presumably its ports to
various other platforms) uses a trust model that doesn't work very well with
OMEMO. For this reason it may be desirable to have the library consider all
keys trusted, effectively disabling its trust management. This makes it
necessary to implement trust handling oneself.

7. Security Considerations
==========================

Clients MUST NOT use a newly built session to transmit data without user
intervention. If a client were to opportunistically start using sessions for
sending without asking the user whether to trust a device first, an attacker
could publish a fake device for this user, which would then receive copies of
all messages sent by/to this user. A client MAY use such "not (yet) trusted"
sessions for decryption of received messages, but in that case it SHOULD
indicate the untrusted nature of such messages to the user.

When prompting the user for a trust decision regarding a key, the client SHOULD
present the user with a fingerprint in the form of a hex string, QR code, or
other unique representation, such that it can be compared by the user.

While it is RECOMMENDED that clients postpone private key deletion until after
MAM catch-up and this standards mandates that clients MUST NOT use
duplicate-PreKey sessions for sending, clients MAY delete such keys immediately
for security reasons. For additional information on potential security impacts
of this decision, refer to Menezes, Alfred, and Berkant Ustaoglu. "On reusing
ephemeral keys in Diffie-Hellman key agreement protocols." International
Journal of Applied Cryptography 2, no. 2 (2010): 154-158..

In order to be able to handle out-of-order messages, the axolotl stack has to cache the keys belonging to "skipped" messages that have not been seen yet. It is up to the implementor to decide how long and how many of such keys to keep around.
8. IANA Considerations

This document requires no interaction with the Internet Assigned Numbers Authority (IANA).

9. XMPP Registrar Considerations
================================

9.1 Protocol Namespaces
-----------------------

This specification defines the following XMPP namespaces:

    `urn:xmpp:omemo:0`

The `XMPP Registrar <https://xmpp.org/registrar/>`_ shall include the foregoing
namespace in its registry at <https://xmpp.org/registrar/namespaces.html>, as
goverened by `XMPP Registrar Function (XEP-0053)
<https://xmpp.org/extensions/xep-0053.html>`_. 

9.2 Protocol Versioning
-----------------------

If the protocol defined in this specification undergoes a revision that is not
fully backwards-compatible with an older version, the XMPP Registrar shall
increment the protocol version number found at the end of the XML namespaces
defined herein, as described in Section 4 of **XEP-0053**.

10. XML Schema
==============
.. highlight:: xml
*Xml Schema*
::
    <xml version="1.0" encoding="utf8">
    <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
        targetNamespace="urn:xmpp:omemo:0"
        xmlns="urn:xmpp:omemo:0">

    <xs:element name="encrypted">
        <xs:element name="header">
        <xs:attribute name="sid" type="xs:integer"/>
        <xs:complexType>
            <xs:sequence>
            <xs:element name="key" type="xs:base64Binary" maxOccurs="unbounded">
                <xs:attribute name="rid" type="xs:integer"/>
            </xs:element>
            <xs:element name="iv" type="xs:base64Binary"/>
        </xs:complexType>
        </xs:element>
        <xs:element name="payload" type="xs:base64Binary" minOccurs="0"/>
    </xs:element>

    <xs:element name="list">
        <xs:complexType>
        <xs:sequence>
            <xs:element name="device" maxOccurs="unbounded">
            <xs:attribute name="id" type="integer"/>
            </xs:element>
        </xs:sequence>
        </xs:complexType>
    </xs:element>

    <xs:element name="bundle">
        <xs:complexType>
        <xs:sequence>
            <xs:element name="signedPreKeyPublic" type="base64Binary">
            <xs:attribute name="id" type="integer"/>
            </xs:element>
            <xs:element name="signedPreKeySignature" type="base64Binary"/>
            <xs:element name="identityKey" type="base64Binary"/>
            <xs:element name="prekeys">
            <xs:complexType>
                <xs:sequence>
                <xs:element name="preKeyPublic" type="base64Binary" maxOccurs="unbounded">
                    <xs:attribute name="id" type="integer"/>
                </xs:element>
                </xs:sequence>
            </xs:complexType>
            </xs:element>
        </xs:sequence>
        </xs:complexType>
    </xs:element>

    </xs:schema>
  

11. Acknowledgements
====================

Big thanks to Daniel Gultsch for mentoring me during the development of this
protocol. Thanks to Thijs Alkemade and Cornelius Aschermann for talking through
some of the finer points of the protocol with me. And lastly I would also like
to thank Sam Whited, Holger Weiss, and Florian Schmaus for their input on the
standard.

Appendices
===========
Appendix A: Document Information
--------------------------------

Series:: 
    XEP
Number:: 
    xxxx
Publisher:: 
    XMPP Standards Foundation
Status::
 ProtoXEP
Type::
 Standards Track
Version::
 0.0.1
Last Updated::
 2015-10-25
Approving Body::
 XMPP Council
Dependencies::
 XMPP Core, XEP-0163
Supersedes::
 None
Superseded By::
 None
Short Name::
 NOT_YET_ASSIGNED
This document in other formats::
 XML  PDF
Appendix B: Author Information
------------------------------
Andreas Straub
~~~~~~~~~~~~~~

Email:: 
    andy@strb.org
JabberID:: 
    andy@strb.org

Appendix C: Legal Notices
-------------------------
Copyright
~~~~~~~~~
This XMPP Extension Protocol is copyright (c) 1999 - 2014 by the XMPP Standards
Foundation (XSF).

Permissions
~~~~~~~~~~~
Permission is hereby granted, free of charge, to any person obtaining a copy of
this specification (the "Specification"), to make use of the Specification
without restriction, including without limitation the rights to implement the
Specification in a software program, deploy the Specification in a network
service, and copy, modify, merge, publish, translate, distribute, sublicense,
or sell copies of the Specification, and to permit persons to whom the
Specification is furnished to do so, subject to the condition that the
foregoing copyright notice and this permission notice shall be included in all
copies or substantial portions of the Specification. Unless separate permission
is granted, modified works that are redistributed shall not contain misleading
information regarding the authors, title, number, or publisher of the
Specification, and shall not claim endorsement of the modified works by the
authors, any organization or project to which the authors belong, or the XMPP
Standards Foundation.

Disclaimer of Warranty
~~~~~~~~~~~~~~~~~~~~~~

.. note::
    This Specification is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE. In no event shall the XMPP Standards Foundation or the authors of this Specification be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the Specification or the implementation, deployment, or other use of the Specification.

Limitation of Liability
~~~~~~~~~~~~~~~~~~~~~~~
In no event and under no legal theory, whether in tort (including negligence),
contract, or otherwise, unless required by applicable law (such as deliberate
and grossly negligent acts) or agreed to in writing, shall the XMPP Standards
Foundation or any author of this Specification be liable for damages, including
any direct, indirect, special, incidental, or consequential damages of any
character arising out of the use or inability to use the Specification
(including but not limited to damages for loss of goodwill, work stoppage,
computer failure or malfunction, or any and all other commercial damages or
losses), even if the XMPP Standards Foundation or such author has been advised
of the possibility of such damages.

IPR Conformance
~~~~~~~~~~~~~~~
This XMPP Extension Protocol has been contributed in full conformance with the
XSF's Intellectual Property Rights Policy (a copy of which may be found at
<https://xmpp.org/extensions/ipr-policy.shtml> or obtained by writing to XSF,
P.O. Box 1641, Denver, CO 80201 USA).

Appendix D: Relation to XMPP
----------------------------

The Extensible Messaging and Presence Protocol (XMPP) is defined in the XMPP
Core (RFC 6120) and XMPP IM (RFC 6121) specifications contributed by the XMPP
Standards Foundation to the Internet Standards Process, which is managed by the
Internet Engineering Task Force in accordance with RFC 2026. Any protocol
defined in this document has been developed outside the Internet Standards
Process and is to be understood as an extension to XMPP rather than as an
evolution, development, or modification of XMPP itself.

Appendix E: Discussion Venue
----------------------------

The primary venue for discussion of XMPP Extension Protocols is the
<standards@xmpp.org> discussion list.

Discussion on other xmpp.org discussion lists might also be appropriate; see
<https://xmpp.org/about/discuss.shtml> for a complete list.

Errata can be sent to <editor@xmpp.org>.

Appendix F: Requirements Conformance
------------------------------------

The following requirements keywords as used in this document are to be
interpreted as described in RFC 2119: "MUST", "SHALL", "REQUIRED"; "MUST NOT",
"SHALL NOT"; "SHOULD", "RECOMMENDED"; "SHOULD NOT", "NOT RECOMMENDED"; "MAY",
"OPTIONAL".

Appendix G: Notes
-----------------

1. XEP-0364: Current Off-the-Record Messaging Usage <https://xmpp.org/extensions/xep-0364.html>.

2. XEP-0027: Current Jabber OpenPGP Usage <https://xmpp.org/extensions/xep-0027.html>.

3. XEP-0280: Message Carbons <https://xmpp.org/extensions/xep-0280.html>.

4. XEP-0313: Message Archive Management <https://xmpp.org/extensions/xep-0313.html>.

5. XEP-0163: Personal Eventing Protocol <https://xmpp.org/extensions/xep-0163.html>.

6. XEP-0313: Message Archive Management <https://xmpp.org/extensions/xep-0313.html>.

7. XEP-0334: Message Processing Hints <https://xmpp.org/extensions/xep-0334.html>.

8. XEP-0313: Message Archive Management <https://xmpp.org/extensions/xep-0313.html>.

9. Menezes, Alfred, and Berkant Ustaoglu. "On reusing ephemeral keys in Diffie-Hellman key agreement protocols." International Journal of Applied Cryptography 2, no. 2 (2010): 154-158.

10. The XMPP Registrar maintains a list of reserved protocol namespaces as well as registries of parameters used in the context of XMPP extension protocols approved by the XMPP Standards Foundation. For further information, see <https://xmpp.org/registrar/>.

11. XEP-0053: XMPP Registrar Function <https://xmpp.org/extensions/xep-0053.html>.
Appendix H: Revision History

Note: Older versions of this specification might be available at https://xmpp.org/extensions/attic/
Version 0.0.1 (2015-10-25)

First draft.
(as) 
