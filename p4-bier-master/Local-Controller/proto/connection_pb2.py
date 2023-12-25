# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: connection.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='connection.proto',
  package='controller_connection',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\x10\x63onnection.proto\x12\x15\x63ontroller_connection\"\x07\n\x05\x45mpty\"(\n\x0cHelloMessage\x12\n\n\x02ip\x18\x01 \x01(\t\x12\x0c\n\x04port\x18\x02 \x01(\r\"C\n\nSwitchInfo\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\n\n\x02ip\x18\x02 \x01(\t\x12\x0b\n\x03mac\x18\x03 \x01(\t\x12\x0e\n\x06\x62\x66r_id\x18\x04 \x01(\r\"\'\n\x06Status\x12\x0c\n\x04\x63ode\x18\x01 \x01(\r\x12\x0f\n\x07message\x18\x02 \x01(\t\"5\n\nTableEntry\x12\x12\n\ntable_name\x18\x01 \x01(\t\x12\x13\n\x0btable_entry\x18\x02 \x01(\t\"O\n\x0bGroupPacket\x12\x0c\n\x04type\x18\x01 \x01(\r\x12\x12\n\nmc_address\x18\x02 \x01(\t\x12\x0e\n\x06src_ip\x18\x03 \x01(\t\x12\x0e\n\x06switch\x18\x04 \x01(\t\"U\n\x0eTopologyPacket\x12\n\n\x02ip\x18\x01 \x01(\t\x12\x0b\n\x03mac\x18\x02 \x01(\t\x12\x0c\n\x04port\x18\x03 \x01(\r\x12\x0c\n\x04name\x18\x04 \x01(\t\x12\x0e\n\x06switch\x18\x05 \x01(\t\"8\n\x08PortInfo\x12\x0e\n\x06switch\x18\x01 \x01(\t\x12\x0c\n\x04port\x18\x02 \x01(\r\x12\x0e\n\x06status\x18\x03 \x01(\x08\x32\xfd\x01\n\x0bLocalServer\x12L\n\x08\x41\x64\x64\x45ntry\x12!.controller_connection.TableEntry\x1a\x1d.controller_connection.Status\x12O\n\x0bRemoveEntry\x12!.controller_connection.TableEntry\x1a\x1d.controller_connection.Status\x12O\n\x05Hello\x12#.controller_connection.HelloMessage\x1a!.controller_connection.SwitchInfo2\xd9\x02\n\x0cGlobalServer\x12Q\n\x0cGroupMessage\x12\".controller_connection.GroupPacket\x1a\x1d.controller_connection.Status\x12W\n\x0fTopologyMessage\x12%.controller_connection.TopologyPacket\x1a\x1d.controller_connection.Status\x12M\n\x0bPortMessage\x12\x1f.controller_connection.PortInfo\x1a\x1d.controller_connection.Status\x12N\n\x0f\x43heckConnection\x12\x1c.controller_connection.Empty\x1a\x1d.controller_connection.Statusb\x06proto3')
)




_EMPTY = _descriptor.Descriptor(
  name='Empty',
  full_name='controller_connection.Empty',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=43,
  serialized_end=50,
)


_HELLOMESSAGE = _descriptor.Descriptor(
  name='HelloMessage',
  full_name='controller_connection.HelloMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ip', full_name='controller_connection.HelloMessage.ip', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='controller_connection.HelloMessage.port', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=52,
  serialized_end=92,
)


_SWITCHINFO = _descriptor.Descriptor(
  name='SwitchInfo',
  full_name='controller_connection.SwitchInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='controller_connection.SwitchInfo.name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ip', full_name='controller_connection.SwitchInfo.ip', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='mac', full_name='controller_connection.SwitchInfo.mac', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='bfr_id', full_name='controller_connection.SwitchInfo.bfr_id', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=94,
  serialized_end=161,
)


_STATUS = _descriptor.Descriptor(
  name='Status',
  full_name='controller_connection.Status',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='code', full_name='controller_connection.Status.code', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='message', full_name='controller_connection.Status.message', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=163,
  serialized_end=202,
)


_TABLEENTRY = _descriptor.Descriptor(
  name='TableEntry',
  full_name='controller_connection.TableEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='table_name', full_name='controller_connection.TableEntry.table_name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='table_entry', full_name='controller_connection.TableEntry.table_entry', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=204,
  serialized_end=257,
)


_GROUPPACKET = _descriptor.Descriptor(
  name='GroupPacket',
  full_name='controller_connection.GroupPacket',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='controller_connection.GroupPacket.type', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='mc_address', full_name='controller_connection.GroupPacket.mc_address', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='src_ip', full_name='controller_connection.GroupPacket.src_ip', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='switch', full_name='controller_connection.GroupPacket.switch', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=259,
  serialized_end=338,
)


_TOPOLOGYPACKET = _descriptor.Descriptor(
  name='TopologyPacket',
  full_name='controller_connection.TopologyPacket',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ip', full_name='controller_connection.TopologyPacket.ip', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='mac', full_name='controller_connection.TopologyPacket.mac', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='controller_connection.TopologyPacket.port', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='name', full_name='controller_connection.TopologyPacket.name', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='switch', full_name='controller_connection.TopologyPacket.switch', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=340,
  serialized_end=425,
)


_PORTINFO = _descriptor.Descriptor(
  name='PortInfo',
  full_name='controller_connection.PortInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='switch', full_name='controller_connection.PortInfo.switch', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='controller_connection.PortInfo.port', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='status', full_name='controller_connection.PortInfo.status', index=2,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=427,
  serialized_end=483,
)

DESCRIPTOR.message_types_by_name['Empty'] = _EMPTY
DESCRIPTOR.message_types_by_name['HelloMessage'] = _HELLOMESSAGE
DESCRIPTOR.message_types_by_name['SwitchInfo'] = _SWITCHINFO
DESCRIPTOR.message_types_by_name['Status'] = _STATUS
DESCRIPTOR.message_types_by_name['TableEntry'] = _TABLEENTRY
DESCRIPTOR.message_types_by_name['GroupPacket'] = _GROUPPACKET
DESCRIPTOR.message_types_by_name['TopologyPacket'] = _TOPOLOGYPACKET
DESCRIPTOR.message_types_by_name['PortInfo'] = _PORTINFO
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Empty = _reflection.GeneratedProtocolMessageType('Empty', (_message.Message,), dict(
  DESCRIPTOR = _EMPTY,
  __module__ = 'connection_pb2'
  # @@protoc_insertion_point(class_scope:controller_connection.Empty)
  ))
_sym_db.RegisterMessage(Empty)

HelloMessage = _reflection.GeneratedProtocolMessageType('HelloMessage', (_message.Message,), dict(
  DESCRIPTOR = _HELLOMESSAGE,
  __module__ = 'connection_pb2'
  # @@protoc_insertion_point(class_scope:controller_connection.HelloMessage)
  ))
_sym_db.RegisterMessage(HelloMessage)

SwitchInfo = _reflection.GeneratedProtocolMessageType('SwitchInfo', (_message.Message,), dict(
  DESCRIPTOR = _SWITCHINFO,
  __module__ = 'connection_pb2'
  # @@protoc_insertion_point(class_scope:controller_connection.SwitchInfo)
  ))
_sym_db.RegisterMessage(SwitchInfo)

Status = _reflection.GeneratedProtocolMessageType('Status', (_message.Message,), dict(
  DESCRIPTOR = _STATUS,
  __module__ = 'connection_pb2'
  # @@protoc_insertion_point(class_scope:controller_connection.Status)
  ))
_sym_db.RegisterMessage(Status)

TableEntry = _reflection.GeneratedProtocolMessageType('TableEntry', (_message.Message,), dict(
  DESCRIPTOR = _TABLEENTRY,
  __module__ = 'connection_pb2'
  # @@protoc_insertion_point(class_scope:controller_connection.TableEntry)
  ))
_sym_db.RegisterMessage(TableEntry)

GroupPacket = _reflection.GeneratedProtocolMessageType('GroupPacket', (_message.Message,), dict(
  DESCRIPTOR = _GROUPPACKET,
  __module__ = 'connection_pb2'
  # @@protoc_insertion_point(class_scope:controller_connection.GroupPacket)
  ))
_sym_db.RegisterMessage(GroupPacket)

TopologyPacket = _reflection.GeneratedProtocolMessageType('TopologyPacket', (_message.Message,), dict(
  DESCRIPTOR = _TOPOLOGYPACKET,
  __module__ = 'connection_pb2'
  # @@protoc_insertion_point(class_scope:controller_connection.TopologyPacket)
  ))
_sym_db.RegisterMessage(TopologyPacket)

PortInfo = _reflection.GeneratedProtocolMessageType('PortInfo', (_message.Message,), dict(
  DESCRIPTOR = _PORTINFO,
  __module__ = 'connection_pb2'
  # @@protoc_insertion_point(class_scope:controller_connection.PortInfo)
  ))
_sym_db.RegisterMessage(PortInfo)



_LOCALSERVER = _descriptor.ServiceDescriptor(
  name='LocalServer',
  full_name='controller_connection.LocalServer',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  serialized_start=486,
  serialized_end=739,
  methods=[
  _descriptor.MethodDescriptor(
    name='AddEntry',
    full_name='controller_connection.LocalServer.AddEntry',
    index=0,
    containing_service=None,
    input_type=_TABLEENTRY,
    output_type=_STATUS,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='RemoveEntry',
    full_name='controller_connection.LocalServer.RemoveEntry',
    index=1,
    containing_service=None,
    input_type=_TABLEENTRY,
    output_type=_STATUS,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='Hello',
    full_name='controller_connection.LocalServer.Hello',
    index=2,
    containing_service=None,
    input_type=_HELLOMESSAGE,
    output_type=_SWITCHINFO,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_LOCALSERVER)

DESCRIPTOR.services_by_name['LocalServer'] = _LOCALSERVER


_GLOBALSERVER = _descriptor.ServiceDescriptor(
  name='GlobalServer',
  full_name='controller_connection.GlobalServer',
  file=DESCRIPTOR,
  index=1,
  serialized_options=None,
  serialized_start=742,
  serialized_end=1087,
  methods=[
  _descriptor.MethodDescriptor(
    name='GroupMessage',
    full_name='controller_connection.GlobalServer.GroupMessage',
    index=0,
    containing_service=None,
    input_type=_GROUPPACKET,
    output_type=_STATUS,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='TopologyMessage',
    full_name='controller_connection.GlobalServer.TopologyMessage',
    index=1,
    containing_service=None,
    input_type=_TOPOLOGYPACKET,
    output_type=_STATUS,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='PortMessage',
    full_name='controller_connection.GlobalServer.PortMessage',
    index=2,
    containing_service=None,
    input_type=_PORTINFO,
    output_type=_STATUS,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='CheckConnection',
    full_name='controller_connection.GlobalServer.CheckConnection',
    index=3,
    containing_service=None,
    input_type=_EMPTY,
    output_type=_STATUS,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_GLOBALSERVER)

DESCRIPTOR.services_by_name['GlobalServer'] = _GLOBALSERVER

# @@protoc_insertion_point(module_scope)
