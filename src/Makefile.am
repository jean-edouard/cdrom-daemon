#
# Copyright (c) 2015 Jed Lejosne <lejosnej@ainfosec.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

DBUS_CLIENT_IDLS =
DBUS_SERVER_IDLS = cdrom_daemon

AM_CFLAGS = -finput-charset=UTF-8 -std=gnu99 -DROOT_UID=0 -DHAVE_ARCH_STRUCT_FLOCK -DUSE_DBUS -DHAVE_ARCH_STRUCT_FLOCK -Wall -Werror

# Add @LIBXCXENSTORE_CFLAGS@ for libxcxenstore
INCLUDES = @DBUS_CFLAGS@ @DBUS_GLIB_CFLAGS@ @LIBXCDBUS_INC@

sbin_PROGRAMS = cdrom-daemon

PROTO_SRCS = main.c rpc.c xenstore.c blktap.c atapi.c

cdrom_daemon_SOURCES = ${PROTO_SRCS} rpcgen/cdrom_daemon_server_obj.c

# Add -lusb-1.0 for a decent usb lib
# Add @LIBXCXENSTORE_LIBS@ for libxcxenstore
cdrom_daemon_LDADD = @DBUS_LIBS@ @DBUS_GLIB_LIBS@ @LIBXCDBUS_LIBS@ -lblktapctl -lxenstore

BUILT_SOURCES = \
        ${DBUS_CLIENT_IDLS:%=rpcgen/%_client.h} \
        ${DBUS_SERVER_IDLS:%=rpcgen/%_server_marshall.h} \
        ${DBUS_SERVER_IDLS:%=rpcgen/%_server_obj.c} \
        ${DBUS_SERVER_IDLS:%=rpcgen/%_server_obj.h}

rpcgen/%_client.h: ${IDLDIR}/%.xml
	mkdir rpcgen || true
	${XC_RPCGEN} -c -o rpcgen/ $<

rpcgen/%_server_marshall.h rpcgen/%_server_obj.h rpcgen/%_server_obj.c : ${IDLDIR}/%.xml
	mkdir rpcgen || true
	${XC_RPCGEN} -s -o rpcgen/ $<
