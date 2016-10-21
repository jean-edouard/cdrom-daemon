/*
 * Copyright (c) 2016 Assured Information Security, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file project.h
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date 03 Oct 2016
 * @brief Local project header
 *
 * Header local to the project that shouldn't be exported.
 * Included by virtually every .c file in the project
 */

#ifndef __PROJECT_H__
#define __PROJECT_H__

#include "config.h"

#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif
#include <time.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(HAVE_SYS_INT_TYPES_H)
#include <sys/int_types.h>
#endif

#include <syslog.h>
#include <xenstore.h>

#include <tap-ctl.h>

/* CDROM_DAEMON dbus object implementation */
#include "rpcgen/cdrom_daemon_server_obj.h"

#define CDROMDAEMON     "com.citrix.xenclient.cdromdaemon" /**< The dbus name of cdrom daemon */
#define CDROMDAEMON_OBJ "/"                         /**< The main dbus object of cdrom daemon */

#define VBD_BACKEND_FORMAT  "/local/domain/0/backend/vbd/%d/%d"
#define VBD_FRONTEND_FORMAT "/local/domain/%d/device/vbd/%d"

/**
 * The (stupid) logging macro
 */
#define log(I, ...) do { fprintf(stderr, ##__VA_ARGS__); fprintf(stderr, "\n"); } while (0)

enum XenBusStates {
  XB_UNKNOWN,
  XB_INITTING,
  XB_INITWAIT,
  XB_INITTED,
  XB_CONNECTED,
  XB_CLOSING,
  XB_CLOSED
};

struct xs_handle *xs_handle; /**< The global xenstore handle, initialized by xenstore_init() */
xcdbus_conn_t *g_xcbus;      /**< The global dbus (libxcdbus) handle, initialized by rpc_init() */

bool  xenstore_be_write(xs_transaction_t trans, int domid, int vdev, char *node, const char *value, ...);
bool  xenstore_fe_write(xs_transaction_t trans, int domid, int vdev, char *node, const char *value, ...);
char *xenstore_be_read(xs_transaction_t trans, int domid, int vdev, char *node);
char *xenstore_fe_read(xs_transaction_t trans, int domid, int vdev, char *node);
bool  xenstore_be_destroy(xs_transaction_t trans, int domid, int vdev);
bool  xenstore_fe_destroy(xs_transaction_t trans, int domid, int vdev);
bool  xenstore_mkdir_with_perms(xs_transaction_t trans, int owner, int reader, char *dir, ...);

bool blktap_change_iso(const char *path, int domid);

void rpc_init(void);

#endif
