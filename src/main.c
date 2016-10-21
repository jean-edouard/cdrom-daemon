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
 * @file   main.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   03 Oct 2016
 *
 * @brief  CDROM daemon
 *
 * Daemon that handles CDROMs
 */

#include "project.h"

int
main() {
  int ret = 0;
  struct timeval tv;
  fd_set readfds;
  fd_set writefds;
  fd_set exceptfds;
  int nfds;

  /* Setup dbus */
  rpc_init();

  /* Setup xenstore */
  xs_handle = xs_daemon_open();
  if (xs_handle == NULL) {
    log(LOG_ERR, "Failed to connect to xenstore");
    return 1;
  }

  /* TODO: list existing vbds */

  /* Main loop */
  while (1) {
    /* Check dbus */
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    nfds = xcdbus_pre_select(g_xcbus, 0, &readfds, &writefds, &exceptfds);
    select(nfds, &readfds, &writefds, &exceptfds, &tv);
    xcdbus_post_select(g_xcbus, 0, &readfds, &writefds, &exceptfds);
    /* TODO: watch xenstore for new (domains and) vbds */
  }

  return ret;
}
