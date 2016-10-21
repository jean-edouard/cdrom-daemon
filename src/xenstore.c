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
 * @file   xenstore.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   06 Oct 2016
 *
 * @brief  XenStore helpers
 *
 * Misc functions to read and write xenstore nodes
 */

#include "project.h"

static bool xenstore_write(xs_transaction_t trans, char *path, const char *value, va_list args)
{
  char val[256];

  vsnprintf(val, sizeof(val), value, args);

  return xs_write(xs_handle, trans, path, val, strlen(val));
}

bool xenstore_be_write(xs_transaction_t trans, int domid, int vdev, char *node, const char *value, ...)
{
  va_list args;
  char path[256];
  bool res;

  snprintf(path, sizeof(path), VBD_BACKEND_FORMAT "/%s", domid, vdev, node);

  va_start(args, value);
  res = xenstore_write(trans, path, value, args);
  va_end(args);

  return res;
}

bool xenstore_fe_write(xs_transaction_t trans, int domid, int vdev, char *node, const char *value, ...)
{
  va_list args;
  char path[256];
  bool res;

  snprintf(path, sizeof(path), VBD_FRONTEND_FORMAT "/%s", domid, vdev, node);

  va_start(args, value);
  res = xenstore_write(trans, path, value, args);
  va_end(args);

  return res;
}

static char *xenstore_read(xs_transaction_t trans, char *path)
{
  return xs_read(xs_handle, trans, path, NULL);
}

char *xenstore_be_read(xs_transaction_t trans, int domid, int vdev, char *node)
{
  char path[256];

  snprintf(path, sizeof(path), VBD_BACKEND_FORMAT "/%s", domid, vdev, node);

  return xenstore_read(trans, path);
}

char *xenstore_fe_read(xs_transaction_t trans, int domid, int vdev, char *node)
{
  char path[256];

  snprintf(path, sizeof(path), VBD_FRONTEND_FORMAT "/%s", domid, vdev, node);

  return xenstore_read(trans, path);
}

bool xenstore_be_destroy(xs_transaction_t trans, int domid, int vdev)
{
  char path[256];

  snprintf(path, sizeof(path), VBD_BACKEND_FORMAT, domid, vdev);

  return xs_rm(xs_handle, trans, path);
}

bool xenstore_fe_destroy(xs_transaction_t trans, int domid, int vdev)
{
  char path[256];

  snprintf(path, sizeof(path), VBD_FRONTEND_FORMAT, domid, vdev);

  return xs_rm(xs_handle, trans, path);
}

bool xenstore_mkdir_with_perms(xs_transaction_t trans, int owner, int reader, char *dir, ...)
{
  va_list args;
  char path[256];
  struct xs_permissions perms[2];

  va_start(args, dir);
  vsnprintf(path, sizeof(path), dir, args);
  va_end(args);

  xs_mkdir(xs_handle, trans, path);

  perms[0].id = owner;
  perms[0].perms = XS_PERM_NONE;
  perms[1].id = reader;
  perms[1].perms = XS_PERM_READ;

  return xs_set_permissions(xs_handle, trans, path, perms, 2);
}
