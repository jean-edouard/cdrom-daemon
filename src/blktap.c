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
 * @file   blktap.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   20 Oct 2016
 *
 * @brief  blktap-related functions
 *
 * This file implements all the code for handling the emulated CDROMs
 * exposed to the guests. (the "iso" drive)
 */

#include "project.h"

static int cdrom_vdev_of_domid(int domid)
{
  char xpath[256], **devs, *type;
  unsigned int i, count;
  int vdev, res = -1;

  /* Find the CDROM virtual device for the given domid */
  snprintf(xpath, sizeof(xpath), "/local/domain/0/backend/vbd/%d", domid);
  devs = xs_directory(xs_handle, XBT_NULL, xpath, &count);
  if (devs) {
    for (i = 0; i < count; ++i) {
      vdev = strtol(devs[i], NULL, 10);
      type = xenstore_be_read(XBT_NULL, domid, vdev, "device-type");
      if (type == NULL)
        continue;
      if (!strcmp(type, "cdrom")) {
        /* CDROM found! */
        res = vdev;
        free(type);
        break;
      }
      free(type);
    }
    free(devs);
  }

  return res;
}

static int cdrom_tap_minor_of_vdev(int domid, int vdev)
{
  char *tmp;
  int tap_minor = -1;

  if (vdev < 0)
    return -1;

  tmp = xenstore_be_read(XBT_NULL, domid, vdev, "params");
  if (tmp != NULL) {
    tap_minor = strtol(tmp + 24, NULL, 10);
    free(tmp);
  }

  return tap_minor;
}

static bool cdrom_tapdev_is_shared(int tap_minor, int domid)
{
  char **domids;
  unsigned int i, count;
  int vdev, tm, d;
  char *target;
  bool res = false;

  domids = xs_directory(xs_handle, XBT_NULL, "/local/domain/0/backend/vbd", &count);
  if (domids) {
    for (i = 0; i < count; ++i) {
      d = strtol(domids[i], NULL, 10);
      /* Skip if it's just us */
      if (d == domid)
	continue;
      target = xenstore_dom_read(XBT_NULL, d, "target");
      /* Skip if it's our stubdom */
      if (target != NULL) {
	if (strtol(target, NULL, 10) == domid) {
	  free(target);
	  continue;
	}
	free(target);
      }
      /* In any other case, if the tapdisk matches, we are true */
      vdev = cdrom_vdev_of_domid(d);
      tm = cdrom_tap_minor_of_vdev(d, vdev);
      if (tm == tap_minor) {
	res = true;
        break;
      }
    }
    free(domids);
  }

  return res;
}

static void cdrom_wait_for_disconnect(int domid, int vdev)
{
  int fd;
  unsigned int len;
  fd_set set;
  struct timeval tv;
  char **watch_paths;
  char *tmp;

  xenstore_be_watch(domid, vdev, "state");
  xenstore_fe_watch(domid, vdev, "state");
  fd = xs_fileno(xs_handle);
  while (1) {
    /* Wait for state changes or 1 second */
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    select(fd + 1, &set, NULL, NULL, &tv);
    if (FD_ISSET(fd, &set)) {
      watch_paths = xs_read_watch(xs_handle, &len);
      if (watch_paths != NULL)
	free(watch_paths);
    }
    /* Either way, check the states and return if they're disconnected */
    tmp = xenstore_be_read(XBT_NULL, domid, vdev, "state");
    if (strcmp(tmp, "6")) {
      free(tmp);
      continue;
    }
    free(tmp);
    tmp = xenstore_fe_read(XBT_NULL, domid, vdev, "state");
    if (strcmp(tmp, "6")) {
      free(tmp);
      continue;
    }
    free(tmp);
    break;
  }
  xenstore_be_unwatch(domid, vdev, "state");
  xenstore_fe_unwatch(domid, vdev, "state");  
}

/* Destroy an existing blkback and recreate it based on a different tapdisk */
static void recreate_single(int domid,
			    int vdev,
			    const char *tapdisk_params,
			    const char *type,
			    const char *physical,
			    const char *params)
{
  xs_transaction_t trans;
  char *tmp;
  bool is_connected = false;

  /* Get the current backend state */
  tmp = xenstore_be_read(XBT_NULL, domid, vdev, "state");
  if (tmp != NULL) {
    if (strtol(tmp, NULL, 10) == 4)
      is_connected = true;
    free(tmp);
  }

  /* If the backend is connected, we need to first disconnect it */
  if (is_connected) {
    /* Kill the current vdev */
    while (1) {
      trans = xs_transaction_start(xs_handle);

      xenstore_be_write(trans, domid, vdev, "online", "0");
      xenstore_be_write(trans, domid, vdev, "state",  "5");

      if (xs_transaction_end(xs_handle, trans, false) == false) {
	if (errno == EAGAIN)
	  continue;
      }
      break;
    }

    /* Wait for both the backend and the frontend to be disconnected */
    cdrom_wait_for_disconnect(domid, vdev);
  }

  /* Remove all traces of the vdev */
  while (1) {
    trans = xs_transaction_start(xs_handle);

    xenstore_be_destroy(trans, domid, vdev);
    xenstore_fe_destroy(trans, domid, vdev);

    if (xs_transaction_end(xs_handle, trans, false) == false) {
      if (errno == EAGAIN)
        continue;
    }
    break;
  }

  /* Create a new vdev based on $params and $physical */
  while (1) {
    trans = xs_transaction_start(xs_handle);

    xenstore_mkdir_with_perms(trans, 0, domid, VBD_BACKEND_FORMAT, domid, vdev);
    xenstore_be_write(trans, domid, vdev, "params",          params);
    xenstore_be_write(trans, domid, vdev, "type",            type);
    xenstore_be_write(trans, domid, vdev, "physical-device", physical);
    xenstore_be_write(trans, domid, vdev, "frontend",        VBD_FRONTEND_FORMAT, domid, vdev);
    xenstore_be_write(trans, domid, vdev, "device-type",     "cdrom");
    xenstore_be_write(trans, domid, vdev, "online",          "1");
    xenstore_be_write(trans, domid, vdev, "state",           "1");
    xenstore_be_write(trans, domid, vdev, "removable",       "1");
    xenstore_be_write(trans, domid, vdev, "mode",            "r");
    xenstore_be_write(trans, domid, vdev, "frontend-id",     "%d", domid);
    xenstore_be_write(trans, domid, vdev, "dev",             "hdc");
    xenstore_be_write(trans, domid, vdev, "tapdisk-params",  tapdisk_params);

    xenstore_mkdir_with_perms(trans, domid, 0, VBD_FRONTEND_FORMAT, domid, vdev);
    xenstore_fe_write(trans, domid, vdev, "state",           "1");
    xenstore_fe_write(trans, domid, vdev, "backend-id",      "0");
    xenstore_fe_write(trans, domid, vdev, "backend",         VBD_BACKEND_FORMAT, domid, vdev);
    xenstore_fe_write(trans, domid, vdev, "virtual-device",  "%d", vdev);
    xenstore_fe_write(trans, domid, vdev, "device-type",     "cdrom");
    xenstore_fe_write(trans, domid, vdev, "backend-uuid",    "00000000-0000-0000-0000-000000000000");

    if (xs_transaction_end(xs_handle, trans, false) == false) {
      if (errno == EAGAIN)
        continue;
    }
    break;
  }
}

static void recreate(int domid,
		     int vdev,
		     const char *params,
		     const char *type,
		     const char *physical,
		     const char *tapdisk_params)
{
  int stubdom = -1;
  char *tmp;

  /* Get stubdom id if any */
  tmp = xenstore_dom_read(XBT_NULL, domid, "image/device-model-domid");
  if (tmp != NULL) {
    stubdom = strtol(tmp, NULL, 10);
    free(tmp);
  }

  /* Change the cdrom for the domain and maybe its stubdom */
  recreate_single(domid, vdev, params, type, physical, tapdisk_params);
  if (stubdom != -1)
    recreate_single(stubdom, vdev, params, type, physical, tapdisk_params);
}

/* Change the iso used by a tapdisk, "" to eject */
static void cdrom_change_single(int domid,
				int vdev,
				const char *params,
				const char *type,
				const char *new_physical,
				const char *tapdisk_params)
{
  xs_transaction_t trans;
  
  while (1) {
    trans = xs_transaction_start(xs_handle);

    xenstore_be_write(trans, domid, vdev, "params", params);
    xenstore_be_write(trans, domid, vdev, "type",   type);
    if (new_physical != NULL)
      xenstore_be_write(trans, domid, vdev, "physical-device", new_physical);
    xenstore_be_write(trans, domid, vdev, "tapdisk-params",  tapdisk_params);

    if (xs_transaction_end(xs_handle, trans, false) == false) {
      if (errno == EAGAIN)
        continue;
    }
    break;
  }
}

static void cdrom_change(int domid,
			 int vdev,
			 const char *params,
			 const char *type,
			 const char *new_physical,
			 const char *tapdisk_params)
{
  int stubdom = -1;
  char *tmp;

  /* Get stubdom id if any */
  tmp = xenstore_dom_read(XBT_NULL, domid, "image/device-model-domid");
  if (tmp != NULL) {
    stubdom = strtol(tmp, NULL, 10);
    free(tmp);
  }

  /* Change the cdrom for the domain and maybe its stubdom */
  cdrom_change_single(domid, vdev, params, type, new_physical, tapdisk_params);
  if (stubdom != -1)
    cdrom_change_single(stubdom, vdev, params, type, new_physical, tapdisk_params);
}

static bool cdrom_tap_close_and_load(int tap_minor, const char *params, bool close)
{
  tap_list_t **list, **tmp, *tap = NULL;

  tap_ctl_list(&list);
  tmp = list;
  while(*tmp != NULL) {
    if ((*tmp)->minor == tap_minor) {
      tap = *tmp;
      break;
    }
    tmp++;
  }
  if (tap == NULL) {
    tap_ctl_free_list(list);
    return false;
  }
  if (close) {
    /* The last argument should be != 0 for force, but it's not supported */
    tap_ctl_close(tap->id, tap_minor, 0);
  }
  tap_ctl_open_flags(tap->id, tap_minor, params, TAPDISK_MESSAGE_FLAG_RDONLY);
  tap_ctl_free_list(list);

  return true;
}

static bool cdrom_tap_destroy(int tap_minor)
{
  tap_list_t **list, **tmp, *tap = NULL;

  tap_ctl_list(&list);
  tmp = list;
  while(*tmp != NULL) {
    if ((*tmp)->minor == tap_minor) {
      tap = *tmp;
      break;
    }
    tmp++;
  }
  if (tap == NULL) {
    tap_ctl_free_list(list);
    return false;
  }
  tap_ctl_destroy(tap->id, tap_minor);
  tap_ctl_free_list(list);

  return true;
}

static int find_tap_with_path(const char *path)
{
  tap_list_t **list, **tmp, *tap = NULL;
  int minor = -1;

  tap_ctl_list(&list);
  tmp = list;
  /* A closed tapdev will have a NULL path */
  while(*tmp != NULL && (*tmp)->path != NULL) {
    if (!strcmp((*tmp)->path, path)) {
      /* We found a tapdev, we can just use it and be done with it */
      tap = *tmp;
      break;
    }
    tmp++;
  }
  if (tap != NULL)
    minor = tap->minor;
  tap_ctl_free_list(list);

  return minor;
}

/*
 * There are 3 possible cases here:
 * 1. There is already a tapdev for the iso we're trying to switch to
 *    In which case destroy the blktap and recreate one pointing to that tapdev
 *    (tapdev hotplug is explicitely not supported),
 *    and maybe destroy our old tapdev
 * 2. IN_domid is the only one to use the iso
 *    (the only one whose blktap is linked to the tapdev that contains its iso)
 *    In which case we change the iso for that tapdev
 * 3. IN_domid shares the iso with another running guest
 *    In which case we create a new tapdev, destroy the blktap and recreate one
 *     pointing to the new iso. (tapdev hotplug is explicitely not supported)
 */
bool blktap_change_iso(const char *path, int domid)
{
  int tap_minor, vdev, existing;
  char tapdisk_params[256]; /**< Tapdisk params, e.g: "aio:/storage/isos/null.iso" */
  char params[256];    /**< Tapdev path,    e.g. "/dev/xen/blktap-2/tapdev0" */
  char phys[16];            /**< Physical path,  e.g. "fe:0" */
  char *new_params = NULL;  /**< Tapdev path,    e.g. "/dev/xen/blktap-2/tapdev1" */
  bool shared;

  /* Get the virtual cdrom vdev and tap minor for the domid */
  vdev = cdrom_vdev_of_domid(domid);
  if (vdev == -1)
    return false;
  tap_minor = cdrom_tap_minor_of_vdev(domid, vdev);

  /* If we don't have a virtual drive, fail. */
  if (tap_minor < 0)
    return false;

  /* Eject the disk */
  cdrom_change(domid, vdev, "", "", NULL, "");

  /* If the path is the empty string we're done. */
  if (*path == '\0')
    return true;

  /* See if there's other guests using the tapdev (we already ejected it) */
  shared = cdrom_tapdev_is_shared(tap_minor, domid);

  /* Inserting the new iso */

  /* 1.: is there already a tapdev for that iso? */
  snprintf(tapdisk_params, sizeof(tapdisk_params), "aio:%s", path);
  existing = find_tap_with_path(path);
  if (existing >= 0)
    {
      /* Destroy previous tapdev? */
      if (!shared)
        cdrom_tap_destroy(tap_minor);
      /* Switch to the one we just found */
      snprintf(params, sizeof(params), "/dev/xen/blktap-2/tapdev%d", existing);
      snprintf(phys, sizeof(phys), "fe:%d", existing);
      recreate(domid, vdev, tapdisk_params, "phy", phys, params);
      return true;
    }

  if (!shared) {
    snprintf(params, sizeof(params), "/dev/xen/blktap-2/tapdev%d", tap_minor);
    /* 2. We're the only one to use it, we can reuse the tapdev */
    if (cdrom_tap_close_and_load(tap_minor, tapdisk_params, true))
      cdrom_change(domid, vdev, params, "phy", NULL, tapdisk_params);
  } else {
    /* 3. We need to create a new tapdev */
    if (tap_ctl_create_flags(tapdisk_params, &new_params, TAPDISK_MESSAGE_FLAG_RDONLY) != 0)
      printf("tap_ctl_create_flags failed!!");
    tap_minor = strtol(new_params + 24, NULL, 10);
    snprintf(phys, sizeof(phys), "fe:%x", tap_minor);
    recreate(domid, vdev, tapdisk_params, "phy", phys, new_params);
  }

  return true;
}
