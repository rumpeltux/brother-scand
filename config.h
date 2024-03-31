/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#ifndef BROTHER_CONFIG_H
#define BROTHER_CONFIG_H

#include <sys/queue.h>

#define CONFIG_HOSTNAME_LENGTH 16
#define CONFIG_SCAN_MAX_PARAMS 16
#define CONFIG_SCAN_MAX_FUNCS 4
#define CONFIG_NETWORK_DEFAULT_TIMEOUT_SEC 5
#define CONFIG_NETWORK_DEFAULT_PAGE_INIT_TIMEOUT 15
#define CONFIG_NETWORK_DEFAULT_PAGE_FINISH_TIMEOUT 60

struct scan_param {
    char id;
    char value[16];
};

struct device_config {
    char *ip;
    char *local_ip;
    unsigned timeout;
    TAILQ_HEAD(, item_config) items;
    TAILQ_ENTRY(device_config) tailq;
};

enum scan_func {
  SCAN_FUNC_INVALID = -1,
  SCAN_FUNC_IMAGE = 0,
  SCAN_FUNC_OCR = 1,
  SCAN_FUNC_EMAIL = 2,
  SCAN_FUNC_FILE = 3
};

struct item_config {
  char *password;
  char *hostname;  // the name displayed on the device

  enum scan_func scan_func;

  unsigned page_init_timeout;
  unsigned page_finish_timeout;
  struct scan_param scan_params[CONFIG_SCAN_MAX_PARAMS];
  // Which script to execute after receiving a page or set of pages.
  char *scan_command;
  TAILQ_ENTRY(item_config) tailq;

  // Registration number for this device. Filled in device_handler.c
  unsigned appnum;
};

struct brother_config {
    TAILQ_HEAD(, device_config) devices;
};

extern struct brother_config g_config;
extern const char *g_scan_func_str[CONFIG_SCAN_MAX_FUNCS];

enum scan_func config_get_scan_func_by_name(const char *name);
const struct item_config *config_find_by_func_and_name(
    const struct device_config *dev_config, enum scan_func func,
    const char *name);
int config_init(const char *config_path);

#endif //BROTHER_CONFIG_H
