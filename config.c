/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

struct brother_config g_config;

void init_item_config(struct item_config *item_config,
                      const struct item_config *template, char name[1024]);

const char *g_scan_func_str[CONFIG_SCAN_MAX_FUNCS] = {
    [SCAN_FUNC_IMAGE] = "IMAGE",
    [SCAN_FUNC_OCR] = "OCR",
    [SCAN_FUNC_EMAIL] = "EMAIL",
    [SCAN_FUNC_FILE] = "FILE",
};

static void init_default_device_config(struct item_config *item_config,
                                       char *default_hostname) {
  struct scan_param *param;
  int i = 0;

  item_config->hostname = strdup(default_hostname);
  item_config->page_init_timeout = CONFIG_NETWORK_DEFAULT_PAGE_INIT_TIMEOUT;
  item_config->page_finish_timeout = CONFIG_NETWORK_DEFAULT_PAGE_FINISH_TIMEOUT;

#define ADD_SCAN_PARAM(ID, VAL)           \
  param = &item_config->scan_params[i++]; \
  param->id = ID;                         \
  strcpy(param->value, VAL);

  ADD_SCAN_PARAM('A', "");
  ADD_SCAN_PARAM('B', "50");
  ADD_SCAN_PARAM('C', "JPEG");
  ADD_SCAN_PARAM('D', "SIN");
  ADD_SCAN_PARAM('E', "");
  ADD_SCAN_PARAM('F', "");
  ADD_SCAN_PARAM('G', "1");
  ADD_SCAN_PARAM('J', "");
  ADD_SCAN_PARAM('L', "128");
  ADD_SCAN_PARAM('M', "CGRAY");
  ADD_SCAN_PARAM('N', "50");
  ADD_SCAN_PARAM('P', "A4");
  ADD_SCAN_PARAM('R', "300,300");
  ADD_SCAN_PARAM('T', "JPEG");

#undef ADD_SCAN_PARAM
}

void init_item_config(struct item_config *item_config,
                      const struct item_config *template, char *name) {
  memcpy(item_config, template, sizeof(*item_config));
  item_config->hostname = strdup(name);
}

const struct item_config *find_preset(const struct item_config *head,
                                      char *name) {
  while (head != NULL) {
    if (!strcmp(name, head->hostname)) return head;
    head = TAILQ_NEXT(head, tailq);
  }
  return NULL;
}

const struct item_config *config_find_by_func_and_name(
    const struct device_config *dev_config, enum scan_func func,
    const char *name) {
  const struct item_config *head = TAILQ_FIRST(&dev_config->items);
  while (head != NULL) {
    if (func == head->scan_func && !strcmp(head->hostname, name)) return head;
    head = TAILQ_NEXT(head, tailq);
  }
  return NULL;
}

enum scan_func config_get_scan_func_by_name(const char *name) {
  int i;
  for (i = 0; i < CONFIG_SCAN_MAX_FUNCS; ++i) {
    if (strcmp(name, g_scan_func_str[i]) == 0) {
      break;
    }
  }

  if (i == CONFIG_SCAN_MAX_FUNCS) {
    fprintf(stderr, "Error: invalid scan.func type '%s'.\n", name);
    return SCAN_FUNC_INVALID;
  }
  return i;
}

int
config_init(const char *config_path)
{
    FILE *config;
    struct device_config *dev_config = NULL;

    char buf[1024];
    char var_str[1024];
    char var2_str[16];
    char var_char;
    unsigned var_uint;
    int rc = -1, param_count = 0, i;

    TAILQ_INIT(&g_config.devices);

    TAILQ_HEAD(, item_config) presets;
    TAILQ_INIT(&presets);
    struct item_config *default_preset = calloc(1, sizeof(*default_preset));
    struct item_config *preset_config = default_preset;
    init_default_device_config(default_preset, "default");
    TAILQ_INSERT_TAIL(&presets, default_preset, tailq);

    config = fopen(config_path, "r");
    if (config == NULL) {
        fprintf(stderr, "Could not open config file '%s'.\n", config_path);
        abort();
    }

    while (fgets((char *) buf, sizeof(buf), config)) {
      if (sscanf(buf, "define-preset %15s", var_str) == 1) {
        // Create a new preset. Insert it into the list.
        preset_config = calloc(1, sizeof(*default_preset));
        init_item_config(preset_config, default_preset, var_str);
        TAILQ_INSERT_TAIL(&presets, preset_config, tailq);
      } else if (sscanf((char *)buf, "ip %64s", var_str) == 1) {
        // Create a new device entry. No items by default.
        dev_config = calloc(1, sizeof(*dev_config));
        preset_config = NULL;
        if (dev_config == NULL) {
          fprintf(stderr,
                  "Error: could not alloc memory for device config '%s'.\n",
                  var_str);
          goto out;
        }
        dev_config->ip = strdup(var_str);
        dev_config->timeout = CONFIG_NETWORK_DEFAULT_TIMEOUT_SEC;
        dev_config->local_ip = NULL;
        TAILQ_INIT(&dev_config->items);
        TAILQ_INSERT_TAIL(&g_config.devices, dev_config, tailq);
      } else if (sscanf(buf, "preset %15s %15s", var_str, var2_str) == 2) {
        // Create a new item within the current device.
        if (dev_config == NULL) {
          fprintf(stderr,
                  "Cannot use a preset %s before configuring a device (start "
                  "with 'ip x.x.x.x')\n",
                  var_str);
          goto out;
        }
        const struct item_config *existing_preset =
            find_preset(TAILQ_FIRST(&presets), var_str);
        if (existing_preset == NULL) {
          fprintf(stderr, "preset %s wasn't defined yet\n", var_str);
          goto out;
        }
        enum scan_func scan_func = config_get_scan_func_by_name(var2_str);
        if (scan_func == SCAN_FUNC_INVALID) {
          goto out;
        }
        preset_config = calloc(1, sizeof(*preset_config));
        init_item_config(preset_config, existing_preset,
                         existing_preset->hostname);
        preset_config->scan_func = scan_func;
        TAILQ_INSERT_TAIL(&dev_config->items, preset_config, tailq);
      } else if (sscanf((char *)buf, "network.timeout %u", &var_uint) == 1) {
        if (dev_config == NULL) {
          fprintf(stderr, "Error: timeout specified without a device.\n");
          goto out;
        }
        dev_config->timeout = var_uint;
      } else if (sscanf((char *)buf, "network.local-ip %64s", var_str) == 1) {
        if (dev_config == NULL) {
          fprintf(stderr, "Error: local ip specified without a device.\n");
          goto out;
        }
        dev_config->local_ip = strdup(var_str);
      } else if (sscanf((char *)buf, "hostname %15s", var_str) == 1) {
        if (preset_config == NULL) {
          fprintf(stderr, "Error: hostname specified without a preset.\n");
          goto out;
        }
        char *old_hostname = preset_config->hostname;
        preset_config->hostname = strdup(var_str);
        free(old_hostname);
      } else if (sscanf((char *)buf, "password %4s", var_str) == 1) {
        if (preset_config == NULL) {
          fprintf(stderr, "Error: password specified without a preset.\n");
          goto out;
        }
        char *old_password = preset_config->password;
        preset_config->password = strdup(var_str);
        if (old_password) free(old_password);
      } else if (sscanf((char *)buf, "network.page.init.timeout %u",
                        &var_uint) == 1) {
        if (preset_config == NULL) {
          fprintf(
              stderr,
              "Error: network.page.init.timeout specified without a preset.\n");
          goto out;
        }
        preset_config->page_init_timeout = var_uint;
      } else if (sscanf((char *)buf, "network.page.finish.timeout %u",
                        &var_uint) == 1) {
        if (preset_config == NULL) {
          fprintf(stderr,
                  "Error: network.page.finish.timeout specified without a "
                  "preset.\n");
          goto out;
        }
        preset_config->page_finish_timeout = var_uint;
      } else if (sscanf((char *)buf, "scan.param %c %15s", &var_char,
                        var_str) == 2) {
        if (preset_config == NULL) {
          fprintf(stderr, "Error: scan.param specified without a preset.\n");
          goto out;
        }

        if (param_count >= CONFIG_SCAN_MAX_PARAMS) {
          fprintf(stderr, "Error: too many scan.params. Max %d.\n",
                  CONFIG_SCAN_MAX_PARAMS);
          goto out;
        }

        for (i = 0; i < CONFIG_SCAN_MAX_PARAMS; ++i) {
          if (preset_config->scan_params[i].id == var_char) {
            strcpy(preset_config->scan_params[i].value, var_str);
            break;
          }
        }

        if (i == CONFIG_SCAN_MAX_PARAMS) {
          fprintf(stderr, "Error: invalid scan.param type '%c'.\n", var_char);
          goto out;
        }

        ++param_count;
      } else if (sscanf((char *)buf, "scan.func %1024[^\n]", var_str) == 1) {
        if (preset_config == NULL) {
          fprintf(stderr, "Error: scan.param specified without a preset.\n");
          goto out;
        }
        preset_config->scan_command = strdup(var_str);
      } else if (*buf == '#' || !*buf || *buf == '\n') {
        // Ignore empty or comment-only lines.
        continue;
      } else {
        fprintf(stderr, "Invalid configuration option: %s", buf);
        goto out;
      }
    }
    rc = 0;
out:
    fclose(config);
    return rc;
}
