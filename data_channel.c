/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <unistd.h>

#include "connection.h"
#include "data_channel.h"
#include "event_thread.h"
#include "log.h"

#define DATA_CHANNEL_CHUNK_MAX_PROGRESS 0x1000
#define DATA_CHANNEL_LOCAL_PORT 49424

#define SET_CALLBACK(x)                                \
  {                                                    \
    LOG_DEBUG("data_channel->process_cb = " #x ";\n"); \
    data_channel->process_cb = x;                      \
  }

// Unique ID (per scand instance) that groups a set of scanned pages.
static atomic_int scan_id;

struct data_packet_header {
    uint8_t id;
    uint16_t magic;
    uint16_t page_id;
    uint8_t unk2;
    uint16_t progress;
    uint16_t unk3;
};

static int receive_initial_data(struct data_channel *data_channel);
static int process_header(struct data_channel *data_channel);

int data_channel_set_paused(struct data_channel *data_channel) {
  event_thread_pause(data_channel->thread);
  sleep(1);
  return 0;
}

static struct scan_param *
get_scan_param_by_index(struct data_channel *data_channel, uint8_t index)
{
    if (index >= CONFIG_SCAN_MAX_PARAMS) {
        return NULL;
    }

    return data_channel->params + index;
}

static struct scan_param *
get_scan_param_by_id(struct data_channel *data_channel, char id)
{
    struct scan_param *ret;
    uint8_t i = 0;

    do {
        ret = get_scan_param_by_index(data_channel, i++);
    } while (ret != NULL && ret->id != id);

    return ret;
}

static int
read_scan_params(struct data_channel *data_channel, uint8_t *buf, uint8_t *buf_end,
                 const char *whitelist)
{
    struct scan_param *param;
    char id;
    size_t i;

    while (buf < buf_end) {
        id = *buf++;
        if (*buf != '=') {
            LOG_ERR("Received invalid scan param (missing '=' sign).\n");
            return -1;
        }
        ++buf;

        param = get_scan_param_by_id(data_channel, id);
        if (param == NULL) {
            LOG_ERR("Received invalid scan param (unknown id '%c').\n", id);
            return -1;
        }

        i = 0;
        while (*buf != 0x0a) {
            if (whitelist == NULL || strchr(whitelist, id) != NULL) {
                param->value[i++] = *buf;
            }

            if (i >= sizeof(param->value) - 1) {
                LOG_ERR("Received data_channel param longer than %zu bytes!\n",
                        sizeof(param->value) - 1);
                return -1;
            }

            ++buf;
        }
        param->value[i] = 0;

        ++buf;
    }

    return 0;
}

static uint8_t *
write_scan_params(struct data_channel *data_channel, uint8_t *buf,
                  const char *whitelist)
{
    struct scan_param *param;
    size_t len;
    uint8_t i = 0;

    while ((param = get_scan_param_by_index(data_channel, i++)) != NULL) {
        len = strlen(param->value);
        if (len == 0) {
            continue;
        }

        if (whitelist != NULL && strchr(whitelist, param->id) == NULL) {
            continue;
        }

        *buf++ = (uint8_t) param->id;
        *buf++ = '=';
        memcpy(buf, param->value, len);
        buf += len;
        *buf++ = 0x0a;
    }

    return buf;
}

static int invoke_callback(struct data_channel *data_channel,
                           const char *filename) {
  char buf[1024];
  int rc;
  char *script = data_channel->item->scan_command;
  const char *scan_func = g_scan_func_str[data_channel->item->scan_func];
  if (!script) {
    LOG_WARN("No hook configured for %s. (Received %s)\n", scan_func, filename);
    return 0;
  }
  LOG_INFO("Running hook: %s\n", script);
  char *args[] = {"/bin/sh", "-c", script, NULL};

  snprintf(buf, sizeof(buf), "%d", data_channel->xdpi);
  setenv("SCANNER_XDPI", buf, 1);
  snprintf(buf, sizeof(buf), "%d", data_channel->xdpi);
  setenv("SCANNER_YDPI", buf, 1);
  snprintf(buf, sizeof(buf), "%d", data_channel->height);
  setenv("SCANNER_HEIGHT", buf, 1);
  snprintf(buf, sizeof(buf), "%d", data_channel->width);
  setenv("SCANNER_WIDTH", buf, 1);
  snprintf(buf, sizeof(buf), "%d", data_channel->page_data.id);
  setenv("SCANNER_PAGE", buf, 1);
  setenv("SCANNER_IP", data_channel->config->ip, 1);
  snprintf(buf, sizeof(buf), "%d", data_channel->scan_id);
  setenv("SCANNER_SCANID", buf, 1);
  setenv("SCANNER_HOSTNAME", data_channel->item->hostname, 1);
  setenv("SCANNER_FUNC", scan_func, 1);
  if (filename) {
    setenv("SCANNER_FILENAME", filename, 1);
  }
  else {
    unsetenv("SCANNER_FILENAME");
  }

  rc = fork();
  if (rc == 0) {  // child process: run the user script
    execv(args[0], args);
    perror("execv");  // we only get here if execve fails.
    exit(1);
  }
  if (rc < 0) {
    perror("fork");
    return -1;
  }
  // parent process
  if (filename) {
    LOG_DEBUG("Waiting for hook to finish: %d\n", rc);
    waitpid(rc, NULL, 0);  // wait for child to finish
    LOG_DEBUG("Hook finished: %d\n", rc);
  }
  return 0;
}

static int process_page_end_header(struct data_channel *data_channel,
                                   struct data_packet_header *header) {
  FILE *destfile;
  char filename[64];
  char buf[2048];
  size_t size;

  if (header->page_id != data_channel->page_data.id) {
    LOG_ERR("%s: packet page_id mismatch (got %u, expected %u)\n",
            data_channel->config->ip, header->page_id,
            data_channel->scanned_pages + 1);
    return -1;
  }

  sprintf(filename, "scan%u.%s", data_channel->scanned_pages++,
          data_channel->file_format);
  destfile = fopen(filename, "w");
  if (destfile == NULL) {
    LOG_ERR("Cannot create file '%s' on data_channel %s\n", filename,
            data_channel->config->ip);
    return -1;
  }

  fseek(data_channel->tempfile, 0, SEEK_SET);
  while ((size = fread(buf, 1, sizeof(buf), data_channel->tempfile))) {
    fwrite(buf, 1, size, destfile);
  }

  fclose(destfile);
  fclose(data_channel->tempfile);
  data_channel->tempfile = NULL;

  SET_CALLBACK(receive_initial_data);
  LOG_INFO("%s: successfully received page %u\n", data_channel->config->ip,
           header->page_id);

  return invoke_callback(data_channel, filename);
}

static void process_scan_end_header(struct data_channel *data_channel) {
  brother_conn_disconnect(data_channel->conn);
  SET_CALLBACK(data_channel_set_paused);
  invoke_callback(data_channel, NULL);
}

static int process_page_payload(struct data_channel *data_channel) {
  if (brother_conn_fill_buffer(data_channel->conn, 1,
                               data_channel->config->timeout) < 0) {
    LOG_ERR("%s: Incomplete data from scanner\n", data_channel->config->ip);
    SET_CALLBACK(data_channel_set_paused);
    return -1;
  }
  size_t msg_len = MIN(data_channel->page_data.remaining_chunk_bytes,
                       brother_conn_data_available(data_channel->conn));
  char *buf = brother_conn_read(data_channel->conn, msg_len);
  if (buf == NULL) {
    LOG_ERR("%s: incomplete scan\n", data_channel->config->ip);
    return -1;
  }
  if (fwrite(buf, 1, msg_len, data_channel->tempfile) != msg_len) {
    LOG_ERR("%s: couldn’t write data to temporary file\n",
            data_channel->config->ip);
    return -1;
  }
  data_channel->page_data.remaining_chunk_bytes -= msg_len;
  if (data_channel->page_data.remaining_chunk_bytes == 0) {
    SET_CALLBACK(process_header);
  }
  return 0;
}

static int process_chunk_header(struct data_channel *data_channel,
                                struct data_packet_header *header) {
  int progress_percent;

  uint8_t *buf = brother_conn_read(data_channel->conn, 2);
  if (!buf) {
    LOG_ERR("%s: couldn't read payload length\n", data_channel->config->ip);
    return -1;
  }

  if (header->page_id == data_channel->page_data.id + 1) {
    // The assumption is that pages start with id 1 and increment linearly.
    // If that's wrong we'll need to update receive scripts too.
    LOG_INFO("%s: now scanning page id %u\n", data_channel->config->ip,
             header->page_id);
    data_channel->page_data.id = header->page_id;
  } else if (header->page_id != data_channel->page_data.id) {
    LOG_ERR("%s: packet page_id mismatch (packet %u != local %u)\n",
            data_channel->config->ip, header->page_id,
            data_channel->page_data.id);
    return -1;
  }

  progress_percent = header->progress * 100 / DATA_CHANNEL_CHUNK_MAX_PROGRESS;
  LOG_DEBUG("%s: receiving data: %d%%\n", data_channel->config->ip,
            progress_percent);

  data_channel->page_data.remaining_chunk_bytes = buf[0] | (buf[1] << 8);
  LOG_DEBUG("remaining_chunk_bytes: %d\n",
            data_channel->page_data.remaining_chunk_bytes);
  SET_CALLBACK(process_page_payload);
  return 0;
}

static int process_header(struct data_channel *data_channel) {
  struct data_packet_header header;
  int rc;

  if (brother_conn_fill_buffer(data_channel->conn, 1,
                               data_channel->item->page_finish_timeout) < 0) {
    LOG_ERR("%s: Incomplete data from scanner. Didn't receive chunk header",
            data_channel->config->ip);
    SET_CALLBACK(data_channel_set_paused);
    return -1;
  }
  uint8_t *buf = brother_conn_peek(data_channel->conn, 1);

  if (buf && *buf == 0x80) {  // page end marker
    brother_conn_read(data_channel->conn, 1);
    process_scan_end_header(data_channel);
    return 1;
  }

  if (brother_conn_fill_buffer(data_channel->conn, 10,
                               data_channel->item->page_finish_timeout) < 0) {
    LOG_ERR("%s: Incomplete data from scanner. Didn't receive chunk header\n",
            data_channel->config->ip);
    SET_CALLBACK(data_channel_set_paused);
    return -1;
  }
  buf = brother_conn_read(data_channel->conn, 10);
  header.id = buf[0];
  header.magic = buf[1] | (buf[2] << 8);
  header.page_id = buf[3] | (buf[4] << 8);
  header.unk2 = buf[5];
  header.progress = buf[6] | (buf[7] << 8);
  header.unk3 = buf[8] | (buf[9] << 8);

  if (header.magic != 0x07) {
    LOG_ERR("%s: invalid header magic number (%u != 0x07)\n",
            data_channel->config->ip, header.magic);
    DUMP_DEBUG(buf, 10);
    return -1;
  }

  switch (header.id) {
    case 0x40:  // RAW
      data_channel->file_format = "raw";
      break;
    case 0x42:  // RLENGTH (packbits)
      data_channel->file_format = "rle";
      break;
    case 0x64:
      data_channel->file_format = "jpeg";
      break;
    default:
      break;
  }

  switch (header.id) {
    case 0x40:  // RAW
    case 0x42:  // RLENGTH
    case 0x64:
      if (brother_conn_fill_buffer(data_channel->conn, 2,
                                   data_channel->item->page_finish_timeout) <
          0) {
        LOG_ERR("%s: Incomplete data from scanner. Didn't receive chunk size",
                data_channel->config->ip);
        SET_CALLBACK(data_channel_set_paused);
        return -1;
      }
      rc = process_chunk_header(data_channel, &header);
      break;
    case 0x82:
      rc = process_page_end_header(data_channel, &header);
      if (rc == 0) {
        rc = 1;
        }
        break;
    default:
        LOG_ERR("%s: received unsupported header (id = %u)\n",
                data_channel->config->ip, header.id);
        rc = -1;
  }

    return rc;
}

static int
receive_initial_data(struct data_channel *data_channel)
{
  int rc;

  if (brother_conn_data_available(data_channel->conn) == 0) {
    int is_first_page = data_channel->page_data.id == 0;
    rc = brother_conn_poll(data_channel->conn,
                           is_first_page
                               ? data_channel->item->page_init_timeout
                               : data_channel->item->page_finish_timeout);
    if (rc <= 0) {
      /* a failed scan attempt */
      LOG_WARN("Waited %ds for page, but didn't receive scan data.\n",
               data_channel->item->page_init_timeout);
      if (!is_first_page) {
        // assume the scan is finished.
        process_scan_end_header(data_channel);
      }
      return -1;
    }
  }
    data_channel->tempfile = tmpfile();
    if (data_channel->tempfile == NULL) {
        LOG_ERR("Cannot create temp file on data_channel %s\n",
                data_channel->config->ip);
        return -1;
    }
    SET_CALLBACK(process_header);
    return 0;
}

static int
exchange_params2(struct data_channel *data_channel)
{
    struct scan_param *param;
    uint8_t buf[1024], *buf_end;
    long recv_params[7];
    int msg_len, rc;
    size_t i;
    long tmp;
    long startx = 0, starty = 0, endx = 0, endy = 0;
    long adf_startx = 0, adf_starty = 0, adf_endx = 0, adf_endy = 0;

    rc = brother_conn_poll(data_channel->conn, 3);
    if (rc <= 0) {
        LOG_ERR("Couldn't receive scan params on data_channel %s\n",
                data_channel->config->ip);
        return -1;
    }

    msg_len = brother_conn_receive(data_channel->conn, buf, sizeof(buf) - 1);
    if (msg_len < 5) {
        LOG_ERR("Failed to receive scan params on data_channel %s\n",
                data_channel->config->ip);
        return -1;
    }

    /* process received data */
    if (buf[0] != 0x00) {
      LOG_ERR(
          "%s: received invalid exchange params msg (invalid first byte "
          "'%c').\n",
          data_channel->config->ip, buf[0]);
      return -1;
    }

    if (buf[1] != msg_len - 3) {
      LOG_ERR("%s: invalid second exchange params msg (invalid length '%c').\n",
              data_channel->config->ip, buf[1]);
      return -1;
    }

    if (buf[2] != 0x00) {
      LOG_ERR(
          "%s: received invalid exchange params msg (invalid third byte "
          "'%c').\n",
          data_channel->config->ip, buf[2]);
      return -1;
    }
    // Make sure it's \0 terminated.
    buf[msg_len] = 0;

    i = 0;
    uint8_t *buf_p = buf + 3;
    buf_end = buf_p;

    while (i < sizeof(recv_params) / sizeof(recv_params[0])) {
      tmp = strtol((char *)buf_p, (char **)&buf_end, 10);
      if (buf_end == buf_p || (*buf_end != ',' && *buf_end != 0) ||
          ((tmp == LONG_MIN || tmp == LONG_MAX) && errno == ERANGE)) {
        LOG_ERR("%s: received invalid exchange params msg (invalid params).\n",
                data_channel->config->ip);
        return -1;
      }

        recv_params[i++] = tmp;
        if (*buf_end) buf_end++;
        buf_p = buf_end;
    }
    data_channel->xdpi = recv_params[0];
    data_channel->ydpi = recv_params[1];

    if (*buf_p != 0x00) {
      LOG_ERR("%s: received invalid exchange params msg (message too long).\n",
              data_channel->config->ip);
      return -1;
    }

    param = get_scan_param_by_id(data_channel, 'R');
    assert(param);

    /* previously sent and just received dpi should match */
    sprintf((char *)buf, "%ld,%ld", recv_params[0], recv_params[1]);
    if (strncmp((char *)(buf), param->value, sizeof(param->value)) != 0) {
      LOG_INFO(
          "Scanner does not support requested dpi: %s."
          " %s will be used instead\n",
          param->value, (char *)(buf));

      strncpy(param->value, (const char *)buf, sizeof(param->value));
      param->value[sizeof(param->value) - 1] = 0;
    }

    /* for ADF */
    param = get_scan_param_by_id(data_channel, 'Z');
    assert(param);
    sscanf(param->value, "%ld,%ld,%ld,%ld", &adf_startx, &adf_starty, &adf_endx, &adf_endy);

    param = get_scan_param_by_id(data_channel, 'A');
    assert(param);
    sscanf(param->value, "%ld,%ld,%ld,%ld", &startx, &starty, &endx, &endy);

    if ((recv_params[6] <= 0) && (adf_endy > 0)) {
      startx = adf_startx;
      endx = adf_endx;
      starty = adf_starty;
      endy = adf_endy;
    }
    else if (endy <= 0) {
      startx = recv_params[3];
      endx = recv_params[4];
      starty = recv_params[5];
      endy = recv_params[6];
    }

    sprintf(param->value, "%ld,%ld,%ld,%ld", startx, starty, endx, endy);
    data_channel->width = endx - startx + 1;
    data_channel->height = endy - starty + 1;

    /* prepare a response */
    buf_p = buf;
    *buf_p++ = 0x1b;  // magic sequence
    *buf_p++ = 0x58;  // packet id (?)
    *buf_p++ = 0x0a;  // header end

    buf_p = write_scan_params(data_channel, buf_p, "RMCJBNADGLPS");
    if (buf_p == NULL) {
      LOG_ERR("Failed to write scan params on data_channel %s\n",
              data_channel->config->ip);
      return -1;
    }

    *buf_p++ = 0x80;  // end of message

    msg_len = brother_conn_send(data_channel->conn, buf, buf_p - buf);
    if (msg_len < 0 || msg_len != buf_p - buf) {
      LOG_ERR("Couldn't send scan params on data_channel %s\n",
              data_channel->config->ip);
      return -1;
    }

    // A new scan always starts from 0.
    data_channel->page_data.id = 0;
    data_channel->scan_id = atomic_fetch_add(&scan_id, 1);

    SET_CALLBACK(receive_initial_data);
    return 0;
}

static int data_channel_send_scan_params(struct data_channel *data_channel) {
  /* prepare a response */
  uint8_t buffer[1024];
  uint8_t *buf = buffer;
  *buf++ = 0x1b;  // magic sequence
  *buf++ = 0x49;  // packet id (?)
  *buf++ = 0x0a;  // header end

  // TODO: double-check why "RMCJBNADGL" isn't good
  buf = write_scan_params(data_channel, buf, "RMD");
  if (buf == NULL) {
    LOG_ERR("Failed to write initial scan params on data_channel %s\n",
            data_channel->config->ip);
    return -1;
  }

  *buf++ = 0x80;  // end of message

  int msg_len = brother_conn_send(data_channel->conn, buffer, buf - buffer);
  if (msg_len < 0) {
    LOG_ERR("Couldn't send initial scan params on data_channel %s\n",
            data_channel->config->ip);
    return -1;
  }

  SET_CALLBACK(exchange_params2);
  return 0;
}

static int
exchange_params1(struct data_channel *data_channel)
{
    struct scan_param *param;
    uint8_t *buf, *buf_end;
    int msg_len;
    size_t str_len;
    int i, rc;
    uint8_t buffer[1024];

    rc = brother_conn_poll(data_channel->conn, data_channel->config->timeout);
    if (rc <= 0) {
        LOG_ERR("%s: couldn't receive initial scan params\n",
                data_channel->config->ip);
        return -1;
    }

    msg_len = brother_conn_receive(data_channel->conn, buffer, sizeof(buffer));

    if (buffer[0] == 0xD0 && msg_len == 1) {
      LOG_INFO("No params to parse from remote.");
      return data_channel_send_scan_params(data_channel);
    }
    if (msg_len < 5) {
        LOG_ERR("%s: failed to receive initial scan params\n",
                data_channel->config->ip);
        return -1;
    }

    /* process received data */
    if (buffer[0] != 0x30) {
      LOG_ERR(
          "%s: received invalid initial exchange params msg"
          " (invalid first byte %02x).\n",
          data_channel->config->ip, buffer[0]);
      return -1;
    }
    //buf[1] == 0x15 or 0x55 (might refer to automatic/manual scan)
    //buf[2] == 0x30 or 0x00 ??

    if (buffer[msg_len - 2] != 0x0a) {  // end of param
      LOG_ERR(
          "%s: received invalid initial exchange params msg"
          " (invalid second-last byte '%c').\n",
          data_channel->config->ip, buffer[msg_len - 2]);
      return -1;
    }

    if (buffer[msg_len - 1] != 0x80) {  // end of message
      LOG_ERR(
          "%s: received invalid initial exchange params msg"
          " (invalid last byte '%c').\n",
          data_channel->config->ip, buffer[msg_len - 1]);
      return -1;
    }

    buf = buffer + 3;
    buf_end = buffer + msg_len - 2;

    if (read_scan_params(data_channel, buf, buf_end, NULL) != 0) {
        LOG_ERR("%s: failed to process initial scan params\n",
                data_channel->config->ip);
        return -1;
    }

    param = get_scan_param_by_id(data_channel, 'R');
    if (strchr(param->value, ',') == NULL) {
        str_len = strlen(param->value);
        if (str_len >= sizeof(param->value) - 1) {
            LOG_ERR("%s: received invalid resolution %s\n",
                    data_channel->config->ip, param->value);
            return -1;
        }

        param->value[str_len] = ',';
        memcpy(&param->value[str_len + 1], param->value, str_len);
    }

    param = get_scan_param_by_id(data_channel, 'F');
    for (i = 0; i < CONFIG_SCAN_MAX_FUNCS; ++i) {
        if (strcmp(param->value, g_scan_func_str[i]) == 0) {
            break;
        }
    }

    if (i == CONFIG_SCAN_MAX_FUNCS) {
        LOG_ERR("%s: received invalid scan function %s.\n",
                data_channel->config->ip, param->value);
        return -1;
    }

    return data_channel_send_scan_params(data_channel);
}

int data_channel_init_connection(struct data_channel *data_channel) {
  int rc, msg_len;
  uint8_t buffer[1024];

  if (brother_conn_reconnect(data_channel->conn,
                             inet_addr(data_channel->config->ip),
                             htons(DATA_CHANNEL_TARGET_PORT)) != 0) {
    LOG_ERR("Could not connect to scanner.\n");
    return -1;
  }

  rc = brother_conn_poll(data_channel->conn, data_channel->config->timeout);
  if (rc <= 0) {
    LOG_ERR("Couldn't receive welcome message on data_channel %s\n",
            data_channel->config->ip);
    return -1;
  }

  msg_len = brother_conn_receive(data_channel->conn, buffer, sizeof(buffer));
  if (msg_len < 1) {
    if (errno == ENOTCONN) {
      LOG_WARN("Lost connection on data_channel %s\n",
               data_channel->config->ip);
      // Let's reconnect.
      return data_channel_init_connection(data_channel);
    }
    LOG_ERR("Failed to receive welcome message on data_channel %s\n",
            data_channel->config->ip);
    return -1;
  }

  // "-NG 401\r\n": Scanner not ready?

  if (buffer[0] != '+') {
    LOG_ERR("Received invalid welcome message on data_channel %s\n",
            data_channel->config->ip);
    return -1;
  }

  msg_len = brother_conn_send(data_channel->conn, "\x1b\x4b\x0a\x80", 4);

  if (msg_len < 0) {
    LOG_ERR("Couldn't send welcome message on data_channel %s\n",
            data_channel->config->ip);
    return -1;
  }

  SET_CALLBACK(exchange_params1);
  return 0;
}

void data_channel_loop(void *arg) {
  struct data_channel *data_channel = arg;
  int rc;

  rc = data_channel->process_cb(data_channel);
  if (rc < 0) {
    LOG_ERR("%s: failed to process data. The channel will be closed.\n",
            data_channel->config->ip);

    if (data_channel->tempfile) {
      fclose(data_channel->tempfile);
      data_channel->tempfile = NULL;
    }

    SET_CALLBACK(data_channel_set_paused);
  }
}

static void
data_channel_stop(void *arg)
{
    struct data_channel *data_channel = arg;

    if (data_channel->tempfile) {
        fclose(data_channel->tempfile);
        data_channel->tempfile = NULL;
    }

    brother_conn_close(data_channel->conn);
    free(data_channel);
}

int data_channel_init(struct data_channel *data_channel) {
  data_channel->thread = event_thread_self();
  SET_CALLBACK(data_channel_set_paused);
  data_channel->file_format = "unk";

  data_channel->conn = brother_conn_open(BROTHER_CONNECTION_TYPE_TCP,
                                         data_channel->config->timeout);
  if (data_channel->conn == NULL) {
    LOG_ERR("Failed to init a data_channel.\n");
    event_thread_stop(data_channel->thread);
    return -1;
  }
  return 0;
}

void
data_channel_kick_cb(void *arg1, void *arg2)
{
    struct data_channel *data_channel = arg1;

    if (data_channel->process_cb != data_channel_set_paused) {
      LOG_ERR("Trying to kick non-sleeping data_channel %s.\n",
              data_channel->config->ip);
      return;
    }

    data_channel->process_cb = data_channel_init_connection;
}

void data_channel_set_item(struct data_channel *data_channel,
                           const struct item_config *item) {
  data_channel->item = item;
  memcpy(data_channel->params, data_channel->item->scan_params,
         sizeof(data_channel->item->scan_params));
}

void
data_channel_kick(struct data_channel *data_channel)
{
    struct event_thread *thread = data_channel->thread;
    int rc;

    rc = event_thread_enqueue_event(thread, data_channel_kick_cb, data_channel, NULL);
    if (rc != 0) {
        goto err;
    }

    rc = event_thread_kick(thread);
    if (rc != 0) {
        goto err;
    }

    return;

err:
    LOG_ERR("Failed to kick data_channel %s.\n",
            data_channel->config->ip);
}

struct data_channel *
data_channel_create(struct device_config *config)
{
    struct data_channel *data_channel;
    struct event_thread *thread;

    data_channel = calloc(1, sizeof(*data_channel));
    if (data_channel == NULL) {
        LOG_ERR("Failed to calloc data_channel.\n");
        return NULL;
    }

    data_channel->config = config;
    SET_CALLBACK(data_channel_init);

    thread = event_thread_create("data_channel", data_channel_loop,
                                 data_channel_stop, data_channel);
    if (thread == NULL) {
        LOG_ERR("Failed to create data_channel thread.\n");
        free(data_channel);
        return NULL;
    }

    return data_channel;
}
