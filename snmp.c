/*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */

#include <stdint.h>
#include <memory.h>
#include <stdio.h>
#include <stdatomic.h>
#include "ber/snmp.h"
#include "network.h"
#include "log.h"

static atomic_int g_request_id = 0;
static uint32_t g_brInfoPrinterUStatusOID[] = { 1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 4, 2, 1, 5, 5, 6, 0, SNMP_MSG_OID_END };
static uint32_t g_brRegisterKeyInfoOID[] = { 1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 2, 11, 1, 1, 0, SNMP_MSG_OID_END };

static void
init_msg_header(struct snmp_msg_header *msg_header, const char *community, enum snmp_data_type type)
{
    msg_header->snmp_ver = 0;
    msg_header->community = community;
    msg_header->pdu_type = type;
    msg_header->request_id = atomic_fetch_add(&g_request_id, 1);
}

int
snmp_get_printer_status(int conn, uint8_t *buf, size_t buf_len)
{
    uint8_t *buf_end = buf + buf_len - 1;
    struct snmp_msg_header msg_header = {0};
    struct snmp_varbind varbind = {0};
    size_t snmp_len;
    uint8_t *out, *dec_out;
    int msg_len, rc = -1;
    uint32_t varbind_num = 1;

    init_msg_header(&msg_header, "public", SNMP_DATA_T_PDU_GET_REQUEST);
    memcpy(varbind.oid, g_brInfoPrinterUStatusOID, sizeof(g_brInfoPrinterUStatusOID));
    varbind.value_type = SNMP_DATA_T_NULL;

    out = snmp_encode_msg(buf_end, &msg_header, varbind_num, &varbind);
    snmp_len = buf_end - out + 1;

    msg_len = network_send(conn, out, snmp_len);
    if (msg_len < 0 || (size_t) msg_len != snmp_len) {
        perror("sendto");
        goto out;
    }

    msg_len = network_receive(conn, buf, buf_len);
    if (msg_len < 0) {
        perror("recvfrom");
        goto out;
    }

    dec_out = snmp_decode_msg(buf, buf_len, &msg_header, &varbind_num, &varbind);
    if (dec_out - buf != msg_len ||  varbind_num != 1) {
        fprintf(stderr, "Received invalid printer status SNMP response\n");
        hexdump("SNMP response", buf, (size_t) msg_len);
    }

    rc = (int) varbind.value.i;
out:
    return rc;
}

int
snmp_register_scanner_host(int conn, uint8_t *buf, size_t buf_len, const char *functions[4])
{
    uint8_t *buf_end = buf + buf_len - 1;

    struct snmp_msg_header msg_header = {0};
    struct snmp_varbind varbind[4] = {0};
    va_list args;
    size_t snmp_len;
    int msg_len;
    uint8_t *out;
    int i, rc = -1;

    init_msg_header(&msg_header, "internal", SNMP_DATA_T_PDU_SET_REQUEST);

    for (i = 0; i < 4; ++i) {
        if (functions[i] == NULL || functions[i][0] == 0) {
            break;
        }

        memcpy(varbind[i].oid, g_brRegisterKeyInfoOID, sizeof(g_brRegisterKeyInfoOID));
        varbind[i].value_type = SNMP_DATA_T_OCTET_STRING;
        varbind[i].value.s = functions[i];
    }

    out = snmp_encode_msg(buf_end, &msg_header, i, varbind);
    snmp_len = buf_end - out + 1;

    msg_len = network_send(conn, out, snmp_len);
    if (msg_len < 0 || (size_t) msg_len != snmp_len) {
        perror("sendto");
        goto out;
    }

    msg_len = network_receive(conn, buf, buf_len);
    if (msg_len < 0 || (size_t) msg_len != snmp_len) {
        perror("recvfrom");
        goto out;
    }

    rc = msg_len;
out:
    return rc;
}
