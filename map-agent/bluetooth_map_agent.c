/*
 * Bluetooth-agent
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <gio/gio.h>
#include <time.h>
#include "vconf.h"
#include "vconf-keys.h"

#include <sys/types.h>
#include <fcntl.h>

/*Messaging Header Files*/
#include "msg.h"
#include "msg_storage.h"
#include "msg_storage_types.h"
#include "msg_transport.h"
#include "msg_transport_types.h"
#include "msg_types.h"

#include <TelSms.h>
#include <TapiUtility.h>
#include <ITapiNetText.h>
#include <bluetooth_map_agent.h>
#include <bluetooth_map_email.h>
#include <bluetooth_map_sms.h>
#include <map_bmessage.h>

#define OBEX_CLIENT_SERVICE "org.bluez.obex"
#define OBEX_CLIENT_INTERFACE "org.bluez.obex.Client1"
#define OBEX_CLIENT_PATH "/org/bluez/obex"
#define MNS_CLIENT_INTERFACE "org.openobex.MessageNotification"

#define BT_MAP_NEW_MESSAGE "NewMessage"
#define BT_MAP_STATUS_CB "sent status callback"
#define BT_MAP_MSG_CB "sms message callback"
#define BT_MNS_OBJECT_PATH "/org/bluez/mns"
#define BT_MNS_INTERFACE "org.bluez.mns"
#define BT_MAP_SENT_FOLDER_NAME "SENT"
#define BT_MAP_MSG_TEMPLATE "TEMPLATE"
#define BT_MAP_DELETED_FOLDER_NAME "DELETED"
#define BT_MAP_MSG_INFO_MAX 256
#define BT_MAP_MSG_HANDLE_MAX 21
#define BT_MAP_TIMESTAMP_MAX_LEN 16
#define BT_MAP_MSG_BODY_MAX 1024
#define BT_MSG_UPDATE	0
#define BT_MSG_DELETE	1
#define BT_SMS 0

static TapiHandle *g_tapi_handle;
static TelSmsAddressInfo_t *g_sca_info;

GSList *id_list = NULL;
guint64 current_push_map_id;
char *push_folder;
msg_send_option_t opt;

typedef enum {
	SMS_TON_UNKNOWN = 0,		/* unknown */
	SMS_TON_INTERNATIONAL = 1,	/* international number */
	SMS_TON_NATIONAL = 2,		/* national number */
	SMS_TON_NETWORK_SPECIFIC = 3, /* network specific number */
	SMS_TON_DEDICATED_ACCESS = 4, /* subscriber number */
	SMS_TON_ALPHA_NUMERIC = 5,	/* alphanumeric, GSM 7-bit default */
	SMS_TON_ABBREVIATED_NUMBER = 6, /* abbreviated number */
	SMS_TON_RESERVED_FOR_EXT = 7 /* reserved for extension */
} bt_sim_type_of_num_t;

struct id_info {
	guint64 map_id;
	int uid;
	int msg_type;
};

/* Store supported folders in SMS and EMAIL */
gboolean folders_supported[FOLDER_COUNT][MSG_TYPES] = { {FALSE, FALSE}, };

GMainLoop *g_mainloop;
static char *g_mns_path;
static GDBusConnection *map_dbus_conn;
static GDBusProxy *g_mns_proxy;

static const gchar map_agent_introspection_xml[] =
"<node name='/'>"
"	<interface name='org.bluez.MapAgent'>"
"		<method name='GetFolderTree'>"
"			<arg type='a(s)' name='folder_list' direction='out'/>"
"		</method>"
"		<method name='GetMessageList'>"
"			<arg type='s' name='folder_name'/>"
"			<arg type='q' name='max'/>"
"			<arg type='q' name='offset'/>"
"			<arg type='y' name='subject_len'/>"
"			<arg type='a{sv}' name='filters'/>"
"			<arg type='b' name='newmessage' direction='out'/>"
"			<arg type='t' name='count' direction='out'/>"
"			<arg type='a(ssssssssssbsbbbbs)' name='msg_list' direction='out'/>"
"		</method>"
"		<method name='GetMessage'>"
"			<arg type='s' name='message_name'/>"
"			<arg type='b' name='attach'/>"
"			<arg type='b' name='transcode'/>"
"			<arg type='b' name='first_request'/>"
"			<arg type='b' name='fraction_deliver' direction='out'/>"
"			<arg type='s' name='msg_body' direction='out'/>"
"		</method>"
"		<method name='PushMessage'>"
"			<arg type='b' name='save_copy'/>"
"			<arg type='b' name='retry_send'/>"
"			<arg type='b' name='native'/>"
"			<arg type='s' name='folder_name'/>"
"			<arg type='t' name='handle' direction='out'/>"
"		</method>"
"		<method name='PushMessageData'>"
"			<arg type='s' name='bmsg'/>"
"		</method>"
"		<method name='UpdateMessage'>"
"			<arg type='u' name='update_err' direction='out'/>"
"		</method>"
"		<method name='SetReadStatus'>"
"			<arg type='s' name='handle'/>"
"			<arg type='b' name='read_status'/>"
"			<arg type='u' name='update_err' direction='out'/>"
"		</method>"
"		<method name='SetDeleteStatus'>"
"			<arg type='s' name='handle'/>"
"			<arg type='b' name='delete_status'/>"
"			<arg type='u' name='update_err' direction='out'/>"
"		</method>"
"		<method name='NotiRegistration'>"
"			<arg type='s' name='remote_addr'/>"
"			<arg type='b' name='status'/>"
"			<arg type='u' name='update_err' direction='out'/>"
"		</method>"
"		<method name='DestroyAgent'>"
"		</method>"
"	</interface>"
"</node>";

/* Method Prototypes */
static GVariant *__bt_map_get_folder_tree(GError **err);
static GVariant *__bt_map_get_message_list(char *folder_name, guint16 max,
				guint16 offset, guint8 subject_len,
				map_msg_filter_t *filter, GError **err);
static GVariant *__bt_map_get_message(char *message_name, gboolean attach,
		gboolean transcode, gboolean first_request, GError **err);
static GVariant *__bt_map_push_message(gboolean save_copy,  gboolean retry_send,
		gboolean native, char *folder_name, GError **err);
static GVariant *__bt_map_push_message_data(char *bmseg, GError **err);
static GVariant *__bt_map_update_message(GError **err);
static GVariant *__bt_map_set_read_status(char *handle, gboolean read_status, GError **err);
static GVariant *__bt_map_set_delete_status(char *handle, gboolean delete_status, GError **err);
static void __bt_map_noti_registration(char *remote_addr, gboolean status);
static void __bt_map_destroy_agent(void);

/* Create GError from error code and error message */
static GError *__bt_map_error(int error_code, char *error_message)
{
	return g_error_new(g_quark_from_string("MAP Agent"),
			error_code, "MAP Agent Error: %s", error_message);
}

static map_msg_filter_t __bt_map_get_filters(GVariant *filters)
{
	map_msg_filter_t filter = { 0, };
	GVariantIter iter;
	GVariant *value;
	gchar *key;

	g_variant_iter_init(&iter, filters);
	while (g_variant_iter_loop(&iter, "{sv}", &key, &value)) {
		if (!g_strcmp0(key, "ParameterMask")) {
			filter.parameter_mask = g_variant_get_uint32(value);
			DBG("ParameterMask :%u", filter.parameter_mask);
		} else if (!g_strcmp0(key, "FilterMessageType")) {
			filter.type = g_variant_get_byte(value);
			DBG("FilterMessageType :%u", filter.type);
		} else if (!g_strcmp0(key, "FilterPeriodBegin")) {
			g_variant_get(value, "s", &filter.period_begin);
			DBG("FilterPeriodBegin :%s", filter.period_begin);
		} else if (!g_strcmp0(key, "FilterPeriodEnd")) {
			g_variant_get(value, "s", &filter.period_end);
			DBG("FilterPeriodEnd :%s", filter.period_end);
		} else if (!g_strcmp0(key, "FilterReadStatus")) {
			filter.read_status = g_variant_get_byte(value);
			DBG("FilterReadStatus :%u", filter.read_status);
		} else if (!g_strcmp0(key, "FilterRecipient")) {
			g_variant_get(value, "s", &filter.recipient);
			DBG("FilterRecipient :%s", filter.recipient);
		} else if (!g_strcmp0(key, "FilterOriginator")) {
			g_variant_get(value, "s", &filter.originator);
			DBG("FilterOriginator :%s", filter.originator);
		} else if (!g_strcmp0(key, "FilterPriority")) {
			filter.priority = g_variant_get_byte(value);
			DBG("FilterPriority :%u", filter.priority);
		}
	}

	return filter;
}

static void __bt_map_agent_method(GDBusConnection *connection,
			const gchar *sender,
			const gchar *object_path,
			const gchar *interface_name,
			const gchar *method_name,
			GVariant *parameters,
			GDBusMethodInvocation *invocation,
			gpointer user_data)
{
	FN_START;

	INFO("method %s", method_name);
	INFO("object_path %s", object_path);
	GError *err = NULL;

	if (g_strcmp0(method_name, "GetFolderTree") == 0) {
		GVariant *folder_list = NULL;

		folder_list = __bt_map_get_folder_tree(&err);
		if (err)
			goto fail;

		g_dbus_method_invocation_return_value(invocation, folder_list);
	} else if (g_strcmp0(method_name, "GetMessageList") == 0) {
		GVariant *message_list = NULL;
		guint16 max;
		guint16 offset;
		guint8 subject_len;
		gchar *folder_name;
		GVariant *filters = NULL;
		map_msg_filter_t filter = { 0, };

		g_variant_get(parameters, "(&sqqy@a{sv})", &folder_name,
				&max, &offset, &subject_len, &filters);

		DBG("MAX:%d Offset:%d SubjectLen:%d", max, offset, subject_len);
		if (subject_len == 0)
			subject_len = BT_MAP_SUBJECT_MAX_LEN;

		filter = __bt_map_get_filters(filters);
		message_list = __bt_map_get_message_list(folder_name, max,
				offset, subject_len, &filter, &err);

		if (err)
			goto fail;

		g_dbus_method_invocation_return_value(invocation, message_list);
	} else if (g_strcmp0(method_name, "GetMessage") == 0) {
		GVariant *message = NULL;
		gchar *message_name;
		gboolean attach;
		gboolean transcode;
		gboolean first_request;

		g_variant_get(parameters, "(&sbbb)", &message_name,
				&attach, &transcode, &first_request);

		message = __bt_map_get_message(message_name, attach,
				transcode, first_request, &err);
		if (err)
			goto fail;

		g_dbus_method_invocation_return_value(invocation, message);
	} else if (g_strcmp0(method_name, "PushMessage") == 0) {
		GVariant *handle = NULL;
		gboolean save_copy;
		gboolean retry_send;
		gboolean native;
		gchar *folder_name;

		g_variant_get(parameters, "(bbb&s)", &save_copy,
				&retry_send, &native, &folder_name);

		handle = __bt_map_push_message(save_copy, retry_send,
				native, folder_name, &err);
		if (err)
			goto fail;

		g_dbus_method_invocation_return_value(invocation, handle);
	} else if (g_strcmp0(method_name, "PushMessageData") == 0) {
		gchar *bmseg;

		g_variant_get(parameters, "(&s)", &bmseg);

		__bt_map_push_message_data(bmseg, &err);
		if (err)
			goto fail;

		g_dbus_method_invocation_return_value(invocation, NULL);
	} else if (g_strcmp0(method_name, "UpdateMessage") == 0) {
		GVariant *update = NULL;

		update = __bt_map_update_message(&err);
		if (err)
			goto fail;

		g_dbus_method_invocation_return_value(invocation, update);
	} else if (g_strcmp0(method_name, "SetReadStatus") == 0) {
		gchar *handle;
		gboolean read_status;

		g_variant_get(parameters, "(&sb)", &handle, &read_status);

		__bt_map_set_read_status(handle, read_status, &err);
		if (err)
			goto fail;

		g_dbus_method_invocation_return_value(invocation, NULL);
	} else if (g_strcmp0(method_name, "SetDeleteStatus") == 0) {
		gchar *handle;
		gboolean delete_status;

		g_variant_get(parameters, "(&sb)", &handle, &delete_status);

		__bt_map_set_delete_status(handle, delete_status, &err);
		if (err)
			goto fail;

		g_dbus_method_invocation_return_value(invocation, NULL);
	} else if (g_strcmp0(method_name, "NotiRegistration") == 0) {
		char *remote_addr;
		gboolean status;
		g_variant_get(parameters, "(&sb)", &remote_addr, &status);

		__bt_map_noti_registration(remote_addr, status);
		g_dbus_method_invocation_return_value(invocation, NULL);
	} else if (g_strcmp0(method_name, "DestroyAgent") == 0) {
		g_dbus_method_invocation_return_value(invocation, NULL);
		__bt_map_destroy_agent();
	}

	INFO("-");
	return;

fail:
	g_dbus_method_invocation_return_gerror(invocation, err);
	g_error_free(err);
	INFO("-");
}

static const GDBusInterfaceVTable method_table = {
	__bt_map_agent_method,
	NULL,
	NULL,
};

static GDBusConnection *__bt_map_get_gdbus_connection(void)
{
	FN_START;

	GError *err = NULL;

	if (map_dbus_conn)
		return map_dbus_conn;

	map_dbus_conn = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &err);
	if (!map_dbus_conn) {
		if (err) {
			ERR("Unable to connect to dbus: %s", err->message);
			g_clear_error(&err);
		}
		return NULL;
	}

	FN_END;
	return map_dbus_conn;
}

gboolean is_mns_connected(void)
{
	if (!g_mns_proxy)
		return FALSE;
	else
		return TRUE;
}

guint64 _bt_validate_uid(int uid, int msg_type)
{
	FN_START;
	struct id_info *info;
	GSList *list = id_list;

	while (list) {
		info = list->data;

		if (info && info->uid == uid && info->msg_type == msg_type) {
			DBG("UID = %d, MessageType=%d", uid, msg_type);
			return info->map_id;
		}

		list = g_slist_next(list);
	}

	FN_END;
	return 0;
}

guint64 _bt_add_id(int uid, int msg_type)
{
	FN_START;
	static guint64 map_id;
	struct id_info *info;
	guint64 test;

	DBG("Add id: %d, MsgType:%d", uid, msg_type);
	test = _bt_validate_uid(uid, msg_type);
	DBG("test: %llx\n", test);
	if (test)
		return test;

	info = g_new0(struct id_info, 1);

	map_id++;

	info->map_id = map_id;
	info->uid = uid;
	info->msg_type = msg_type;
	DBG("map_id = %llx, uid = %d, MsgType=%d", info->map_id, info->uid, msg_type);

	id_list = g_slist_append(id_list, info);

	FN_END;
	return map_id;
}

static struct id_info *__bt_get_id(guint64 map_id)
{
	FN_START;
	struct id_info *info;
	GSList *list = id_list;

	while (list) {
		info = list->data;

		if (info->map_id == map_id)
			return info;

		list = g_slist_next(list);
	}

	FN_END;
	return NULL;
}

static struct id_info *__bt_get_uid(gchar *handle)
{
	FN_START;
	guint64 map_id;
	struct id_info *handle_info;

	if (handle == NULL)
		return NULL;

	map_id = g_ascii_strtoull(handle, NULL, 16);
	if (!map_id)
		return NULL;

	handle_info = __bt_get_id(map_id);

	FN_END;
	return handle_info;
}

int _bt_update_id(guint64 map_id, int new_uid, int msg_type)
{
	FN_START;
	struct id_info *info;
	GSList *list = id_list;

	while (list) {
		info = list->data;

		if (info->map_id == map_id) {
			info->uid = new_uid;
			info->msg_type = msg_type;
			return map_id;
		}

		list = g_slist_next(list);
	}

	FN_END;
	return -1;
}

static void __bt_remove_list(GSList *id_list)
{
	FN_START;
	if (!id_list)
		return;

	DBG("Removing id list\n");
	g_slist_free_full(id_list, g_free);
	FN_END;
}

gboolean _bt_verify_sender(message_info_t *msg_info, char *sender)
{
	if (!sender)
		return TRUE;

	if (!g_strcmp0(sender, "*"))
		return TRUE;

	if (g_strrstr(msg_info->sender_name, sender) ||
			g_strrstr(msg_info->sender_addressing, sender))
		return TRUE;

	return FALSE;
}

gboolean _bt_verify_receiver(message_info_t *msg_info, char *receiver)
{
	if (!receiver)
		return TRUE;

	if (!g_strcmp0(receiver, "*"))
		return TRUE;

	if (g_strrstr(msg_info->recipient_name, receiver) ||
			g_strrstr(msg_info->recipient_addressing, receiver))
		return TRUE;

	return FALSE;
}

gboolean _bt_verify_read_status(message_info_t *msg_info, guint8 read_status)
{
	if (read_status == FILTER_READ_STATUS_ALL ||
			((read_status == FILTER_READ_STATUS_UNREAD) && msg_info->read == FALSE) ||
			((read_status == FILTER_READ_STATUS_READ) && msg_info->read == TRUE))
		return TRUE;

	return FALSE;
}

gboolean _bt_filter_priority(message_info_t *msg_info, guint8 priority)
{
	if (priority == FILTER_PRIORITY_ALL ||
			((priority == FILTER_PRIORITY_HIGH) && msg_info->priority == TRUE) ||
			((priority == FILTER_PRIORITY_LOW) && msg_info->priority == FALSE))
		return TRUE;

	return FALSE;
}

void _get_msg_timestamp(time_t *ltime, char *timestamp)
{
	FN_START;
	struct tm local_time;
	int year;
	int month;

	if (!localtime_r(ltime, &local_time))
		return;

	year = local_time.tm_year + 1900; /* years since 1900 */
	month = local_time.tm_mon + 1; /* months since January */
	snprintf(timestamp, 16, "%04d%02d%02dT%02d%02d%02d", year, month,
					local_time.tm_mday, local_time.tm_hour,
					local_time.tm_min, local_time.tm_sec);

	FN_END;
}

time_t _get_time_t_from_timestamp(char *timestamp)
{
	struct tm local_time;
	int year;
	int month;
	time_t int_time;

	sscanf(timestamp, "%04d%02d%02dT%02d%02d%02d", &year, &month,
			&local_time.tm_mday, &local_time.tm_hour,
			&local_time.tm_min, &local_time.tm_sec);

	local_time.tm_year = year - 1900;
	local_time.tm_mon = month - 1;

	int_time = mktime(&local_time);
	return int_time;
}

gboolean _bt_verify_time(message_info_t *msg_info, map_msg_filter_t *filter)
{
	struct tm local_time = { 0, };
	time_t start;
	time_t end;

	/* Set 19710101T000000 as Start Date */
	local_time.tm_year = 1971 - 1900;
	local_time.tm_mon = 0;
	local_time.tm_mday = 1;
	start = mktime(&local_time);

	/* Set 20380101T000000 as End Date */
	local_time.tm_year = 2038 - 1900;
	local_time.tm_mon = 0;
	local_time.tm_mday = 1;
	end = mktime(&local_time);

	if (filter->period_begin)
		start = _get_time_t_from_timestamp(filter->period_begin);

	if (filter->period_end)
		end = _get_time_t_from_timestamp(filter->period_end);

	if (msg_info->time >= start && msg_info->time <= end)
		return TRUE;

	return FALSE;
}

#define SET_TON_NPI(dest, ton, npi) {	\
	dest = 0x80;			\
	dest |= (ton & 0x07) << 4;	\
	dest |= npi & 0x0F;		\
}

static int __bt_ascii_to_upper(int ch)
{
	return (('a' <= (ch) && (ch) <= 'z') ? ((ch) - ('a'-'A')) : (ch));
}

static int __bt_sms_pack_gsm_code(gchar *p_out, const char *data, int in_len)
{
	FN_START;
	int i;
	int pos;
	int shift = 0;

	for (pos = 0, i = 0; i < in_len; pos++, i++) {
		/* pack the low bits */
		p_out[pos] = data[i] >> shift;

		if (i + 1 < in_len) {
			/* pack the high bits using the low bits
			   of the next character */
			p_out[pos] |= data[i+1] << (7 - shift);

			shift++;

			if (shift == 7) {
				shift = 0;
				i++;
			}
		}
	}

	FN_END;
	return pos;
}

static void __bt_sms_conv_digit_to_bcd(gchar *p_bcd, char *p_digits, int digit_len)
{
	FN_START;
	int i;
	int j;
	int digit;
	unsigned char higher;
	unsigned char lower;

	if (p_bcd == NULL || p_digits == NULL)
		return;

	/* 0123456789 -> 1032547698 */
	for (i = 0, j = 0; i < digit_len; i = i + 2, j++) {
		if (p_digits[i] == '*')
			digit = 0x0A;
		else if (p_digits[i] == '#')
			digit = 0x0B;
		else if (__bt_ascii_to_upper(p_digits[i]) == 'P')
			digit = 0x0C;
		else
			digit = (int) (p_digits[i] - '0');

		lower = digit & 0x0F;

		if (digit_len != i + 1) {
			if (p_digits[i+1] == '*')
				digit = 0x0A;
			else if (p_digits[i+1] == '#')
				digit = 0x0B;
			else if (__bt_ascii_to_upper(p_digits[i+1]) == 'P')
				digit = 0x0C;
			else
				digit = (int) (p_digits[i+1] - '0');

			higher = digit & 0x0F;
		} else {
			higher = 0xFF;
		}

		p_bcd[j] = (higher << 4) | lower;
	}
	FN_END;
}

static int  __bt_sms_encode_addr(gchar *addr_field, char *dial_num,
				int dial_num_len, int ton, int npi)
{
	FN_START;
	int index = 0;

	if (dial_num == NULL || addr_field == NULL)
		return -1;

	if (dial_num[0] == '+') {
		dial_num++;
		dial_num_len--;
		ton = SMS_TON_INTERNATIONAL;
	}

	if (ton != SMS_TON_ALPHA_NUMERIC) {
		/* Origination address length address length */
		addr_field[index++] = (unsigned char)dial_num_len;
	} else {
		addr_field[index] = (unsigned char)
					(((dial_num_len * 7 + 7) / 8) * 2);

		if (((dial_num_len * 7) % 8) <= 4)
			addr_field[index]--;

		index++;
	}

	SET_TON_NPI(addr_field[index], ton, npi);
	index++; /* SET_TON_NPI */

	if (ton != SMS_TON_ALPHA_NUMERIC) {
		__bt_sms_conv_digit_to_bcd(&addr_field[index],
					(char *)dial_num, dial_num_len);

		if (dial_num_len % 2)
			index += (dial_num_len / 2) + 1;
		else
			index += dial_num_len / 2;
	} else {
		index += __bt_sms_pack_gsm_code(&addr_field[index],
						dial_num, (int)dial_num_len);
	}

	FN_END;
	return index;
}

static int __bt_sms_encode_time(gchar *addr_field, time_t *tm)
{
	FN_START;
	int index = 0;
	struct tm ltime;
	int year;
	int month;

	if (!localtime_r(tm, &ltime))
		return index;

	year = ltime.tm_year + 1900; /* years since 1900 */
	year = year % 100;
	month = ltime.tm_mon + 1; /* months since January */

	addr_field[index++] = ((year % 10)  << 4) + (year / 10);
	addr_field[index++] = ((month % 10) << 4) + (month / 10);
	addr_field[index++] = ((ltime.tm_mday % 10) << 4) +
							(ltime.tm_mday / 10);
	addr_field[index++] = ((ltime.tm_hour % 10) << 4) +
							(ltime.tm_hour / 10);
	addr_field[index++] = ((ltime.tm_min % 10) << 4) + (ltime.tm_min / 10);
	addr_field[index++] = ((ltime.tm_sec % 10) << 4) + (ltime.tm_sec / 10);
	addr_field[index] = 0x00;

	FN_END;
	return index;
}

gchar *__bt_get_sms_pdu_from_msg_data(gchar *number,
						char *msg, time_t tm,
						int *msg_pdu_len)
{
	FN_START;
	gchar packet[TAPI_NETTEXT_MSG_SIZE_MAX] = {0,};
	int index = 0;

	packet[index] = 0x00; /* Since SCA is unknown for stored messages */
	index++;

	/* TP-MTI : Type of message */
	packet[index] = 0x00;	/* SMS-DELIVER PDU */

	/* TP-MMS bit is set to 1 as we support only SMS */
	packet[index] |= 0x04;
	index++;

	/* TP-OA : Mobile originating address */
	index += __bt_sms_encode_addr(packet+index,
					number, strlen(number),
					g_sca_info->Ton, g_sca_info->Npi);

	/* TP-PID : Since we use only SMS so set to 0 */
	packet[index++] = 0x00;

	/* TP-DCS : Data Coding Scheme, default value set */
	packet[index++] = 0x00;

	/* TP-SCTS : Message timestamp */
	index += __bt_sms_encode_time(packet+index, &tm);
	index++;
	/* TP-UDL : Message body length */
	packet[index++] = strlen(msg);

	/* TP-UD : Message body */
	index += __bt_sms_pack_gsm_code(packet + index, msg, strlen(msg));

	*msg_pdu_len = index;

	FN_END;
	return g_memdup(packet, index);
}

static void __bt_get_sms_sca(TapiHandle *handle, int result, void *data,
							void *user_data)
{
	FN_START;
	TelSmsAddressInfo_t *scaInfo = data;

	DBG("__bt_get_sms_sca 0x%x", result);

	if (data == NULL) {
		g_sca_info = g_malloc0(sizeof(TelSmsAddressInfo_t));
		g_sca_info->Ton = 0;
		g_sca_info->Npi = 0;
		g_sca_info->DialNumLen = 0;
		return;
	}

	g_sca_info = g_malloc0(sizeof(TelSmsAddressInfo_t));
	g_sca_info->Ton = scaInfo->Ton;
	g_sca_info->Npi = scaInfo->Npi;
	g_sca_info->DialNumLen = scaInfo->DialNumLen;
	FN_END;
}

void _bt_message_info_free(gpointer data)
{
	FN_START;
	message_info_t *msg_info = (message_info_t *)data;
	g_free(msg_info->handle);
	g_free(msg_info->subject);
	g_free(msg_info->datetime);
	g_free(msg_info->sender_name);
	g_free(msg_info->sender_addressing);
	g_free(msg_info->replyto_addressing);
	g_free(msg_info->recipient_name);
	g_free(msg_info->recipient_addressing);
	g_free(msg_info->type);
	g_free(msg_info->reception_status);
	g_free(msg_info->size);
	g_free(msg_info->attachment_size);
	g_free(msg_info);
	FN_END;
}

static gboolean __bluetooth_map_start_service()
{
	FN_START;
	gboolean sms;
	gboolean email;

	sms = _bt_map_start_sms_service();
	email = _bt_map_start_email_service();
	if (sms && email)
		return TRUE;

	FN_END;
	return FALSE;
}

static gboolean __bt_validate_utf8(char **text)
{
	FN_START;
	if (g_utf8_validate(*text, -1, NULL))
		return TRUE;

	FN_END;
	return FALSE;
}

gboolean _bt_validate_msg_data(message_info_t *msg_info)
{
	FN_START;
	if (msg_info == NULL)
		return FALSE;

	if (msg_info->subject)
		return __bt_validate_utf8(&msg_info->subject);

	if (msg_info->sender_name)
		return __bt_validate_utf8(&msg_info->sender_name);

	if (msg_info->sender_addressing)
		return __bt_validate_utf8(&msg_info->sender_addressing);

	if (msg_info->replyto_addressing)
		return __bt_validate_utf8(&msg_info->replyto_addressing);

	if (msg_info->recipient_name)
		return __bt_validate_utf8(&msg_info->recipient_name);

	if (msg_info->recipient_addressing)
		return __bt_validate_utf8(&msg_info->recipient_addressing);

	FN_END;
	return TRUE;
}

static void __bt_mns_client_connect(char *address)
{
	FN_START;
	GDBusConnection *connection;
	GVariantBuilder builder;
	GVariant *args;
	GVariant *param;
	GVariant *value;
	GError *error = NULL;
	const char *session_path;

	if (g_mns_proxy) {
		DBG_SECURE("MNS Client already connected to %s", address);
		return;
	}

	connection = __bt_map_get_gdbus_connection();
	if (connection == NULL) {
		DBG("Could not get GDBus Connection");
		return;
	}

	g_mns_proxy = g_dbus_proxy_new_sync(connection,
			G_DBUS_PROXY_FLAGS_NONE, NULL,
			OBEX_CLIENT_SERVICE, OBEX_CLIENT_PATH,
			OBEX_CLIENT_INTERFACE, NULL, &error);

	if (!g_mns_proxy) {
		ERR("Failed to get a proxy for D-Bus");
		return;
	}

	/* Create Hash*/
	g_variant_builder_init(&builder, G_VARIANT_TYPE_ARRAY);
	g_variant_builder_add(&builder, "{sv}", "Target",
					g_variant_new("s", "MNS"));
	args = g_variant_builder_end(&builder);

	param = g_variant_new("(s@a{sv})", address, args);

	value = g_dbus_proxy_call_sync(g_mns_proxy,
			"CreateSession", param, G_DBUS_CALL_FLAGS_NONE, -1,
			NULL, &error);
	if (value == NULL) {
		/* dBUS-RPC is failed */
		ERR("dBUS-RPC is failed");
		if (error != NULL) {
			/* dBUS gives error cause */
			ERR("D-Bus API failure: errCode[%x], message[%s]",
				error->code, error->message);

			g_clear_error(&error);
		}
		g_object_unref(g_mns_proxy);
		g_mns_proxy = NULL;
		return;
	}

	g_variant_get(value, "(&o)", &session_path);
	g_mns_path = g_strdup(session_path);
	DBG("g_mns_path = %s\n", g_mns_path);

	g_variant_unref(value);
	FN_END;
}

static void __bt_mns_client_disconnect()
{
	FN_START;
	GError *error = NULL;
	GVariant *value;

	if (!g_mns_proxy) {
		ERR("No proxy to disconnect");
		return;
	}

	value = g_dbus_proxy_call_sync(g_mns_proxy,
			"RemoveSession", g_variant_new("(o)", g_mns_path),
			G_DBUS_CALL_FLAGS_NONE, -1,
			NULL, &error);

	if (value == NULL) {
		/* dBUS-RPC is failed */
		ERR("dBUS-RPC is failed: Could not remove MAP session");
		if (error != NULL) {
			/* dBUS gives error cause */
			ERR("D-Bus API failure: errCode[%x], message[%s]",
				error->code, error->message);

			g_clear_error(&error);
		}
		return;
	}

	g_free(g_mns_path);
	g_mns_path = NULL;

	g_object_unref(g_mns_proxy);
	g_mns_proxy = NULL;

	g_variant_unref(value);
	FN_END;
}

void _bt_mns_client_event_notify(gchar *event, guint64 handle,
					gchar *folder, gchar *old_folder,
					gchar *msg_type)
{
	FN_START;
	GError *error = NULL;
	GDBusProxy *mns_proxy;
	GDBusConnection *connection = NULL;
	GVariant *value;

	if (!g_mns_proxy) {
		ERR("No client proxy");
		return;
	}

	connection = __bt_map_get_gdbus_connection();
	if (connection == NULL) {
		DBG("Could not get GDBus Connection");
		return;
	}

	mns_proxy = g_dbus_proxy_new_sync(connection,
			G_DBUS_PROXY_FLAGS_NONE, NULL,
			OBEX_CLIENT_SERVICE, g_mns_path,
			MNS_CLIENT_INTERFACE, NULL, &error);
	if (mns_proxy == NULL) {
		ERR("Failed to get a proxy for D-Bus\n");
		return;
	}

	value = g_dbus_proxy_call_sync(mns_proxy, "SendEvent",
			g_variant_new("(stsss)", event, handle, folder, old_folder, msg_type),
			G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (value == NULL) {
		/* dBUS-RPC is failed */
		ERR("dBUS-RPC is failed: SendEvent failed");
		if (error != NULL) {
			/* dBUS gives error cause */
			ERR("D-Bus API failure: errCode[%x], message[%s]",
				error->code, error->message);

			g_clear_error(&error);
		}
		g_object_unref(mns_proxy);
		return;
	}

	g_variant_unref(value);
	g_object_unref(mns_proxy);
	FN_END;
}

static gchar *__bt_get_map_folder(int folder)
{
	switch (folder) {
	case BT_MSG_INBOX:
		return g_strdup("INBOX");
	case BT_MSG_SENT:
		return g_strdup("SENT");
	case BT_MSG_OUTBOX:
		return g_strdup("OUTBOX");
	case BT_MSG_DRAFT:
		return g_strdup("DRAFT");
	case BT_MSG_DELETED:
		return g_strdup("DELETED");
	}
	return NULL;
}

static GList *_bt_map_merge_sorted(GSList *sms_list, GSList *email_list)
{
	GList *list = NULL;
	message_info_t *sms;
	message_info_t *email;

/* **********************Note from glib documentation**************************
 * g_list_append() has to traverse the entire list to find the end, which
 * is inefficient when adding multiple elements. A common idiom to avoid the
 * inefficiency is to use g_list_prepend() and reverse the list with
 * g_list_reverse() when all elements have been added.
 * ***************************************************************************/

	while (sms_list && email_list) {
		sms = sms_list->data;
		email = email_list->data;

		if (sms->time > email->time) {
			list = g_list_prepend(list, sms);
			sms_list = g_slist_next(sms_list);
		} else {
			list = g_list_prepend(list, email);
			email_list = g_slist_next(email_list);
		}
	}

	while (sms_list) {
		sms = sms_list->data;
		list = g_list_prepend(list, sms);
		sms_list = g_slist_next(sms_list);
	}
	while (email_list) {
		email = email_list->data;
		list = g_list_prepend(list, email);
		email_list = g_slist_next(email_list);
	}

	list = g_list_reverse(list);
	return list;
}

static GVariant *__bt_map_get_folder_tree(GError **err)
{
	GVariant *folder_list = NULL;
	GVariantBuilder *builder = g_variant_builder_new(G_VARIANT_TYPE("a(s)"));
	int i;
	gboolean sms_ret = TRUE;
	gboolean email_ret = TRUE;

	sms_ret = _bt_map_sms_get_supported_folders(folders_supported);
	email_ret = _bt_map_email_get_supported_folders(folders_supported);

	if (sms_ret || email_ret) {
		for (i = 0; i < 5; i++) {
			if (folders_supported[i][BT_MSG_SOURCE_SMS] ||
					folders_supported[i][BT_MSG_SOURCE_EMAIL]) {
				g_variant_builder_add(builder, "(s)", __bt_get_map_folder(i));
			}
		}

		folder_list = g_variant_new("(a(s))", builder);
	} else {
		*err = __bt_map_error(BT_MAP_AGENT_ERROR_INTERNAL,
						"InternalError");
	}

	g_variant_builder_unref(builder);
	return folder_list;
}

static GVariant *__bt_map_get_message_list(char *folder_name, guint16 max,
				guint16 offset, guint8 subject_len,
				map_msg_filter_t *filter, GError **err)
{
	FN_START;
	GVariant *message_list = NULL;
	GVariantBuilder *builder = g_variant_builder_new(G_VARIANT_TYPE("a(ssssssssssbsbbbbs)"));
	GSList *sms_list = NULL;
	GSList *email_list = NULL;
	gboolean sms_ret = TRUE;
	gboolean email_ret = TRUE;
	guint64 count = 0;
	guint64 count_sms = 0;
	guint64 count_email = 0;
	gboolean newmsg = FALSE;
	char *folder = NULL;

	DBG("Folder:%s Max:%d", folder_name, max);
	if (!folder_name)
		goto fail;

	/* In case of parent folders send empty message listing */
	/*
	if (g_ascii_strncasecmp(folder_name, "/telecom/msg/", strlen("/telecom/msg/")))
		goto fail;
	 */

	folder = strrchr(folder_name, '/');
	if (NULL == folder)
		folder = folder_name;
	else
		folder++;
	DBG("Filter Type: %d", filter->type);
	if ((filter->type & FILTER_TYPE_SMS_GSM) == 0) { /* Check if SMS is requested */
		if (!g_ascii_strncasecmp(folder, "SENT", strlen("SENT"))) {
			/* Failed Sent SMS are stored in OUTBOX.
			 * Hence, Fetch both SENT and OUTBOX */
			gboolean sent_ret = _bt_map_get_sms_message_list("SENT",
						max + offset, subject_len, filter,
						&sms_list, &count_sms, &newmsg);
			gboolean outbox_ret = _bt_map_get_sms_message_list("OUTBOX",
						max + offset, subject_len, filter,
						&sms_list, &count_sms, &newmsg);
			sms_ret = (sent_ret || outbox_ret);
		} else {
			sms_ret = _bt_map_get_sms_message_list(folder,
					max + offset, subject_len, filter,
					&sms_list, &count_sms, &newmsg);
		}
	}

	if ((filter->type & FILTER_TYPE_EMAIL) == 0) { /* Check if EMAIL is requested */
		email_ret = _bt_map_get_email_list(folder,
				max + offset, subject_len, filter,
				&email_list, &count_email, &newmsg);
	}

	if (sms_ret || email_ret) {
		GList *list = _bt_map_merge_sorted(sms_list, email_list);
		GList *pos = NULL;
		int i;
		message_info_t *msg_info = NULL;

		g_slist_free(sms_list);
		g_slist_free(email_list);

		count = count_sms + count_email;

		pos = g_list_nth(list, offset);
		for (i = offset; pos && i < max + offset; i++) {
			msg_info = pos->data;
			g_variant_builder_add(builder, "(ssssssssssbsbbbbs)",
						msg_info->handle,
						msg_info->subject,
						msg_info->datetime,
						msg_info->sender_name,
						msg_info->sender_addressing,
						msg_info->recipient_name,
						msg_info->recipient_addressing,
						msg_info->type,
						msg_info->size,
						msg_info->reception_status,
						msg_info->text,
						msg_info->attachment_size,
						msg_info->priority,
						msg_info->read,
						msg_info->sent,
						msg_info->protect,
						msg_info->replyto_addressing);

			pos = g_list_next(pos);
		}

		message_list = g_variant_new("(bta(ssssssssssbsbbbbs))",
				newmsg, count, builder);
		g_variant_builder_unref(builder);
		g_list_free_full(list, _bt_message_info_free);

		return message_list;
	}

fail:
	*err = __bt_map_error(BT_MAP_AGENT_ERROR_INTERNAL,
					"InternalError");
	g_variant_builder_unref(builder);
	ERR("fail -");
	return NULL;
}

static GVariant *__bt_map_get_message(char *message_name, gboolean attach,
		gboolean transcode, gboolean first_request, GError **err)
{
	FN_START;
	GVariant *message = NULL;
	int message_id = 0;
	gboolean val_ret;
	gchar *bmseg = NULL;

	struct id_info *handle_info = __bt_get_uid(message_name);
	if (handle_info == NULL)
		return FALSE;

	message_id = handle_info->uid;
	if (handle_info->msg_type == BT_MAP_ID_SMS)
		val_ret = _bt_map_get_sms_message(message_id, attach, transcode, first_request, &bmseg);
	else
		val_ret = _bt_map_get_email_message(message_id, attach, transcode, first_request, &bmseg);

	if (val_ret) {
		message = g_variant_new("(bs)", FALSE, bmseg);
		g_free(bmseg);
		FN_END;
		return message;
	}

	*err = __bt_map_error(BT_MAP_AGENT_ERROR_INTERNAL,
							"InternalError");
	ERR("fail - \n");
	return NULL;
}

static GVariant *__bt_map_push_message(gboolean save_copy, gboolean retry_send,
		gboolean native, char *folder_name, GError **err)
{
	FN_START;
	guint64 handle = 0;

	DBG_SECURE("folder_name = %s\n", folder_name);

	handle = _bt_add_id(-1, BT_MAP_ID_SMS);
	current_push_map_id = handle;
	push_folder = g_strdup(folder_name);

	/* FALSE : Keep messages in Sent folder */
	/* TRUE : don't keep messages in sent folder */
	opt.save_copy = save_copy;
	DBG("opt.save_copy = %d\n", opt.save_copy);

	/* FALSE : don't retry */
	/* TRUE  : retry */
	opt.retry_send = retry_send;
	DBG("opt.retry_send = %d\n", opt.retry_send);

	/* FALSE : native */
	/* TRUE : UTF-8 */
	opt.native = native;
	DBG("opt.native = %d\n", opt.native);

	return g_variant_new("(t)", handle);
	FN_END;
}

static GVariant *__bt_map_push_message_data(char *bmseg, GError **err)
{
	FN_START;
	gboolean ret = FALSE;

	DBG_SECURE("BMSG: %s", bmseg);

	struct bmsg_data *bmsg_info = NULL;

	bmsg_info = bmsg_parse(bmseg);
	if (bmsg_info) {
		if (!g_ascii_strcasecmp(bmsg_info->type, "SMS_GSM"))
			ret = _bt_map_push_sms_data(bmsg_info, &opt, push_folder);
		else if (!g_ascii_strcasecmp(bmsg_info->type, "EMAIL"))
			ret = _bt_map_push_email_data(bmsg_info, &opt, push_folder);

		bmsg_free_bmsg(bmsg_info);
	}

	g_free(push_folder);
	push_folder = NULL;
	if (ret) {
		INFO("Message Successfully Sent or Saved");
		return NULL;
	}

	*err = __bt_map_error(BT_MAP_AGENT_ERROR_INTERNAL,
						"InternalError");
	ERR("Error in sending or saving Message");
	return NULL;
}

/* Dummy Implementation */
static GVariant *__bt_map_update_message(GError **err)
{
	return g_variant_new("(b)", TRUE);
}

static GVariant *__bt_map_set_read_status(char *handle, gboolean read_status, GError **err)
{
	FN_START;
	int msg_id;
	gboolean val_ret;

	struct id_info *handle_info = __bt_get_uid(handle);
	if (handle_info == NULL)
		goto fail;

	msg_id = handle_info->uid;
	DBG("msg_id = %d,  read_status = %d\n", msg_id, read_status);
	if (handle_info->msg_type == BT_MAP_ID_SMS)
		val_ret = _bt_map_sms_set_read_status(msg_id, read_status);
	else
		val_ret = _bt_map_set_email_read_status(msg_id, read_status);

	if (val_ret) {
		FN_END;
		return NULL;
	}

fail:
	*err = __bt_map_error(BT_MAP_AGENT_ERROR_INTERNAL,
							"InternalError");
	ERR("fail -\n");
	return NULL;
}

static GVariant *__bt_map_set_delete_status(char *handle, gboolean delete_status, GError **err)
{
	FN_START;
	int msg_id = 0;
	gboolean val_ret;

	struct id_info *handle_info = __bt_get_uid(handle);
	if (handle_info == NULL)
		goto fail;

	msg_id = handle_info->uid;
	if (handle_info->msg_type == BT_MAP_ID_SMS)
		val_ret = _bt_map_set_sms_delete_status(msg_id, delete_status);
	else
		val_ret = _bt_map_set_email_delete_status(msg_id, delete_status);

	if (val_ret) {
		FN_END;
		return NULL;
	}

fail:
	*err = __bt_map_error(BT_MAP_AGENT_ERROR_INTERNAL,
							"InternalError");
	ERR("fail -\n");
	return NULL;
}

static void __bt_map_noti_registration(char *remote_addr, gboolean status)
{
	FN_START;
	DBG_SECURE("remote_addr = %s \n", remote_addr);

	if (status == TRUE)
		__bt_mns_client_connect(remote_addr);
	else
		__bt_mns_client_disconnect();
}

static void __bt_map_destroy_agent(void)
{
	g_main_loop_quit(g_mainloop);
}

static GDBusNodeInfo *__bt_map_create_method_node_info
					(const gchar *introspection_data)
{
	GError *err = NULL;
	GDBusNodeInfo *node_info = NULL;

	if (introspection_data == NULL)
		return NULL;

	node_info = g_dbus_node_info_new_for_xml(introspection_data, &err);

	if (err) {
		ERR("Unable to create node: %s", err->message);
		g_clear_error(&err);
	}
	return node_info;
}

static gboolean __bt_map_dbus_init(void)
{
	guint owner_id;
	guint map_id;
	GDBusNodeInfo *node_info;
	GError *error = NULL;
	GDBusConnection *gdbus_conn = __bt_map_get_gdbus_connection();

	if (gdbus_conn == NULL) {
		ERR("Error in creating the gdbus connection");
		return FALSE;
	}

	owner_id = g_bus_own_name(G_BUS_TYPE_SESSION,
			BT_MAP_SERVICE_NAME,
			G_BUS_NAME_OWNER_FLAGS_NONE,
			NULL, NULL, NULL,
			NULL, NULL);
	DBG("owner_id is [%d]", owner_id);

	node_info = __bt_map_create_method_node_info(
			map_agent_introspection_xml);
	if (node_info == NULL)
		return FALSE;

	map_id = g_dbus_connection_register_object(gdbus_conn, BT_MAP_SERVICE_OBJECT_PATH,
					node_info->interfaces[0],
					&method_table,
					NULL, NULL, &error);

	g_dbus_node_info_unref(node_info);

	if (map_id == 0) {
		ERR("Failed to register: %s", error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

int main(void)
{
	FN_START;
	int ret;
	DBG("Starting Bluetooth MAP agent");

	//g_type_init();

	g_mainloop = g_main_loop_new(NULL, FALSE);

	if (g_mainloop == NULL) {
		ERR("Couldn't create GMainLoop\n");
		return EXIT_FAILURE;
	}

	if (__bt_map_dbus_init() == FALSE)
		goto failure;

	if (__bluetooth_map_start_service() == FALSE)
		goto failure;

	g_tapi_handle = tel_init(NULL);
	if (!g_tapi_handle)
		goto failure;

	ret = tel_get_sms_sca(g_tapi_handle, 0, __bt_get_sms_sca, NULL);
	if (ret != TAPI_API_SUCCESS) {
		ERR("TAPI err = %d", ret);
		goto failure;
	}

	g_main_loop_run(g_mainloop);

 failure:

	__bt_remove_list(id_list);

	tel_deinit(g_tapi_handle);
	g_free(g_sca_info);

	__bt_mns_client_disconnect();

	if (map_dbus_conn)
		g_object_unref(map_dbus_conn);

	_bt_map_stop_sms_service();
	_bt_map_stop_email_service();

	DBG("Bluetooth MAP agent Terminated successfully\n");
	FN_END;
	return EXIT_FAILURE;
}
