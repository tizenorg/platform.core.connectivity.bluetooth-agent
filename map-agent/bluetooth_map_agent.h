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

#ifndef __DEF_BT_PB_AGENT_H_
#define __DEF_BT_PB_AGENT_H_

#include <unistd.h>
#include <dlog.h>
#include <stdio.h>
#include <glib.h>
#include "bluetooth_map_types.h"

typedef enum {
	BT_MAP_AGENT_ERROR_INTERNAL,
	BT_MAP_AGENT_ERROR_CANCEL,
} bt_map_agent_error_t;

#define BT_MAP_SERVICE_OBJECT_PATH "/org/bluez/map_agent"
#define BT_MAP_SERVICE_NAME "org.bluez.map_agent"
#define BT_MAP_SERVICE_INTERFACE "org.bluez.MapAgent"

#undef LOG_TAG
#define LOG_TAG "BLUETOOTH_AGENT_MAP"
#define INFO(fmt, args...) SLOGI(fmt, ##args)
#define DBG(fmt, args...) SLOGD(fmt, ##args)
#define ERR(fmt, args...) SLOGE(fmt, ##args)

#define DBG_SECURE(fmt, args...) SECURE_SLOGD(fmt, ##args)
#define ERR_SECURE(fmt, args...) SECURE_SLOGE(fmt, ##args)

#define FUCNTION_CALLS
#ifdef FUCNTION_CALLS
#define FN_START	DBG("ENTER==>")
#define FN_END		DBG("EXIT===>")
#else
#define FN_START
#define FN_END
#endif

#define retv_if(expr, val) \
	do { \
		if (expr) { \
			ERR("(%s) return", #expr); \
			return (val); \
		} \
	} while (0)

void _bt_mns_client_event_notify(gchar *event, guint64 handle,
					gchar *folder, gchar *old_folder,
					gchar *msg_type);
int _bt_update_id(guint64 map_id, int new_uid, int msg_type);
gboolean _bt_validate_msg_data(message_info_t *msg_info);
void _bt_message_info_free(gpointer data);
void _get_msg_timestamp(time_t *ltime, char *timestamp);
guint64 _bt_add_id(int uid, int msg_type);
guint64 _bt_validate_uid(int uid, int msg_type);
gboolean is_mns_connected(void);
gchar *__bt_get_sms_pdu_from_msg_data(gchar *number, char *msg, time_t tm,
		int *msg_pdu_len);
gboolean _bt_verify_read_status(message_info_t *msg_info, guint8 read_status);
gboolean _bt_verify_sender(message_info_t *msg_info, char *sender);
gboolean _bt_verify_receiver(message_info_t *msg_info, char *receiver);
gboolean _bt_verify_time(message_info_t *msg_info, map_msg_filter_t *filter);
gboolean _bt_filter_priority(message_info_t *msg_info, guint8 priority);
#endif /* __DEF_BT_AGENT_H_ */
