/*
 * Bluetooth-agent
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Syam Sidhardhan <s.syam@samsung.com>
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

#ifndef BLUETOOTH_MAP_TYPES_H_
#define BLUETOOTH_MAP_TYPES_H_

#define FOLDER_COUNT 5 /* INBOX, OUTBOX, SENT, DRAFT, DELETED*/
#define MSG_TYPES 2 /* GSM_SMS, EMAIL*/
#define BT_MAP_SUBJECT_MAX_LEN 50

#define FILTER_TYPE_SMS_GSM		0x01
#define FILTER_TYPE_SMS_CDMA	0x02
#define FILTER_TYPE_EMAIL		0x04
#define FILTER_TYPE_MMS			0x08

#define FILTER_READ_STATUS_ALL		0x00
#define FILTER_READ_STATUS_UNREAD	0x01
#define FILTER_READ_STATUS_READ		0x02

#define FILTER_PRIORITY_ALL		0x00
#define FILTER_PRIORITY_HIGH	0x01
#define FILTER_PRIORITY_LOW		0x02

typedef struct  {
	char *handle;
	char *subject;
	char *datetime;
	char *sender_name;
	char *sender_addressing;
	char *recipient_name;
	char *recipient_addressing;
	char *type;
	char *size;
	char *reception_status;
	char *attachment_size;
	char *replyto_addressing;
	gboolean text;
	gboolean priority;
	gboolean read;
	gboolean sent;
	gboolean protect;
	time_t time; /* for sorting */
} message_info_t;

typedef enum {
	BT_MSG_INBOX = 0,
	BT_MSG_SENT,
	BT_MSG_OUTBOX,
	BT_MSG_DRAFT,
	BT_MSG_DELETED
} folders_t;

typedef enum {
	BT_MSG_SOURCE_SMS = 0,
	BT_MSG_SOURCE_EMAIL
} source_t;

typedef enum {
	BT_MAP_ID_SMS,
	BT_MAP_ID_EMAIL
} bt_msg_t;

typedef struct {
	gboolean save_copy;
	gboolean retry_send;
	gboolean native;
} msg_send_option_t;


typedef struct {
	guint32 parameter_mask;
	guint8 type;
	char *period_begin;
	char *period_end;
	guint8 read_status;
	char *recipient;
	char *originator;
	guint8 priority;
} map_msg_filter_t;
#endif /* BLUETOOTH_MAP_TYPES_H_ */
