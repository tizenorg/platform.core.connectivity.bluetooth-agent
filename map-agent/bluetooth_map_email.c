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

#include "email-types.h"
#include "email-api-init.h"
#include "email-api-account.h"
#include "email-api-mailbox.h"
#include "email-api-mail.h"
#include "email-api-network.h"
#include <email-api.h>

#include <bluetooth_map_agent.h>
#include <map_bmessage.h>

#include <glib.h>
#include <gio/gio.h>
#include <stdlib.h>
#ifdef ARCH64
#include <stdint.h>
#endif

#define BT_MAIL_ID_MAX_LENGTH 50
#define BT_MAP_TIMESTAMP_MAX_LEN 16
#define BT_MAIL_TEMP_BODY "/tmp/bt_mail.txt"
#define BT_MAP_MSG_HANDLE_MAX 21
#define BT_EMAIL_STORAGE_INTERFACE "User.Email.StorageChange"
#define BT_EMAIL_STORAGE_PATH "/User/Email/StorageChange"
#define BT_EMAIL_STORAGE_SIGNAL "email"

#define BEGIN_BMSEG "BEGIN:BMSG\r\n"
#define END_BMSEG "END:BMSG\r\n"
#define BMSEG_VERSION "VERSION:1.0\r\n"
#define MSEG_STATUS "STATUS:%s\r\n"
#define MSEG_TYPE "TYPE:%s\r\n"
#define FOLDER_PATH "FOLDER:%s\r\n"
#define EMAIL_VCARD "BEGIN:VCARD\r\nVERSION:2.1\r\nN:%s\r\nEMAIL:%s\r\nEND:VCARD\r\n"
#define BEGIN_BENV "BEGIN:BENV\r\n"
#define END_BENV "END:BENV\r\n"
#define BEGIN_BBODY "BEGIN:BBODY\r\n"
#define END_BBODY "END:BBODY\r\n"
#define ENCODING "ENCODING:%s\r\n"
#define CHARSET "CHARSET:%s\r\n"
#define LANGUAGE "LANGUAGE:%s\r\n"
#define LENGTH "LENGTH:%d\r\n"
#define MSG_BODY "BEGIN:MSG\r\n%s\r\nEND:MSG\r\n"
#define MSG_BODY_BEGIN "BEGIN:MSG\r\n"
#define MSG_BODY_END "\r\nEND:MSG\r\n"

extern guint64 current_push_map_id;

static void __bt_map_parse_moved_mails(char *inbuf, int *from_box_id,
				int *to_box_id, GList **mail_list)
{
	if (!inbuf)
		return;

	DBG("inbuf = %s", inbuf);

	/* notification format: <from_box_id><0x01><to_box_id><0x01><<mail_id><,><mail_id>>*/
	gchar **outer_tok;
	char delimiter[2] = { 0x01, 0x00 };
	outer_tok = g_strsplit_set(inbuf, delimiter, -1);
	if (outer_tok == NULL) {
		ERR("outer_tok == NULL");
		return;
	}
	if (outer_tok[0] && strlen(outer_tok[0]) > 0)
		*from_box_id = atoi(outer_tok[0]);
	if (outer_tok[1] && strlen(outer_tok[1]) > 0)
		*to_box_id = atoi(outer_tok[1]);
	if (outer_tok[2] && strlen(outer_tok[2]) > 0) {
		gchar **inner_tok;
		inner_tok = g_strsplit_set(outer_tok[2], ",", -1);
		if (g_strv_length(inner_tok) == 1) { // only one mail_id exists without ","
			int mail_id = atoi(outer_tok[2]);
#ifdef ARCH64
			*mail_list = g_list_append(*mail_list, (void *)(uintptr_t) mail_id);
#else
			*mail_list = g_list_append(*mail_list, (void *) mail_id);
#endif
		} else {
			int i;
			for (i = 0; i < g_strv_length(inner_tok); ++i) {
				if (!strcmp(inner_tok[i], "\"")) /* skip the empty token */
					continue;
				else {
					int mail_id = atoi(inner_tok[i]);
#ifdef ARCH64
					*mail_list = g_list_prepend(*mail_list, (void *)(uintptr_t) mail_id);
#else
					*mail_list = g_list_prepend(*mail_list, (void *) mail_id);
#endif
				}
			}
		}
		g_strfreev(inner_tok);
	}
	g_strfreev(outer_tok);

	*mail_list = g_list_reverse(*mail_list);
}

char *__bt_email_get_path(int mailboxtype)
{
	switch (mailboxtype) {
	case EMAIL_MAILBOX_TYPE_INBOX:
		return g_strdup("TELECOM/MSG/INBOX");
	case EMAIL_MAILBOX_TYPE_SENTBOX:
		return g_strdup("TELECOM/MSG/SENT");
	case EMAIL_MAILBOX_TYPE_TRASH:
		return g_strdup("TELECOM/MSG/DELETED");
	case EMAIL_MAILBOX_TYPE_DRAFT:
		return g_strdup("TELECOM/MSG/DRAFT");
	case EMAIL_MAILBOX_TYPE_OUTBOX:
		return g_strdup("TELECOM/MSG/OUTBOX");
	}
	return g_strdup("");
}

static void __bt_email_subscription_callback(GDBusConnection *connection,
		const gchar *sender_name, const gchar *object_path,
		const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer data)
{
	int subtype = 0;
	int data1 = 0;
	int data2 = 0;
	char *data3 = NULL;
	int data4 = 0;

	g_variant_get(parameters, "(iii&si)", &subtype, &data1,
			&data2, &data3, &data4);

	if ((g_strcmp0(object_path, BT_EMAIL_STORAGE_PATH)) ||
			(g_strcmp0(signal_name, BT_EMAIL_STORAGE_SIGNAL)))
		return;

	if (subtype == NOTI_MAIL_ADD) {
		/* Received values from Signal*/
		int account_id = data1;
		int mailid = data2;
		int mailbox_id = atoi(data3);
		/* Fetch Values */
		int default_account_id = -1;
		email_mailbox_t *mailbox = NULL;
		guint64 handle;

		DBG("Mail Added[AccountID: %d, MailID:%d, MailBoxID:%d]",
				account_id, mailid, mailbox_id);

		if (email_load_default_account_id(&default_account_id)
						!= EMAIL_ERROR_NONE) {
			ERR("Could not load default account");
			return;
		}
		DBG("Default account_id: %d", default_account_id);
		if (default_account_id != account_id) {
			ERR("Event not meant for default email account");
			return;
		}

		if (email_get_mailbox_by_mailbox_id(mailbox_id,
				&mailbox) != EMAIL_ERROR_NONE) {
			ERR("Could not get mailbox info");
			return;
		}

		handle = _bt_add_id(mailid, BT_MAP_ID_EMAIL);
		if (mailbox) {
			if (mailbox->mailbox_type == EMAIL_MAILBOX_TYPE_INBOX) {
				_bt_mns_client_event_notify("NewMessage", handle,
						"TELECOM/MSG/INBOX", "",
						"EMAIL");
			}
			email_free_mailbox(&mailbox, 1);
		}

	} else if (subtype == NOTI_MAIL_MOVE_FINISH) {
		/* Received values from Signal*/
		/* DATA1[account_id] DATA2[move_type] DATA4[??]
		 * DATA3[mailbox_id0x01updated_value0x01mail_id] */
		int account_id = data1;
		int from_mailbox_id = -1;
		int to_mailbox_id = -1;
		GList *mail_ids = NULL;

		/* Fetch Values */
		int default_account_id = -1;
		email_mailbox_t *mailbox_from = NULL;
		email_mailbox_t *mailbox_to = NULL;
		guint64 handle;

		__bt_map_parse_moved_mails(data3, &from_mailbox_id,
					&to_mailbox_id, &mail_ids);

		DBG("Mail Moved[AccountID:%d From:%d, To:%d]", account_id,
				from_mailbox_id, to_mailbox_id);

		if (email_load_default_account_id(&default_account_id)
						!= EMAIL_ERROR_NONE) {
			ERR("Could not load default account");
			return;
		}
		DBG("Default account_id: %d", default_account_id);
		if (default_account_id != account_id) {
			ERR("Event not meant for default email account");
			return;
		}
		if (email_get_mailbox_by_mailbox_id(from_mailbox_id, &mailbox_from)
							!= EMAIL_ERROR_NONE) {
			ERR("Could not get mailbox info");
			return;
		}
		if (email_get_mailbox_by_mailbox_id(to_mailbox_id, &mailbox_to)
							!= EMAIL_ERROR_NONE) {
			ERR("Could not get mailbox info");
			if (from_mailbox_id)
				email_free_mailbox(&mailbox_from, 1);
			return;
		}

		if (mailbox_to->mailbox_type == EMAIL_MAILBOX_TYPE_TRASH) {
			while (mail_ids) {
#ifdef ARCH64
				int mailid = (int)(uintptr_t)(void*) mail_ids->data;
#else
				int mailid = (int) mail_ids->data;
#endif
				char *old_folder;
				DBG("Mail ID[%d]", mailid);
				if (mailid == 0)
					break;

				old_folder = __bt_email_get_path(mailbox_from->mailbox_type);
				handle = _bt_add_id(mailid, BT_MAP_ID_EMAIL);
				DBG("[MessageDeleted] Handle:%d", handle);
				_bt_mns_client_event_notify("MessageShift", handle,
						"TELECOM/MSG/DELETED", old_folder, "EMAIL");
				g_free(old_folder);
				mail_ids = g_list_next(mail_ids);
			}
		} else if (mailbox_to->mailbox_type == EMAIL_MAILBOX_TYPE_SENTBOX
				&& mailbox_from->mailbox_type == EMAIL_MAILBOX_TYPE_OUTBOX) {
			while (mail_ids) {
#ifdef ARCH64
				int mailid = (int)(uintptr_t)(void*) mail_ids->data;
#else
				int mailid = (int) mail_ids->data;
#endif
				DBG("Mail ID[%d]", mailid);
				if (mailid == 0)
					break;

				handle = _bt_add_id(mailid, BT_MAP_ID_EMAIL);
				DBG("[SendingSuccess] Handle:%d", handle);

				_bt_mns_client_event_notify("MessageShift", handle,
						"TELECOM/MSG/SENT", "TELECOM/MSG/OUTBOX", "EMAIL");

				_bt_mns_client_event_notify("SendingSuccess", handle,
						"TELECOM/MSG/SENT", "", "EMAIL");
				mail_ids = g_list_next(mail_ids);
			}
		}

		email_free_mailbox(&mailbox_to, 1);
		email_free_mailbox(&mailbox_from, 1);
	}
}

gboolean _bt_map_start_email_service(void)
{
	int err;
	GDBusConnection *dbus_conn = NULL;
	GError *error = NULL;
	int signal_handler_storage = -1;
	err = email_service_begin();
	if (err != EMAIL_ERROR_NONE) {
		ERR("email_service_begin fail  error = %d\n", err);
		return FALSE;
	}

	dbus_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (error) {
		ERR("g_bus_get_sync() failed (%s)", error->message);
		g_error_free(error);
		email_service_end();
		return FALSE;
	}

	signal_handler_storage = g_dbus_connection_signal_subscribe(dbus_conn,
			NULL, BT_EMAIL_STORAGE_INTERFACE, BT_EMAIL_STORAGE_SIGNAL,
			BT_EMAIL_STORAGE_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
			__bt_email_subscription_callback, NULL, NULL);

	if (signal_handler_storage == -1) {
		ERR("Failed to g_dbus_connection_signal_subscribe()");
		g_object_unref(dbus_conn);
		email_service_end();
		return FALSE;
	}

	return TRUE;
}

gboolean _bt_map_stop_email_service(void)
{
	int err;

	err = email_service_end();
	if (err != EMAIL_ERROR_NONE) {
		ERR("email_service_end fail  error = %d\n", err);
		return FALSE;
	}

	return TRUE;
}

gboolean _bt_map_email_get_supported_folders(gboolean folders[FOLDER_COUNT][MSG_TYPES])
{
	DBG("");
	int account_id = 0;
	int mailbox_count = 0;
	int err;
	int i;
	email_mailbox_t *mailbox_list = NULL;
	email_mailbox_t *temp = NULL;

	err = email_load_default_account_id(&account_id);
	if (err != EMAIL_ERROR_NONE)
		return FALSE;

	err = email_get_mailbox_list(account_id, EMAIL_MAILBOX_ALL,
				&mailbox_list, &mailbox_count);
	if (err != EMAIL_ERROR_NONE)
		return FALSE;

	DBG("Count: %d", mailbox_count);
	for (i = 0, temp = mailbox_list; i < mailbox_count; i++, temp++) {
		DBG("Folder:%s", temp->mailbox_name);
		if (!g_ascii_strncasecmp(temp->mailbox_name, "SENT", strlen("SENT"))) {
			folders[BT_MSG_SENT][BT_MSG_SOURCE_EMAIL] = TRUE;
			DBG("SENT");
		} else if (!g_ascii_strncasecmp(temp->mailbox_name, "DRAFT", strlen("DRAFT"))) {
			folders[BT_MSG_DRAFT][BT_MSG_SOURCE_EMAIL] = TRUE;
			DBG("DRAFT");
		} else if (!g_ascii_strncasecmp(temp->mailbox_name, "DELETED", strlen("DELETED")) ||
				!g_ascii_strncasecmp(temp->mailbox_name, "TRASH", strlen("TRASH"))) {
			folders[BT_MSG_DELETED][BT_MSG_SOURCE_EMAIL] = TRUE;
			DBG("DELETED");
		} else if (!g_ascii_strncasecmp(temp->mailbox_name, "INBOX", strlen("INBOX"))) {
			folders[BT_MSG_INBOX][BT_MSG_SOURCE_EMAIL] = TRUE;
			DBG("INBOX");
		} else if (!g_ascii_strncasecmp(temp->mailbox_name, "OUTBOX", strlen("OUTBOX"))) {
			folders[BT_MSG_OUTBOX][BT_MSG_SOURCE_EMAIL] = TRUE;
			DBG("OUTBOX");
		} else if (!g_ascii_strncasecmp(temp->mailbox_name, "[gmail]", strlen("[gmail]"))) {
			DBG("GMAIL Folder");
			if (!g_ascii_strncasecmp(temp->mailbox_name, "[Gmail]/Drafts", strlen("[Gmail]/Drafts"))) {
				folders[BT_MSG_DRAFT][BT_MSG_SOURCE_EMAIL] = TRUE;
				DBG("[Gmail]/DRAFT");
			} else if (!g_ascii_strncasecmp(temp->mailbox_name, "[Gmail]/Sent", strlen("[Gmail]/Sent"))) {
				folders[BT_MSG_SENT][BT_MSG_SOURCE_EMAIL] = TRUE;
				DBG("[Gmail]/SENT");
			} else if (!g_ascii_strncasecmp(temp->mailbox_name, "[Gmail]/Trash", strlen("[Gmail]/Trash"))) {
				folders[BT_MSG_DELETED][BT_MSG_SOURCE_EMAIL] = TRUE;
				DBG("[Gmail]/Trash");
			}
		}
	}

	if (mailbox_list != NULL)
		email_free_mailbox(&mailbox_list, mailbox_count);

	return TRUE;
}

static message_info_t *__bt_email_info_get(email_mail_list_item_t *email_struct,
							guint8 subject_len)
{
	message_info_t *email_info = NULL;
	email_mail_data_t *mail_data;
	guint64 uid = 0;
	time_t dptime;
	char email_handle[BT_MAP_MSG_HANDLE_MAX] = {0,};
	char msg_datetime[BT_MAP_TIMESTAMP_MAX_LEN] = {0,};
	email_info = g_new0(message_info_t, 1);

	uid = _bt_add_id(email_struct->mail_id, BT_MAP_ID_EMAIL);
#ifdef ARCH64
	snprintf(email_handle, sizeof(email_handle), "%lx", uid);
#else
	snprintf(email_handle, sizeof(email_handle), "%llx", uid);
#endif
	DBG("******* MAP ID:%d, MailID:%d **********", uid, email_struct->mail_id);
	email_info->handle = g_strdup(email_handle);

	dptime = email_struct->date_time;
	_get_msg_timestamp(&dptime, msg_datetime);

	email_info->sender_name = g_strdup(email_struct->email_address_sender);
	email_info->sender_addressing = g_strdup(email_struct->email_address_sender);
	email_info->recipient_name = g_strdup(email_struct->email_address_recipient);
	email_info->recipient_addressing = g_strdup(email_struct->email_address_recipient);

	email_info->subject = g_strndup(email_struct->subject, subject_len);
	email_info->datetime = g_strdup(msg_datetime);
	email_info->time = dptime; // for sorting
	email_info->type = g_strdup("EMAIL");
	email_info->size = g_strdup_printf("%d", email_struct->mail_size);
	email_info->reception_status = g_strdup("complete");
	email_info->attachment_size = g_strdup("0");
	email_info->replyto_addressing = g_strdup(
			email_struct->email_address_sender);

	DBG("Seen Status: %d", email_struct->flags_seen_field);
	if (email_struct->flags_seen_field)
		email_info->read = TRUE;
	else
		email_info->read = FALSE;

	DBG("Priority: %d", email_struct->priority);
	if (email_struct->priority == EMAIL_MAIL_PRIORITY_HIGH)
		email_info->priority = TRUE;
	else
		email_info->priority = FALSE;

	email_info->text = FALSE;
	email_info->protect = FALSE;

	if (email_get_mail_data(email_struct->mail_id, &mail_data) != EMAIL_ERROR_NONE) {
		ERR("email_get_mail_data failed\n");
		return email_info;
	}

	if (mail_data->alias_sender) {
		g_free(email_info->sender_name);
		email_info->sender_name = g_strdup(mail_data->alias_sender);
	}

	if (mail_data->alias_recipient) {
		g_free(email_info->recipient_name);
		email_info->recipient_name = g_strdup(mail_data->alias_recipient);
	}

	if (mail_data->email_address_recipient) {
		g_free(email_info->recipient_addressing);
		email_info->recipient_addressing = g_strdup(mail_data->email_address_recipient);
	}

	return email_info;
}

static gboolean __bt_map_email_compare_folders(char *alias, char *folder)
{
	DBG("Folder:%s, Alias:%s", folder, alias);

	char *map_folder = NULL;

	if (!g_ascii_strncasecmp(alias, "SENT", strlen("SENT"))) {
		map_folder = "SENT";
	} else if (!g_ascii_strncasecmp(alias, "DRAFT", strlen("DRAFT"))) {
		map_folder = "DRAFT";
	} else if (!g_ascii_strncasecmp(alias, "DELETED", strlen("DELETED")) ||
			!g_ascii_strncasecmp(alias, "TRASH", strlen("TRASH"))) {
		map_folder = "DELETED";
	} else if (!g_ascii_strncasecmp(alias, "INBOX", strlen("INBOX"))) {
		map_folder = "INBOX";
	} else if (!g_ascii_strncasecmp(alias, "OUTBOX", strlen("OUTBOX"))) {
		map_folder = "OUTBOX";
	} else if (!g_ascii_strncasecmp(alias, "[gmail]", strlen("[gmail]"))) {
		DBG("GMAIL Folders");
		if (!g_ascii_strncasecmp(alias, "[Gmail]/Drafts", strlen("[Gmail]/Drafts"))) {
			map_folder = "DRAFT";
		} else if (!g_ascii_strncasecmp(alias, "[Gmail]/Sent", strlen("[Gmail]/Sent"))) {
			map_folder = "SENT";
		} else if (!g_ascii_strncasecmp(alias, "[Gmail]/Trash", strlen("[Gmail]/Trash"))) {
			map_folder = "DELETED";
		}
	}

	DBG("Equivalent MAP Folder for Alias: %s", map_folder);
	if (map_folder && g_ascii_strcasecmp(map_folder, folder) == 0)
		return TRUE;

	return FALSE;
}

gboolean _bt_map_get_email_list(char *folder, int max,
		guint8 subject_len, map_msg_filter_t *filter,
		GSList **email_list, guint64 *count, gboolean *newmsg)
{
	DBG("");
	int i;
	int ret;
	int total = 0;
	int account_id = 0;
	int mailbox_count = 0;
	int mail_count = 0;
	int msg_count = 0;
	char *type = NULL;

	email_mailbox_t *mailbox_list = NULL;
	email_mail_list_item_t *mail_list = NULL;
	email_mail_list_item_t *temp = NULL;
	email_list_filter_t *filter_list = NULL;
	email_list_sorting_rule_t *sorting_rule_list = NULL;
	GSList *list = NULL;

	if (max == 0)
		max = 1024;

	ret = email_load_default_account_id(&account_id);
	if (ret != EMAIL_ERROR_NONE)
		return FALSE;
	DBG("Account ID:%d", account_id);

	ret = email_get_mailbox_list(account_id, EMAIL_MAILBOX_ALL,
					&mailbox_list, &mailbox_count);
	if (ret != EMAIL_ERROR_NONE || mailbox_list == NULL)
		return FALSE;

	for (i = 0; i < mailbox_count; i++) {
		DBG("mailbox alias = %s \n", mailbox_list[i].alias);
		/* Optimize using mailbox_type */
		if (__bt_map_email_compare_folders(mailbox_list[i].mailbox_name, folder)) {
			total = mailbox_list[i].total_mail_count_on_server;
			DBG("Total mail on sever:%d\n", total);
			DBG("mailbox name:%s\n", mailbox_list[i].mailbox_name);
			DBG("mailbox ID:%d\n", mailbox_list[i].mailbox_id);
			break;
		}
	}
	DBG("");
	if (total == 0) {
		email_free_mailbox(&mailbox_list, mailbox_count);
		return FALSE;
	}
	DBG("");
	filter_list = g_new0(email_list_filter_t, 3);
	filter_list[0].list_filter_item_type = EMAIL_LIST_FILTER_ITEM_RULE;
	filter_list[0].list_filter_item.rule.target_attribute = EMAIL_MAIL_ATTRIBUTE_ACCOUNT_ID;
	filter_list[0].list_filter_item.rule.rule_type = EMAIL_LIST_FILTER_RULE_EQUAL;
	filter_list[0].list_filter_item.rule.key_value.integer_type_value = account_id;

	filter_list[1].list_filter_item_type = EMAIL_LIST_FILTER_ITEM_OPERATOR;
	filter_list[1].list_filter_item.operator_type = EMAIL_LIST_FILTER_OPERATOR_AND;

	filter_list[2].list_filter_item_type = EMAIL_LIST_FILTER_ITEM_RULE;
	filter_list[2].list_filter_item.rule.target_attribute = EMAIL_MAIL_ATTRIBUTE_MAILBOX_ID;
	filter_list[2].list_filter_item.rule.rule_type = EMAIL_LIST_FILTER_RULE_EQUAL;
	filter_list[2].list_filter_item.rule.key_value.integer_type_value = mailbox_list[i].mailbox_id;
	DBG("mailbox ID:%d\n", mailbox_list[i].mailbox_id);

	sorting_rule_list = g_new0(email_list_sorting_rule_t, 1);
	sorting_rule_list[0].target_attribute = EMAIL_MAIL_ATTRIBUTE_DATE_TIME;
	sorting_rule_list[0].sort_order = EMAIL_SORT_ORDER_DESCEND;
	sorting_rule_list[0].force_boolean_check = false;

	ret = email_get_mail_list_ex(filter_list, 3, sorting_rule_list, 1, -1,
			-1, &mail_list, &mail_count);
	if (ret != EMAIL_ERROR_NONE) {
		DBG("Error Code:%d", ret);
		g_free(type);
		g_free(filter_list);
		g_free(sorting_rule_list);
		return FALSE;
	}

	DBG("Mail Count: %d", mail_count);
	max = (max > mail_count) ? (mail_count) : max;
	DBG("Max:%d", max);
	for (i = 0, temp = mail_list; i < mail_count && msg_count < max; ++i, temp++) {
		message_info_t *email_info;

		email_info = __bt_email_info_get(temp, subject_len);

		if (!_bt_verify_read_status(email_info, filter->read_status) ||
				!_bt_verify_receiver(email_info, filter->recipient) ||
				!_bt_verify_sender(email_info, filter->originator) ||
				!_bt_verify_time(email_info, filter) ||
				!_bt_filter_priority(email_info, filter->priority) ||
				!_bt_validate_msg_data(email_info)) {
			_bt_message_info_free((gpointer)email_info);
			continue;
		}

		list = g_slist_append(list, email_info);
		msg_count++;
	}

	*count = (guint64)mail_count;
	*email_list = list;

	email_free_mailbox(&mailbox_list, mailbox_count);

	if (mail_list)
		free(mail_list);

	g_free(filter_list);
	g_free(sorting_rule_list);
	g_free(type);
	DBG("EXIT");
	return TRUE;
}

gboolean _bt_map_update_mailbox(char *folder)
{
	int handle;
	int ret;

	ret = email_sync_header_for_all_account(&handle);
	if (ret == EMAIL_ERROR_NONE) {
		DBG("Handle to stop download = %d \n", handle);
	} else {
		ERR("Message Update failed \n");
		return FALSE;
	}

	return TRUE;
}

gboolean _bt_map_set_email_read_status(int mail_id, int read_status)
{
	int ret;
	email_mail_data_t *mail_data = NULL;

	ret = email_get_mail_data(mail_id, &mail_data);
	if (ret != EMAIL_ERROR_NONE) {
		ERR("email_get_mail_data failed\n");
		return FALSE;
	}

	ret = email_set_flags_field(mail_data->account_id, &mail_id, 1,
				EMAIL_FLAGS_SEEN_FIELD, read_status, 0);
	if (ret != EMAIL_ERROR_NONE) {
		email_free_mail_data(&mail_data, 1);
		return FALSE;
	}

	email_free_mail_data(&mail_data, 1);
	return TRUE;
}

gboolean _bt_map_set_email_delete_status(int mail_id, int read_status)
{
	int ret;
	email_mail_data_t *mail_data = NULL;

	ret = email_get_mail_data(mail_id, &mail_data);
	if (ret != EMAIL_ERROR_NONE)
		return FALSE;

	ret = email_delete_mail(mail_data->mailbox_id, &mail_id, 1, 1);
	if (ret != EMAIL_ERROR_NONE) {
		email_free_mail_data(&mail_data, 1);
		return FALSE;
	}

	email_free_mail_data(&mail_data, 1);
	return TRUE;
}

static gchar *__bt_get_email_folder_name(int mailboxtype)
{
	switch (mailboxtype) {
	case EMAIL_MAILBOX_TYPE_SENTBOX:
		return g_strdup("TELECOM/MSG/SENT");
	case EMAIL_MAILBOX_TYPE_TRASH:
		return g_strdup("TELECOM/MSG/DELETED");
	case EMAIL_MAILBOX_TYPE_OUTBOX:
		return g_strdup("TELECOM/MSG/OUTBOX");
	case EMAIL_MAILBOX_TYPE_DRAFT:
		return g_strdup("TELECOM/MSG/DRAFT");
	default:
		return g_strdup("TELECOM/MSG/INBOX");
	}
}

static char *__bt_prepare_email_bmseg(email_mail_data_t *mail_data)
{
	FN_START;
	char *folder = NULL;
	FILE *body_file;
	long read_size;
	long email_size;
	GString *msg;
	char *buf = NULL;

	msg = g_string_new(BEGIN_BMSEG);
	g_string_append(msg, BMSEG_VERSION);

	DBG("Seen Flag: %d", mail_data->flags_seen_field);
	if (mail_data->flags_seen_field)
		g_string_append_printf(msg, MSEG_STATUS, "READ");
	else
		g_string_append_printf(msg, MSEG_STATUS, "UNREAD");

	g_string_append_printf(msg, MSEG_TYPE, "EMAIL");

	folder = __bt_get_email_folder_name(mail_data->mailbox_type);
	g_string_append_printf(msg, FOLDER_PATH, folder);
	g_free(folder);

	/* List of recepient & sender */
	DBG("Sender: %d", mail_data->email_address_sender);
	DBG("Sender Alias: %d", mail_data->alias_sender);
	g_string_append_printf(msg, EMAIL_VCARD, mail_data->email_address_sender,
			mail_data->email_address_sender);

	g_string_append(msg, BEGIN_BENV);
	g_string_append(msg, BEGIN_BBODY);


	g_string_append_printf(msg, CHARSET, "UTF-8");
	g_string_append_printf(msg, ENCODING, "8BIT");
	DBG("Plain Message file: %s", mail_data->file_path_plain);
	DBG("HTML Message file: %s", mail_data->file_path_html);
	body_file = fopen(mail_data->file_path_plain, "r");
	if (body_file == NULL) {
		DBG("NOT PLAIN TEXT MESSAGE");
		body_file = fopen(mail_data->file_path_html, "rb");
	}

	if (body_file != NULL) {
		fseek(body_file, 0, SEEK_END);
		email_size = ftell(body_file);
		rewind(body_file);

		buf = (char *)g_malloc0(sizeof(char) * email_size);
		read_size = fread(buf, 1, email_size, body_file);
		fclose(body_file);
		DBG("MESSAGE: [%s]", buf);
		if (read_size != email_size) {
			ERR("Unequal Read size");
			email_free_mail_data(&mail_data, 1);
			g_string_free(msg, TRUE);
			g_free(buf);
			return NULL;
		}
	} else {
		DBG("BODY of the MESSAGE NOT FOUND");
		buf = (char *)g_strdup("");
	}
#ifdef ARCH64
	g_string_append_printf(msg, LENGTH, (int)(unsigned int)strlen(buf));
#else
	g_string_append_printf(msg, LENGTH, strlen(buf));
#endif
	g_string_append_printf(msg, MSG_BODY, buf);


	g_string_append(msg, END_BBODY);
	g_string_append(msg, END_BENV);
	g_string_append(msg, END_BMSEG);
	g_free(buf);

	FN_END;
	return g_string_free(msg, FALSE);
}

gboolean _bt_map_get_email_message(int mail_id, gboolean attach,
		gboolean transcode, gboolean first_request, gchar **bmseg)
{
	DBG("ENTER==>");
	int account_id;
	int ret;
	email_mail_data_t *mail_data = NULL;

	ret = email_load_default_account_id(&account_id);
	if (ret != EMAIL_ERROR_NONE)
		return FALSE;

	ret = email_get_mail_data(mail_id, &mail_data);
	if (ret != EMAIL_ERROR_NONE)
		return FALSE;

	*bmseg = __bt_prepare_email_bmseg(mail_data);

	email_free_mail_data(&mail_data, 1);
	DBG("EXIT==>");
	return TRUE;
}

static int __bt_map_save_email_to_outbox(char *subject, char *body,
		char *recepients)
{
	int type =  EMAIL_MAILBOX_TYPE_OUTBOX;
	int account_id;
	int mail_id = -1;
	int ret;
	struct stat st_buf;
	FILE *body_file;

	email_account_t *account_data = NULL;
	email_mailbox_t *mailbox_data = NULL;
	email_mail_data_t *mail_data = NULL;

	DBG("email_mailbox_type_e :%d", type);
	DBG("Subject: %s", subject);
	DBG("Body: %s", body);
	DBG("Recepients: %s", recepients);

	ret = email_load_default_account_id(&account_id);
	if (ret != EMAIL_ERROR_NONE)
		goto fail;

	DBG("account_id %d", account_id);
	ret = email_get_mailbox_by_mailbox_type(account_id, type,
			&mailbox_data);
	if (ret != EMAIL_ERROR_NONE)
		goto fail;

	ret = email_get_account(account_id, EMAIL_ACC_GET_OPT_FULL_DATA,
			&account_data);
	if (ret != EMAIL_ERROR_NONE)
		goto fail;

	mail_data = calloc(1, sizeof(email_mail_data_t));
	if (mail_data == NULL) {
		ERR("Allocation Failed");
		goto fail;
	}

	mail_data->account_id = account_id;
	mail_data->save_status = EMAIL_MAIL_STATUS_SEND_DELAYED;
	mail_data->body_download_status = 1;
	mail_data->flags_seen_field = 1;
	mail_data->report_status = EMAIL_MAIL_REQUEST_DSN |
						EMAIL_MAIL_REQUEST_MDN;
	mail_data->remaining_resend_times = 3;
	mail_data->file_path_plain = g_strdup(BT_MAIL_TEMP_BODY);
	mail_data->subject = g_strdup(subject);
	mail_data->full_address_to = g_strdup(recepients);

	/* Get Sender Address  from Account data*/
	mail_data->full_address_from = g_strdup(account_data->user_email_address);

	/* Get MailboxID and Type from mailbox data */
	mail_data->mailbox_id = mailbox_data->mailbox_id;
	mail_data->mailbox_type = mailbox_data->mailbox_type;

	/* Save Body to a File */
	body_file = fopen(BT_MAIL_TEMP_BODY, "w");
	if (body_file == NULL) {
		ERR("fopen [%s]failed", BT_MAIL_TEMP_BODY);
		goto fail;
	}

	ret = fprintf(body_file, "%s", body);
	fflush(body_file);
	fclose(body_file);

	/* Save Email */
	ret = email_add_mail(mail_data, NULL, 0, NULL, 0);
	if (ret != EMAIL_ERROR_NONE) {
		DBG("email_add_mail failed. [%d]\n", ret);
		if (!stat(mail_data->file_path_plain, &st_buf))
			remove(mail_data->file_path_plain);

		goto fail;
	}

	DBG("saved mail id = [%d]\n", mail_data->mail_id);
	mail_id = mail_data->mail_id;

fail:
	if (mailbox_data)
		email_free_mailbox(&mailbox_data, 1);
	if (account_data)
		email_free_account(&account_data, 1);
	if (mail_data)
		email_free_mail_data(&mail_data, 1);

	return mail_id;
}

static int __bt_map_save_email_to_draft(char *subject,
						char *body, char *recepients)
{
	int type =  EMAIL_MAILBOX_TYPE_DRAFT;
	int account_id;
	int mail_id = -1;
	int ret;
	struct stat st_buf;
	FILE *body_file;

	email_account_t *account_data = NULL;
	email_mailbox_t *mailbox_data = NULL;
	email_mail_data_t *mail_data = NULL;

	DBG("email_mailbox_type_e :%d", type);
	DBG("Subject: %s", subject);
	DBG("Body: %s", body);
	DBG("Recepients: %s", recepients);

	ret = email_load_default_account_id(&account_id);
	if (ret != EMAIL_ERROR_NONE)
		goto fail;

	DBG("account_id %d", account_id);
	ret = email_get_mailbox_by_mailbox_type(account_id, type,
						&mailbox_data);
	if (ret != EMAIL_ERROR_NONE)
		goto fail;

	ret = email_get_account(account_id, EMAIL_ACC_GET_OPT_FULL_DATA,
			&account_data);
	if (ret != EMAIL_ERROR_NONE)
		goto fail;

	mail_data = calloc(1, sizeof(email_mail_data_t));
	if (mail_data == NULL) {
		ERR("Allocation Failed");
		goto fail;
	}

	mail_data->account_id = account_id;
	mail_data->body_download_status = 1;
	mail_data->flags_seen_field = 1;
	mail_data->flags_draft_field = 1;
	mail_data->report_status = EMAIL_MAIL_REPORT_NONE;
	mail_data->remaining_resend_times = -1;
	mail_data->subject = g_strdup(subject);
	mail_data->full_address_to = g_strdup(recepients);

	/* Get Sender Address  from Account data*/
	mail_data->full_address_from = g_strdup(account_data->user_email_address);
	email_free_account(&account_data, 1);

	/* Get MailboxID and Type from mailbox data */
	mail_data->mailbox_id = mailbox_data->mailbox_id;
	mail_data->mailbox_type = mailbox_data->mailbox_type;
	email_free_mailbox(&mailbox_data, 1);

	/* Save Body to a File */
	mail_data->file_path_plain = g_strdup(BT_MAIL_TEMP_BODY);

	body_file = fopen(BT_MAIL_TEMP_BODY, "w");
	if (body_file == NULL) {
		ERR("fopen [%s]failed", BT_MAIL_TEMP_BODY);
		goto fail;
	}

	ret = fprintf(body_file, "%s", body);
	fflush(body_file);
	fclose(body_file);

	/* Save Email */
	ret = email_add_mail(mail_data, NULL, 0, NULL, 0);
	if (ret != EMAIL_ERROR_NONE) {
		DBG("email_add_mail failed. [%d]\n", ret);
		if (!stat(mail_data->file_path_plain, &st_buf))
			remove(mail_data->file_path_plain);

		goto fail;
	}

	DBG("saved mail id = [%d]\n", mail_data->mail_id);
	mail_id = mail_data->mail_id;

fail:
	if (mailbox_data)
		email_free_mailbox(&mailbox_data, 1);
	if (account_data)
		email_free_account(&account_data, 1);
	if (mail_data)
		email_free_mail_data(&mail_data, 1);

	return mail_id;
}

static int __bt_map_send_email(char *subject, char *body,
		char *recepients, gboolean send)
{
	int ret;
	int mail_id = -1;
	int handle;

	if (send) {
		DBG("Send Mail");
		mail_id = __bt_map_save_email_to_outbox(subject,
					body, recepients);
		if (mail_id) {
			DBG("mail_id = %d\n", mail_id);
			ret = email_send_mail(mail_id, &handle);
			if (ret != EMAIL_ERROR_NONE)
				DBG("Sending failed[%d]\n", ret);
		}

	} else {
		DBG("Save to Draft");
		mail_id = __bt_map_save_email_to_draft(subject,
					body, recepients);
	}

	return mail_id;
}

static char *__bt_map_get_email_address(GSList *recepients)
{
	GString *mailto = NULL;

	while (recepients) {
		char *address = recepients->data;
		DBG("Email: %s", address);
		if (email_verify_email_address(address) == EMAIL_ERROR_NONE) {
			if (mailto == NULL) {
				mailto = g_string_new(address);
			} else {
				g_string_append(mailto, "; ");
				g_string_append(mailto, address);
			}
		}
		recepients = g_slist_next(recepients);
	}

	return g_string_free(mailto, FALSE);
}

gboolean _bt_map_push_email_data(struct bmsg_data *bmsg_info,
		msg_send_option_t *option, char *folder)
{
	FN_START;
	int id = -1;
	char *message = NULL;
	char *body = NULL;
	char *subject = NULL;
	GSList *recepients = NULL;
	gboolean send = FALSE;
	char *mailto = NULL;

	DBG("Length of Folder String: %d", strlen(bmsg_info->folder));
	if (strlen(bmsg_info->folder) == 0) {
		DBG("No Folder Info. Default to OUTBOX");
		bmsg_info->folder = g_strdup(folder);
	}

	DBG("FOLDER: %s", bmsg_info->folder);
	if (!g_ascii_strcasecmp(bmsg_info->folder, "OUTBOX") ||
			!g_ascii_strcasecmp(bmsg_info->folder, "TELECOM/MSG/OUTBOX"))
		send = TRUE;

	message = bmsg_get_msg_body(bmsg_info, option->native);
	if (message == NULL)
		goto done;
	DBG_SECURE("Message: %s", message);

	if (!bmsg_parse_msg_body(message, &body, &subject))
		goto done;
	DBG_SECURE("SUBJECT: %s", subject);
	DBG_SECURE("BODY: %s", body);

	recepients = bmsg_get_msg_recepients(bmsg_info, BT_MAP_ID_EMAIL);

	mailto = __bt_map_get_email_address(recepients);
	DBG("Email IDs: %s", mailto);

	/* TODO : Write logic to Get Subject from bmessage
	 */

	id = __bt_map_send_email(subject, body, mailto, send);
	if (id == -1)
		goto done;

	_bt_update_id(current_push_map_id, id, BT_MAP_ID_EMAIL);

done:
	g_free(body);
	g_free(subject);
	g_free(message);
	g_slist_free(recepients);

	if (id == -1) {
		FN_END;
		return FALSE;
	}

	return TRUE;
}
