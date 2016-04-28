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

#include <bluetooth_map_agent.h>
#include <map_bmessage.h>

/*Messaging Header Files*/
#include "msg.h"
#include "msg_storage.h"
#include "msg_storage_types.h"
#include "msg_transport.h"
#include "msg_transport_types.h"
#include "msg_types.h"

#include <glib.h>

#define BT_MAP_STATUS_CB "sent status callback"
#define BT_MAP_MSG_CB "sms message callback"
#define BT_MAP_DELETED_FOLDER_NAME "DELETED"
#define BT_MAP_SENT_FOLDER_NAME "SENT"
#define BT_MAP_MSG_TEMPLATE "TEMPLATE"

#define BT_MAP_MSG_INFO_MAX 256
#define BT_MAP_MSG_HANDLE_MAX 21
#define BT_MAP_TIMESTAMP_MAX_LEN 16
#define BT_MAP_MSG_BODY_MAX 1024

#define BEGIN_BMSEG "BEGIN:BMSG\r\n"
#define END_BMSEG "END:BMSG\r\n"
#define BMSEG_VERSION "VERSION:1.0\r\n"
#define MSEG_STATUS "STATUS:%s\r\n"
#define MSEG_TYPE "TYPE:%s\r\n"
#define FOLDER_PATH "FOLDER:%s\r\n"
#define VCARD "BEGIN:VCARD\r\nVERSION:2.1\r\nN:%s\r\nTEL:%s\r\nEND:VCARD\r\n"
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

static msg_handle_t g_msg_handle = NULL;
extern guint64 current_push_map_id;

static int __bt_get_sms_folder_id(char *folder_path)
{
	FN_START;
	int folder_id = -1;
	int i;
	char *folder;
	msg_struct_list_s folder_list = {0,};
	msg_error_t err;
	msg_struct_t p_folder;
	DBG_SECURE("folder_path %s\n", folder_path);

	folder = strrchr(folder_path, '/');
	if (NULL == folder)
		folder = folder_path;
	else
		folder++;

	err = msg_get_folder_list(g_msg_handle, &folder_list);
	if (err != MSG_SUCCESS)
		goto done;

	for (i = 0; i < folder_list.nCount; i++) {
		char folder_name[BT_MAP_MSG_INFO_MAX] = {0, };

		p_folder = folder_list.msg_struct_info[i];

		err = msg_get_str_value(p_folder, MSG_FOLDER_INFO_NAME_STR,
					folder_name, BT_MAP_MSG_INFO_MAX);
		if (err != MSG_SUCCESS)
			continue;

		DBG_SECURE("folder_name %s\n", folder_name);
		if (!g_ascii_strncasecmp(folder_name, folder, strlen(folder))) {
			err = msg_get_int_value(p_folder,
					MSG_FOLDER_INFO_ID_INT,
					&folder_id);
			if (err != MSG_SUCCESS)
				goto done;

			DBG("folder_id %d", folder_id);
			break;
		}
	}

done:
	if (folder_list.msg_struct_info)
		msg_release_list_struct(&folder_list);

	FN_END;
	return folder_id;

}


static void __bt_add_deleted_folder(void)
{
	FN_START;
	msg_error_t err;
	msg_struct_t folder_info = msg_create_struct(MSG_STRUCT_FOLDER_INFO);

	err = msg_set_int_value(folder_info, MSG_FOLDER_INFO_TYPE_INT,
						MSG_FOLDER_TYPE_USER_DEF);
	if (err != MSG_SUCCESS) {
		ERR("Failed adding type %d", err);
		msg_release_struct(&folder_info);
		return;
	}

	err = msg_set_str_value(folder_info, MSG_FOLDER_INFO_NAME_STR,
					"DELETED", MAX_FOLDER_NAME_SIZE);
	if (err != MSG_SUCCESS) {
		ERR("Failed adding str %d", err);
		msg_release_struct(&folder_info);
		return;
	}

	err = msg_add_folder(g_msg_handle, folder_info);
	if (err != MSG_SUCCESS) {
		ERR("Failed adding folder %d", err);
		msg_release_struct(&folder_info);
		return;
	}

	msg_release_struct(&folder_info);
	FN_END;
}

static void __bluetooth_map_msg_incoming_status_cb(msg_handle_t handle,
							msg_struct_t msg,
							void *user_param)
{
	FN_START;
	int msg_id = 0;
	int msg_type = 0;
	int ret;

	guint64 uid;

	if (is_mns_connected() == FALSE) {
		INFO("MNS Client not connected");
		return;
	}

	ret = msg_get_int_value(msg, MSG_MESSAGE_TYPE_INT, &msg_type);
	if (ret != MSG_SUCCESS)
		return;

	if (msg_type != MSG_TYPE_SMS) {
		INFO("Not a SMS");
		return;
	}

	ret = msg_get_int_value(msg, MSG_MESSAGE_ID_INT, &msg_id);
	if (ret != MSG_SUCCESS)
		return;

	uid = _bt_add_id(msg_id, BT_MAP_ID_SMS);

	_bt_mns_client_event_notify("NewMessage", uid,
						"TELECOM/MSG/INBOX", "",
						"SMS_GSM");

	FN_END;
}

static void __bluetooth_map_msg_sent_status_cb(msg_handle_t handle,
							msg_struct_t msg,
							void *user_param)
{
	FN_START;
	int ret;
	int status;

	if (is_mns_connected() == FALSE) {
		INFO("MNS Client not connected");
		return;
	}

	ret = msg_get_int_value(msg, MSG_SENT_STATUS_NETWORK_STATUS_INT,
								&status);
	if (ret != MSG_SUCCESS)
		return;

	if (status == MSG_NETWORK_SEND_SUCCESS) {
		INFO("MSG SENT SUCCESS !!! ");
		_bt_mns_client_event_notify("MessageShift",
					current_push_map_id,
					"TELECOM/MSG/SENT",
					"TELECOM/MSG/OUTBOX",
					"SMS_GSM");

		_bt_mns_client_event_notify("SendingSuccess",
					current_push_map_id,
					"TELECOM/MSG/SENT", "",
					"SMS_GSM");
	} else {
		ERR("MSG SENT FAIL !!! [%d]", status);
		_bt_mns_client_event_notify("SendingFailure",
					current_push_map_id,
					"TELECOM/MSG/OUTBOX", "",
					"SMS_GSM");
	}

	FN_END;
}

gboolean _bt_map_sms_get_supported_folders(gboolean folders[FOLDER_COUNT][MSG_TYPES])
{
	FN_START;
	char folder_name[BT_MAP_MSG_INFO_MAX] = {0,};
	int i;
	int ret;
	gboolean msg_ret = TRUE;

	msg_struct_list_s folder_list = {0,};
	msg_struct_t p_folder;

	if (g_msg_handle == NULL) {
		msg_ret = FALSE;
		goto done;
	}

	if (msg_get_folder_list(g_msg_handle, &folder_list) != MSG_SUCCESS) {
		msg_ret = FALSE;
		goto done;
	}

	for (i = 0; i < folder_list.nCount; i++) {
		p_folder = folder_list.msg_struct_info[i];
		memset(folder_name, 0x00, BT_MAP_MSG_INFO_MAX);

		ret = msg_get_str_value(p_folder, MSG_FOLDER_INFO_NAME_STR,
					folder_name, BT_MAP_MSG_INFO_MAX);
		if (ret != MSG_SUCCESS)
			continue;

		DBG("%d. %s", i, folder_name);
		if (g_strstr_len(folder_name, -1, BT_MAP_MSG_TEMPLATE) ||
				g_strstr_len(folder_name, -1, "CBMSGBOX") ||
				g_strstr_len(folder_name, -1, "SPAMBOX"))
			continue;

		if (!g_ascii_strncasecmp(folder_name, BT_MAP_SENT_FOLDER_NAME,
					strlen(BT_MAP_SENT_FOLDER_NAME))) {
			memset(folder_name, 0, sizeof(folder_name));
			g_strlcpy(folder_name, BT_MAP_SENT_FOLDER_NAME,
							sizeof(folder_name));
			folders[BT_MSG_SENT][BT_MSG_SOURCE_SMS] = TRUE;
			DBG("SENT");
		} else if (!g_ascii_strcasecmp(folder_name, "INBOX")) {
			folders[BT_MSG_INBOX][BT_MSG_SOURCE_SMS] = TRUE;
			DBG("INBOX");
		} else if (!g_ascii_strcasecmp(folder_name, "OUTBOX")) {
			folders[BT_MSG_OUTBOX][BT_MSG_SOURCE_SMS] = TRUE;
			DBG("OUTBOX");
		} else if (!g_ascii_strcasecmp(folder_name, "DRAFT")) {
			folders[BT_MSG_DRAFT][BT_MSG_SOURCE_SMS] = TRUE;
			DBG("DRAFT");
		} else if (!g_ascii_strcasecmp(folder_name, "DELETED")) {
			folders[BT_MSG_DELETED][BT_MSG_SOURCE_SMS] = TRUE;
			DBG("DELETED");
		}
	}

done:

	if (folder_list.msg_struct_info)
		msg_release_list_struct(&folder_list);

	FN_END;
	return msg_ret;
}

gboolean _bt_map_sms_set_read_status(int msg_id, gboolean read_status)
{
	FN_START;
	msg_error_t msg_err;

	msg_err = msg_update_read_status(g_msg_handle, msg_id,
							read_status);
	if (msg_err != MSG_SUCCESS) {
		ERR("Failed to Set Read Status");
		return FALSE;

	}
	FN_END;
	return TRUE;
}


static gchar *__bt_get_sms_folder_name(int id)
{
	FN_START;
	int ret;
	int i;
	int folder_id;
	gboolean path_found = FALSE;
	char folder_name[BT_MAP_MSG_INFO_MAX] = {0,};

	msg_struct_list_s folder_list = {0,};
	msg_struct_t p_folder;

	ret = msg_get_folder_list(g_msg_handle, &folder_list);
	if (ret != MSG_SUCCESS)
		return g_strdup("TELECOM/MSG");

	if (folder_list.msg_struct_info == NULL)
		return g_strdup("TELECOM/MSG");

	for (i = 0; i < folder_list.nCount; i++) {
		p_folder = folder_list.msg_struct_info[i];

		ret = msg_get_int_value(p_folder,
					MSG_FOLDER_INFO_ID_INT,
					&folder_id);
		if (ret != MSG_SUCCESS)
			break;
		DBG("folder_id %d, id = %d", folder_id, id);
		if (folder_id == id) {
			ret = msg_get_str_value(p_folder,
					MSG_FOLDER_INFO_NAME_STR,
					folder_name, BT_MAP_MSG_INFO_MAX);
			if (ret != MSG_SUCCESS)
				break;

			path_found = TRUE;
			DBG_SECURE("folder_name %s", folder_name);
			break;
		}
	}

	if (folder_list.msg_struct_info) {
		ret = msg_release_list_struct(&folder_list);
		ERR("Err %d", ret);
	}

	FN_END;
	if (path_found != TRUE)
		return g_strdup("TELECOM/MSG");
	else
		return g_strdup_printf("TELECOM/MSG/%s", folder_name);
}

gboolean _bt_map_set_sms_delete_status(int msg_id, gboolean delete_status)
{
	FN_START;
	int folder_id;
	int del_folder_id;
	int err;
	gchar *folder_name = NULL;
	guint64 map_id;
	msg_struct_t msg = NULL;
	msg_struct_t send_opt = NULL;


	if (msg_id == -1)
		goto fail;

	if (g_msg_handle == NULL)
		goto fail;

	msg = msg_create_struct(MSG_STRUCT_MESSAGE_INFO);
	if (msg == NULL)
		goto fail;

	send_opt = msg_create_struct(MSG_STRUCT_SENDOPT);
	if (send_opt == NULL)
		goto fail;

	err = msg_get_message(g_msg_handle,
					(msg_message_id_t)msg_id,
					msg, send_opt);
	if (err != MSG_SUCCESS)
		goto fail;

	err = msg_get_int_value(msg, MSG_MESSAGE_FOLDER_ID_INT,
							&folder_id);
	if (err != MSG_SUCCESS)
		goto fail;

	folder_name = __bt_get_sms_folder_name(folder_id);
	del_folder_id = __bt_get_sms_folder_id(BT_MAP_DELETED_FOLDER_NAME);
	map_id = _bt_validate_uid(msg_id, BT_MAP_ID_SMS);

	DBG("msg_id = %d, delete_status = %d\n", msg_id, delete_status);

	if (del_folder_id == -1) {
		ERR("Delete folder not present");
		if (delete_status == TRUE) {
			err = msg_delete_message(g_msg_handle, msg_id);
			if (err != MSG_SUCCESS)
				goto fail;
		}
	} else {
		if (delete_status == TRUE) {
			err = msg_move_msg_to_folder(g_msg_handle, msg_id, del_folder_id);
			if (err == MSG_SUCCESS) {
				_bt_mns_client_event_notify("MessageShift",
						map_id,
						"TELECOM/MSG/DELETED",
						folder_name,
						"SMS_GSM");
			}
		} else {
			if (folder_id != del_folder_id) {
				DBG("Message not in delete folder");
				goto fail;
			}

			err = msg_move_msg_to_folder(g_msg_handle, msg_id, MSG_INBOX_ID);
			if (err == MSG_SUCCESS) {
				_bt_mns_client_event_notify("MessageShift",
						map_id,
						"TELECOM/MSG/INBOX",
						"TELECOM/MSG/DELETED",
						"SMS_GSM");
			}
		}
	}

	g_free(folder_name);
	msg_release_struct(&msg);
	msg_release_struct(&send_opt);

	FN_END;
	return TRUE;

fail:
	g_free(folder_name);

	msg_release_struct(&msg);
	msg_release_struct(&send_opt);

	ERR("Failed to Delete SMS");
	return FALSE;
}

static msg_error_t __bt_send_sms(int msg_id, msg_struct_t p_msg, msg_struct_t p_send_opt)
{
	FN_START;
	msg_error_t err;
	msg_struct_t p_req;

	p_req = msg_create_struct(MSG_STRUCT_REQUEST_INFO);

	msg_set_int_value(p_msg, MSG_MESSAGE_ID_INT, msg_id);
	msg_set_struct_handle(p_req, MSG_REQUEST_MESSAGE_HND, p_msg);
	msg_set_struct_handle(p_req, MSG_REQUEST_SENDOPT_HND, p_send_opt);

	err = msg_sms_send_message(g_msg_handle, p_req);
	if (err != MSG_SUCCESS)
		ERR("Failed msg_sms_send_message %d", err);

	msg_release_struct(&p_req);
	FN_END;
	return err;
}

static int __bt_push_sms(gboolean send, int folder_id, char *body,
		GSList *recepients, msg_send_option_t *option)
{
	FN_START;
	msg_struct_t msg_info = NULL;
	msg_struct_t send_opt = NULL;
	msg_error_t err;

	int msg_id = -1;

	msg_info = msg_create_struct(MSG_STRUCT_MESSAGE_INFO);
	if (msg_info == NULL)
		goto fail;

	err = msg_set_int_value(msg_info, MSG_MESSAGE_TYPE_INT, MSG_TYPE_SMS);
	if (err != MSG_SUCCESS)
		goto fail;

	if (body) {
		err = msg_set_str_value(msg_info,
					MSG_MESSAGE_SMS_DATA_STR,
					body, strlen(body));
		if (err != MSG_SUCCESS)
			goto fail;
	} else {
		err = msg_set_str_value(msg_info, MSG_MESSAGE_SMS_DATA_STR,
								NULL, 0);
		if (err != MSG_SUCCESS)
			goto fail;
	}

	DBG("folder_id  %d\n", folder_id);
	err = msg_set_int_value(msg_info, MSG_MESSAGE_FOLDER_ID_INT,
								folder_id);
	if (err != MSG_SUCCESS)
		goto fail;

	while (recepients) {
		msg_struct_t tmp_addr;
		char *address = recepients->data;
		if (address == NULL) {
			ERR("[ERROR] address is value NULL, skip");
			recepients = g_slist_next(recepients);
			continue;
		}

		msg_list_add_item(msg_info,
				MSG_MESSAGE_ADDR_LIST_HND, &tmp_addr);

		msg_set_int_value(tmp_addr,
				MSG_ADDRESS_INFO_RECIPIENT_TYPE_INT,
				MSG_RECIPIENTS_TYPE_TO);

		msg_set_str_value(tmp_addr,
				MSG_ADDRESS_INFO_ADDRESS_VALUE_STR,
				address, strlen(address));

		recepients = g_slist_next(recepients);
	}

	send_opt = msg_create_struct(MSG_STRUCT_SENDOPT);

	err = msg_set_bool_value(send_opt, MSG_SEND_OPT_SETTING_BOOL, true);
	if (err != MSG_SUCCESS)
		goto fail;

	/* Do not keep a copy
	err = msg_set_bool_value(send_opt, MSG_SEND_OPT_KEEPCOPY_BOOL,
			option->save_copy);
	*/
	err = msg_set_bool_value(send_opt, MSG_SEND_OPT_KEEPCOPY_BOOL,
			true);
	if (err != MSG_SUCCESS)
		goto fail;

	msg_id = msg_add_message(g_msg_handle, msg_info, send_opt);
	DBG("msg_id = %d\n", msg_id);

	if (send == TRUE)
		__bt_send_sms(msg_id, msg_info, send_opt);


fail:
	msg_release_struct(&msg_info);
	msg_release_struct(&send_opt);
	FN_END;
	return msg_id;
}

gboolean _bt_map_push_sms_data(struct bmsg_data *bmsg_info,
		msg_send_option_t *option, char *folder)
{
	FN_START;
	int id = -1;
	int folder_id;
	char *body = NULL;
	GSList *recepients = NULL;
	gboolean send = FALSE;

	DBG("Length of Folder String: %d", strlen(bmsg_info->folder));
	if (strlen(bmsg_info->folder) == 0) {
		DBG("No Folder Info. Default to OUTBOX");
		bmsg_info->folder = g_strdup(folder);
	}

	folder_id = __bt_get_sms_folder_id(bmsg_info->folder);
	if (folder_id == -1)
		goto done;

	if (folder_id == MSG_OUTBOX_ID)
		send = TRUE;

	body = bmsg_get_msg_body(bmsg_info, option->native);
	if (body == NULL)
		goto done;

	recepients = bmsg_get_msg_recepients(bmsg_info, BT_MAP_ID_SMS);

	id = __bt_push_sms(send, folder_id, body, recepients, option);
	if (id == -1)
		goto done;

	_bt_update_id(current_push_map_id, id, BT_MAP_ID_SMS);

done:
	g_free(body);
	g_slist_free(recepients);

	if (id == -1) {
		FN_END;
		return FALSE;
	}

	FN_END;
	return TRUE;
}


static char *__bt_prepare_msg_bmseg(msg_struct_t msg_info, gboolean attach,
							gboolean transcode)
{
	FN_START;
	int ret;
	int m_type = MSG_TYPE_SMS;
	int folder_id;
	int count;
	int dptime = 0;
	int j;
	bool read_status = false;
	char msg_body[BT_MAP_MSG_BODY_MAX] = {0,};
	char addr_value[MAX_ADDRESS_VAL_LEN] = {0,};
	char name_value[MAX_DISPLAY_NAME_LEN] = {0,};

	msg_list_handle_t addr_list = NULL;
	msg_struct_t addr_info = NULL;

	GString *msg;
	gchar *folder_path = NULL;
	gchar *msg_pdu;

	msg = g_string_new(BEGIN_BMSEG);
	g_string_append(msg, BMSEG_VERSION);

	ret = msg_get_bool_value(msg_info, MSG_MESSAGE_READ_BOOL, &read_status);
	if (ret == MSG_SUCCESS)
		INFO("read_status %d\n", read_status);

	if (read_status)
		g_string_append_printf(msg, MSEG_STATUS, "READ");
	else
		g_string_append_printf(msg, MSEG_STATUS, "UNREAD");

	ret = msg_get_int_value(msg_info, MSG_MESSAGE_TYPE_INT, &m_type);
	if (ret == MSG_SUCCESS) {
		INFO("m_type %d\n", m_type);
		 g_string_append_printf(msg, MSEG_TYPE, "SMS_GSM");
	}

	ret = msg_get_int_value(msg_info, MSG_MESSAGE_FOLDER_ID_INT,
							&folder_id);
	if (ret == MSG_SUCCESS) {
		DBG("folder_id %d\n", folder_id);

		folder_path = __bt_get_sms_folder_name(folder_id);
		g_string_append_printf(msg, FOLDER_PATH, folder_path);
	}

	ret = msg_get_list_handle(msg_info, MSG_MESSAGE_ADDR_LIST_HND,
						(void **)&addr_list);
	if (ret == MSG_SUCCESS) {
		count = msg_list_length(addr_list);
		DBG("count %d \n", count);

		if (count > 0) {
			addr_info = (msg_struct_t)msg_list_nth_data(addr_list,
									0);

			msg_get_str_value(addr_info,
					MSG_ADDRESS_INFO_ADDRESS_VALUE_STR,
					addr_value, MAX_ADDRESS_VAL_LEN);
			DBG_SECURE("addr_value %s\n", addr_value);
			msg_get_str_value(addr_info,
					MSG_ADDRESS_INFO_DISPLAYNAME_STR,
					name_value, MAX_DISPLAY_NAME_LEN);
			if (!strlen(name_value))
				g_stpcpy(name_value, addr_value);

			DBG_SECURE("name_value %s\n", name_value);

			g_string_append_printf(msg, VCARD, name_value,
								addr_value);
		}
	}

	g_string_append(msg, BEGIN_BENV);
	g_string_append(msg, BEGIN_BBODY);

	if (transcode) {
		g_string_append_printf(msg, CHARSET, "UTF-8");


		ret = msg_get_str_value(msg_info,
					MSG_MESSAGE_SMS_DATA_STR,
					msg_body, BT_MAP_MSG_BODY_MAX);
		if (ret == MSG_SUCCESS) {
			g_string_append_printf(msg, LENGTH, strlen(msg_body));
			g_string_append_printf(msg, MSG_BODY, msg_body);
		}
	} else {
		g_string_append_printf(msg, ENCODING, "G-7BIT");
		g_string_append_printf(msg, CHARSET, "native");

		msg_get_int_value(msg_info,
				MSG_MESSAGE_DISPLAY_TIME_INT, &dptime);

		ret = msg_get_str_value(msg_info, MSG_MESSAGE_SMS_DATA_STR,
					msg_body, BT_MAP_MSG_BODY_MAX);
		if (ret == MSG_SUCCESS) {
			int msg_pdu_len = 0;
			msg_pdu = __bt_get_sms_pdu_from_msg_data(addr_value,
							msg_body, dptime,
							&msg_pdu_len);
			if (msg_pdu) {
				DBG("msg_pdu_len = %d", msg_pdu_len);

				g_string_append_printf(msg, LENGTH, msg_pdu_len);
				g_string_append(msg, MSG_BODY_BEGIN);
				for (j = 0; j < msg_pdu_len; j++)
					g_string_append_printf(msg, "%02x",
									msg_pdu[j]);

				g_string_append(msg, MSG_BODY_END);
				g_free(msg_pdu);
			}
		}
	}

	g_string_append(msg, END_BBODY);
	g_string_append(msg, END_BENV);
	g_string_append(msg, END_BMSEG);
	g_free(folder_path);

	FN_END;
	return g_string_free(msg, FALSE);
}

gboolean _bt_map_get_sms_message(int message_id, gboolean attach,
		gboolean transcode, gboolean first_request, gchar **bmseg)
{
	FN_START;
	msg_error_t msg_err;
	msg_struct_t msg = NULL;
	msg_struct_t send_opt = NULL;

	DBG("message_id %d \n", message_id);
	DBG("attach %d \n", attach);
	DBG("transcode %d \n", transcode);
	DBG("first_request %d \n", first_request);

	if (g_msg_handle == NULL)
		goto fail;

	msg = msg_create_struct(MSG_STRUCT_MESSAGE_INFO);
	if (!msg)
		goto fail;

	send_opt = msg_create_struct(MSG_STRUCT_SENDOPT);
	if (!send_opt)
		goto fail;

	msg_err = msg_get_message(g_msg_handle,
					(msg_message_id_t)message_id,
					msg, send_opt);
	if (msg_err != MSG_SUCCESS)
		goto fail;

	*bmseg = __bt_prepare_msg_bmseg(msg, attach, transcode);
	msg_release_struct(&msg);
	msg_release_struct(&send_opt);

	FN_END;
	return TRUE;

fail:

	if (msg)
		msg_release_struct(&msg);

	if (send_opt)
		msg_release_struct(&send_opt);

	ERR("Unable to Get SMS Message");
	return FALSE;
}

static char *__bt_get_truncated_utf8_string(char *src)
{
	FN_START;
	char *p = src;
	char *next;
	char dest[BT_MAP_SUBJECT_MAX_LEN] = {0,};
	int count;
	int i = 0;

	if (src == NULL)
		return NULL;

	while (*p != '\0' && i < sizeof(dest)) {
		next = g_utf8_next_char(p);
		count = next - p;

		while (count > 0 && ((i + count) < sizeof(dest))) {
			dest[i++] = *p;
			p++;
			count --;
		}
		p = next;
	}

	FN_END;
	return g_strdup(dest);
}


static message_info_t *__bt_message_info_get(msg_struct_t msg_struct_handle,
							guint8 subject_len)
{
	FN_START;
	message_info_t *msg_info = NULL;
	int ret;
	int msg_id;
	guint64 uid;
	time_t dptime;
	int m_type = 0;
	int data_size;
	int priority;
	int direction_type;
	int count;
	bool protect_status = 0;
	bool read_status = 0;

	char msg_handle[BT_MAP_MSG_HANDLE_MAX] = {0,};
	char msg_datetime[BT_MAP_TIMESTAMP_MAX_LEN] = {0,};
	char msg_size[5] = {0,};
	char msg_body[BT_MAP_MSG_BODY_MAX] = {0,};
	char addr_value[MAX_ADDRESS_VAL_LEN] = {0,};
	char name_value[MAX_DISPLAY_NAME_LEN] = {0,};

	msg_info = g_new0(message_info_t, 1);
	msg_info->text = FALSE;
	msg_info->protect = FALSE;
	msg_info->read = FALSE;
	msg_info->priority = FALSE;

	msg_struct_t msg = NULL;
	msg_struct_t send_opt = NULL;
	msg_list_handle_t addr_list = NULL;
	msg_struct_t addr_info = NULL;

	ret = msg_get_int_value(msg_struct_handle, MSG_MESSAGE_ID_INT, &msg_id);
	if (ret != MSG_SUCCESS) {
		ERR("Could not get Message ID");
	}

	uid = _bt_add_id(msg_id, BT_MAP_ID_SMS);
	snprintf(msg_handle, sizeof(msg_handle), "%llx", uid);
	DBG("HANDLE: %s, MAP Id: %d, MSG ID:%d", msg_handle, uid, msg_id);
	msg_info->handle = g_strdup(msg_handle);

	msg = msg_create_struct(MSG_STRUCT_MESSAGE_INFO);
	if (msg == NULL)
		goto next;

	send_opt = msg_create_struct(MSG_STRUCT_SENDOPT);
	if (send_opt == NULL)
		goto next;

	ret = msg_get_message(g_msg_handle,
						(msg_message_id_t)msg_id,
						msg, send_opt);
	if (ret != MSG_SUCCESS) {
		DBG("ret = %d\n", ret);
		goto next;
	}

	ret = msg_get_list_handle(msg, MSG_MESSAGE_ADDR_LIST_HND,
							(void **)&addr_list);
	if (ret != MSG_SUCCESS) {
		DBG("ret = %d\n", ret);
		goto next;
	}

	count = msg_list_length(addr_list);

	if (count != 0) {
		addr_info = (msg_struct_t)msg_list_nth_data(addr_list, 0);

		ret = msg_get_str_value(addr_info,
					MSG_ADDRESS_INFO_ADDRESS_VALUE_STR,
					addr_value, MAX_ADDRESS_VAL_LEN);
		if (ret == MSG_SUCCESS)
			DBG_SECURE("addr_value %s\n", addr_value);

		ret = msg_get_str_value(addr_info,
					MSG_ADDRESS_INFO_DISPLAYNAME_STR,
					name_value, MAX_DISPLAY_NAME_LEN);

		if (ret == MSG_SUCCESS)
			DBG_SECURE("name_value %s\n", name_value);

		if (!strlen(name_value))
			g_stpcpy(name_value, addr_value);

		DBG_SECURE("name_value %s\n", name_value);
	}

	ret = msg_get_int_value(msg, MSG_MESSAGE_DIRECTION_INT,
						&direction_type);
	if (ret != MSG_SUCCESS)
		goto next;

	if (direction_type == MSG_DIRECTION_TYPE_MT) {
		msg_info->sender_name = g_strdup(name_value);
		msg_info->sender_addressing = g_strdup(addr_value);
		msg_info->recipient_name = g_strdup("Unknown");
		msg_info->recipient_addressing = g_strdup("0000");
	} else {
		msg_info->sender_name = g_strdup("Unknown");
		msg_info->sender_addressing = g_strdup("0000");
		msg_info->recipient_name = g_strdup(name_value);
		msg_info->recipient_addressing = g_strdup(addr_value);
	}

next:
	msg_release_struct(&msg);
	msg_release_struct(&send_opt);

	ret = msg_get_int_value(msg_struct_handle,
				MSG_MESSAGE_DISPLAY_TIME_INT, &dptime);
	if (ret == MSG_SUCCESS) {
		_get_msg_timestamp(&dptime, msg_datetime);
	}
	DBG("Got date time: %s", msg_datetime);

	msg_info->datetime = g_strdup(msg_datetime);
	msg_info->time = dptime; // for sorting

	ret = msg_get_int_value(msg_struct_handle, MSG_MESSAGE_TYPE_INT,
								&m_type);
	if (ret == MSG_SUCCESS) {
		DBG("m_type %d\n", m_type);
	}

	msg_info->type = g_strdup("SMS_GSM");

	ret = msg_get_str_value(msg_struct_handle,
				MSG_MESSAGE_SMS_DATA_STR, msg_body,
				BT_MAP_MSG_BODY_MAX);
	if (ret == MSG_SUCCESS) {
		DBG_SECURE("SMS subject %s", msg_body);
		if (strlen(msg_body)) {
			char *subject;
			msg_info->text = TRUE;
			subject = __bt_get_truncated_utf8_string(msg_body);
			msg_info->subject = g_strndup(subject, subject_len);
			g_free(subject);
		}
	}

	ret = msg_get_int_value(msg_struct_handle, MSG_MESSAGE_DATA_SIZE_INT,
								&data_size);
	if (ret == MSG_SUCCESS)
		snprintf(msg_size, sizeof(msg_size), "%d", data_size);

	msg_info->size = g_strdup(msg_size);

	msg_info->reception_status = g_strdup("complete");
	msg_info->attachment_size = g_strdup("0");

	ret = msg_get_bool_value(msg_struct_handle, MSG_MESSAGE_PROTECTED_BOOL,
							&protect_status);
	if (ret == MSG_SUCCESS) {
		if (protect_status)
			msg_info->protect = TRUE;
	}

	ret = msg_get_bool_value(msg_struct_handle, MSG_MESSAGE_READ_BOOL,
								&read_status);
	if (ret == MSG_SUCCESS) {
		if (read_status)
			msg_info->read = TRUE;
	}

	ret = msg_get_int_value(msg_struct_handle, MSG_MESSAGE_PRIORITY_INT,
								&priority);
	if (ret == MSG_SUCCESS) {
		if (priority == MSG_MESSAGE_PRIORITY_HIGH)
			msg_info->priority = TRUE;
	}

	FN_END;
	return msg_info;
}

gboolean _bt_map_get_sms_message_list(gchar *folder, guint16 max,
		guint8 subject_len, map_msg_filter_t *filter,
		GSList **sms_list, guint64 *count, gboolean *newmsg)
{
	FN_START;
	int i = 0;
	int ret = 0;
	int folder_id = -1;
	guint64 local_count;
	bool read;

	msg_struct_list_s folder_list = {0,};
	msg_struct_list_s msg_list = {0,};
	msg_struct_t list_cond;
	GSList *list = NULL;
	int msg_count;

	DBG("Folder:%s Max:%d", folder, max);
	if (max == 0)
		max = 1024;

	ret = msg_get_folder_list(g_msg_handle, &folder_list);
	if (ret != MSG_SUCCESS)
		goto fail;

	for (i = 0; i < folder_list.nCount; i++) {
		char f_name[BT_MAP_MSG_INFO_MAX] = {0, };
		msg_struct_t p_folder = folder_list.msg_struct_info[i];

		ret = msg_get_str_value(p_folder, MSG_FOLDER_INFO_NAME_STR,
					f_name, BT_MAP_MSG_INFO_MAX);
		if (ret  != MSG_SUCCESS)
			continue;

		if (!g_ascii_strncasecmp(f_name, folder, strlen(folder))) {
			ret = msg_get_int_value(p_folder, MSG_FOLDER_INFO_ID_INT,
								&folder_id);
			if (ret != MSG_SUCCESS)
				goto fail;

			DBG("folder_id %d \n", folder_id);

			break;
		}
	}

	if (folder_id == -1)
		goto fail;

	list_cond = msg_create_struct(MSG_STRUCT_MSG_LIST_CONDITION);
	ret = msg_set_int_value(list_cond,
				MSG_LIST_CONDITION_FOLDER_ID_INT,
				folder_id);
	if (ret != MSG_SUCCESS)
		goto fail;

	ret = msg_set_int_value(list_cond,
				MSG_LIST_CONDITION_MSGTYPE_INT, MSG_TYPE_SMS);
	if (ret != MSG_SUCCESS)
		goto fail;

	ret = msg_get_message_list2(g_msg_handle, list_cond, &msg_list);

	msg_release_struct(&list_cond);

	if (ret != MSG_SUCCESS)
		goto fail;

	local_count = (guint64)msg_list.nCount;
	DBG("msg_list.nCount: %d, count:%d", msg_list.nCount, local_count);
	for (i = 0; i < local_count; i++) {
		msg_get_bool_value(msg_list.msg_struct_info[i],
					MSG_MESSAGE_READ_BOOL, &read);
		if (read == false) {
			*newmsg = TRUE;
			break;
		}
	}

	DBG("count = %llx, newmsg = %d, max = %d", local_count, *newmsg, max);

	for (i = 0, msg_count = 0; i < local_count && msg_count < max; i++) {
		message_info_t *msg_info;

		msg_info = __bt_message_info_get(msg_list.msg_struct_info[i],
								subject_len);

		if (!_bt_verify_read_status(msg_info, filter->read_status) ||
				!_bt_verify_receiver(msg_info, filter->recipient) ||
				!_bt_verify_sender(msg_info, filter->originator) ||
				!_bt_verify_time(msg_info, filter) ||
				!_bt_filter_priority(msg_info, filter->priority) ||
				!_bt_validate_msg_data(msg_info)) {
			_bt_message_info_free((gpointer)msg_info);
			continue;
		}

		list = g_slist_append(list, msg_info);
		msg_count++;
	}

	if (folder_list.msg_struct_info)
		ret = msg_release_list_struct(&folder_list);

	if (msg_list.msg_struct_info)
		ret = msg_release_list_struct(&msg_list);

	*count = local_count;
	*sms_list = list;
	FN_END;
	return TRUE;

fail:
	if (folder_list.msg_struct_info)
		ret = msg_release_list_struct(&folder_list);

	if (msg_list.msg_struct_info)
		ret = msg_release_list_struct(&msg_list);

	ERR("Getting SMS List Failed");
	return FALSE;
}

void _bt_map_stop_sms_service(void)
{
	FN_START;
	msg_error_t err =  MSG_SUCCESS;
	int folder_id;

	folder_id = __bt_get_sms_folder_id(BT_MAP_DELETED_FOLDER_NAME);
	if (folder_id != -1) {
		err = msg_delete_folder(g_msg_handle, folder_id);
		if (err != MSG_SUCCESS)
			ERR("Delete folder failed");
	}

	if (g_msg_handle) {
		msg_close_msg_handle(&g_msg_handle);
		g_msg_handle = NULL;
	}

	FN_END;
}

gboolean _bt_map_start_sms_service(void)
{
	FN_START;
	msg_error_t err;

	err = msg_open_msg_handle(&g_msg_handle);
	if (err != MSG_SUCCESS) {
		ERR("msg_open_msg_handle error = %d\n", err);
		return FALSE;
	}

	if (__bt_get_sms_folder_id(BT_MAP_DELETED_FOLDER_NAME) == -1)
		__bt_add_deleted_folder();

	err = msg_reg_sms_message_callback(g_msg_handle,
					__bluetooth_map_msg_incoming_status_cb,
					0, (void *)BT_MAP_MSG_CB);
	if (err != MSG_SUCCESS) {
		ERR("msg_reg_sms_message_callback error  = %d\n", err);
		return FALSE;
	}

	err = msg_reg_sent_status_callback(g_msg_handle,
					__bluetooth_map_msg_sent_status_cb,
					NULL);
	if (err != MSG_SUCCESS) {
		ERR("msg_reg_sent_status_callback error  = %d\n", err);
		return FALSE;
	}

	FN_END;
	return TRUE;
}
