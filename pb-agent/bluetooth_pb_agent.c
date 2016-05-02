/*
 * Bluetooth-agent
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
 *		 Jaekyun Lee <jkyun.leek@samsung.com>
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
#include <signal.h>
#include <glib.h>
#include <gio/gio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <contacts.h>
#include <TapiUtility.h>
#include <ITapiSim.h>

#include "bluetooth_pb_agent.h"
#include "bluetooth_pb_vcard.h"

#define BLUETOOTH_PB_AGENT_TIMEOUT 600

typedef struct {
	TapiHandle *tapi_handle;
	gchar *tel_number;
	guint timeout_id;
	PhoneBookType pb_type;
	guint pbagent_interface_id;
	guint pbagent_at_interface_id;
} PbAgentData;

static gchar *bluetooth_pb_agent_folder_list[] = {
	"/telecom/pb",
	"/telecom/ich",
	"/telecom/och",
	"/telecom/mch",
	"/telecom/cch",
#ifdef PBAP_SIM_ENABLE
	"/SIM1/telecom/pb",
#endif
	NULL
};

static guint total_missed_call_count = 0;
static guint unnotified_missed_call_count = 0;

GMainLoop *g_mainloop;
static GDBusConnection *pb_dbus_conn = NULL;

static const gchar pb_agent_introspection_xml[] =
"<node name='/'>"
	"<interface name='org.bluez.PbAgent'>"
		"<method name='GetPhonebookFolderList'>"
			"<arg type='as' name='folder_list' direction='out'/>"
		"</method>"

		"<method name='GetPhonebook'>"
			"<arg type='s' name='name'/>"
			"<arg type='t' name='filter'/>"
			"<arg type='y' name='format'/>"
			"<arg type='q' name='max_list_count'/>"
			"<arg type='q' name='list_start_offset'/>"
			"<arg type='as' name='phonebook' direction='out'/>"
			"<arg type='u' name='new_missed_call' direction='out'/>"
		"</method>"

		"<method name='GetPhonebookSize'>"
			"<arg type='s' name='name'/>"
			"<arg type='u' name='phonebook_size' direction='out'/>"
			"<arg type='u' name='new_missed_call' direction='out'/>"
		"</method>"

		"<method name='GetPhonebookList'>"
			"<arg type='s' name='name'/>"
			"<arg type='a(ssu)' name='phonebook_list' direction='out'/>"
			"<arg type='u' name='new_missed_call' direction='out'/>"
		"</method>"

		"<method name='GetPhonebookEntry'>"
			"<arg type='s' name='folder'/>"
			"<arg type='s' name='id'/>"
			"<arg type='t' name='filter'/>"
			"<arg type='y' name='format'/>"
			"<arg type='s' name='phonebook_entry' direction='out'/>"
		"</method>"

		"<method name='GetTotalObjectCount'>"
			"<arg type='s' name='path'/>"
			"<arg type='u' name='phonebook_size' direction='out'/>"
		"</method>"

		"<method name='AddContact'>"
			"<arg type='s' name='filename'/>"
		"</method>"

		"<method name='DestroyAgent'>"
		"</method>"
	"</interface>"

	"<interface name='org.bluez.PbAgent.At'>"
		"<method name='GetPhonebookSizeAt'>"
			"<arg type='s' name='command'/>"
			"<arg type='u' name='phonebook_size' direction='out'/>"
		"</method>"

		"<method name='GetPhonebookEntriesAt'>"
			"<arg type='s' name='command'/>"
			"<arg type='i' name='start_index'/>"
			"<arg type='i' name='end_index'/>"
			"<arg type='a(ssu)' name='phonebook_entries' direction='out'/>"
		"</method>"

		"<method name='GetPhonebookEntriesFindAt'>"
			"<arg type='s' name='command'/>"
			"<arg type='s' name='find_text' />"
			"<arg type='a(ssu)' name='phonebook_entries' direction='out'/>"
		"</method>"
	"</interface>"
"</node>";

static void __bt_pb_agent_method(GDBusConnection *connection,
			const gchar *sender, const gchar *object_path,
			const gchar *interface_name, const gchar *method_name,
			GVariant *parameters, GDBusMethodInvocation *invocation,
			gpointer user_data);

static GVariant *__bt_pb_get_phonebook_folder_list(GError **error);

static GVariant *__bt_pb_get_phonebook(PbAgentData *agent, const char *name,
			guint64 filter, guint8 format, guint16 max_list_count,
			guint16 list_start_offset, GError **err);

static GVariant *__bt_pb_get_phonebook_size(PbAgentData *agent,
					const char *name, GError **err);

static GVariant *__bt_pb_get_phonebook_list(PbAgentData *agent,
					const char *name, GError **err);

static GVariant *__bt_pb_get_phonebook_entry(PbAgentData *agent,
			const gchar *folder, const gchar *id, guint64 filter,
			guint8 format, GError **err);

static GVariant *__bt_pb_get_phonebook_size_at(PbAgentData *agent,
					const gchar *command, GError **err);

static GVariant *__bt_pb_get_phonebook_entries_at(PbAgentData *agent,
			const gchar *command, gint32 start_index,
			gint32 end_index, GError **err);

static GVariant *__bt_pb_get_phonebook_entries_find_at(PbAgentData *agent,
				const gchar *command, const gchar *find_text,
				GError **err);

static GVariant *__bt_pb_get_total_object_count(PbAgentData *agent,
					gchar *path, GError **err);

static gboolean __bt_pb_add_contact(PbAgentData *agent, const char *filename,
					GError **error);

static gboolean __bt_pb_destroy_agent();

static GError *__bt_pb_error(gint error_code, const gchar *error_message);

static PhoneBookType __bluetooth_pb_get_pb_type(const char *name);

static PhoneBookType __bluetooth_pb_get_storage_pb_type(const char *name);

static gint __bluetooth_pb_phone_log_filter_append(contacts_filter_h filter,
						gint *match, gint size);

static contacts_query_h __bluetooth_pb_query_phone_log(gint *match, gint size);

static contacts_query_h __bluetooth_pb_query_person(int addressbook);

static contacts_query_h __bluetooth_pb_query_person_number(void);

static contacts_query_h __bluetooth_pb_query_phone_log_incoming(void);

static contacts_query_h __bluetooth_pb_query_phone_log_outgoing(void);

static contacts_query_h __bluetooth_pb_query_phone_log_missed(void);

static contacts_query_h __bluetooth_pb_query_phone_log_combined(void);

static gboolean __bluetooth_pb_get_count(PhoneBookType pb_type, guint *count);

static gboolean __bluetooth_pb_get_count_new_missed_call(guint *count);

static const char *__bluetooth_pb_phone_log_get_log_type(contacts_record_h record);

static void __bluetooth_pb_get_vcards(PbAgentData *agent, PhoneBookType pb_type,
			guint64 filter, guint8 format, guint16 max_list_count,
			guint16 list_start_offset, GVariantBuilder *vcards);

static void __bluetooth_pb_get_contact_list(PbAgentData *agent,
			contacts_query_h query, GVariantBuilder *builder);

static void __bluetooth_pb_get_phone_log_list(PbAgentData *agent,
			contacts_query_h query, GVariantBuilder *builder);

static void __bluetooth_pb_get_list(PbAgentData *agent, PhoneBookType pb_type,
				GVariantBuilder *builder);

static void __bluetooth_pb_get_contact_list_number(PbAgentData *agent,
				contacts_query_h query, gint start_index,
				gint end_index, GVariantBuilder *builder);

static void __bluetooth_pb_get_phone_log_list_number(PbAgentData *agent,
				contacts_query_h query, gint start_index,
				gint end_index, GVariantBuilder *builder);

static void __bluetooth_pb_get_list_number(PbAgentData *agent,
				PhoneBookType pb_type, gint start_index,
				gint end_index, GVariantBuilder *builder);

static void __bluetooth_pb_get_contact_list_name(PbAgentData *agent,
				contacts_query_h query, const gchar *find_text,
				GVariantBuilder *builder);

static void __bluetooth_pb_get_phone_log_list_name(PbAgentData *agent,
				contacts_query_h query, const gchar *find_text,
				GVariantBuilder *builder);

static void __bluetooth_pb_get_list_name(PbAgentData *agent,
				PhoneBookType pb_type, const gchar *find_text,
				GVariantBuilder *builder);

static void __bluetooth_pb_list_ptr_array_add(GVariantBuilder *builder,
			const gchar *name, const gchar *number, gint handle);

static void __bluetooth_pb_agent_signal_handler(int signum);

static void __bluetooth_pb_contact_changed(const gchar *view_uri,
					void *user_data);

static void __bluetooth_pb_agent_timeout_add_seconds(PbAgentData *agent);

static gboolean __bluetooth_pb_agent_timeout_calback(gpointer user_data);

static void __bluetooth_pb_tel_callback(TapiHandle *handle, int result,
					void *data, void *user_data);

static gboolean __bt_pb_dbus_init(PbAgentData *agent);

static gboolean __bt_pb_dbus_deinit(PbAgentData *agent);

static const GDBusInterfaceVTable method_table = {
	__bt_pb_agent_method,
	NULL,
	NULL,
};

static void __bt_pb_agent_method(GDBusConnection *connection,
			const gchar *sender, const gchar *object_path,
			const gchar *interface_name, const gchar *method_name,
			GVariant *parameters, GDBusMethodInvocation *invocation,
			gpointer user_data)
{
	FN_START;
	INFO("method: %s; object_path: %s", method_name, object_path);
	PbAgentData *agent = (PbAgentData *)user_data;
	GError *err = NULL;
	if (g_strcmp0(interface_name, "org.bluez.PbAgent") == 0) {
		if (g_strcmp0(method_name, "GetPhonebookFolderList") == 0) {
			GVariant *folder_list = NULL;

			folder_list = __bt_pb_get_phonebook_folder_list(&err);
			if (err)
				goto fail;
			g_dbus_method_invocation_return_value(invocation,
								folder_list);
		} else if (g_strcmp0(method_name, "GetPhonebook") == 0) {
			GVariant *phonebook = NULL;
			const char *name;
			guint64 filter;
			guint8 format;
			guint16 max_list_count;
			guint16 list_start_offset;

			g_variant_get(parameters, "(&styqq)", &name, &filter,
						&format, &max_list_count,
						&list_start_offset);
			phonebook = __bt_pb_get_phonebook(agent, name, filter,
						format, max_list_count,
						list_start_offset, &err);
			if (err)
				goto fail;
			g_dbus_method_invocation_return_value(invocation,
								phonebook);
		} else if (g_strcmp0(method_name, "GetPhonebookSize") == 0) {
			GVariant *phonebook_size = NULL;
			const char *name;

			g_variant_get(parameters, "(&s)", &name);
			phonebook_size = __bt_pb_get_phonebook_size(agent, name,
									&err);
			if (err)
				goto fail;
			g_dbus_method_invocation_return_value(invocation,
								phonebook_size);
		} else if (g_strcmp0(method_name, "GetPhonebookList") == 0) {
			GVariant *phonebook_list = NULL;
			const char *name;

			g_variant_get(parameters, "(&s)", &name);
			phonebook_list = __bt_pb_get_phonebook_list(agent, name,
									&err);
			if (err)
				goto fail;
			g_dbus_method_invocation_return_value(invocation,
								phonebook_list);
		} else if (g_strcmp0(method_name, "GetPhonebookEntry") == 0) {
			GVariant *phonebook_entry = NULL;
			const gchar *folder;
			const gchar *id;
			guint64 filter;
			guint8 format;

			g_variant_get(parameters, "(&s&sty)", &folder, &id,
							&filter, &format);
			phonebook_entry = __bt_pb_get_phonebook_entry(agent,
						folder, id, filter, format, &err);
			if (err)
				goto fail;
			g_dbus_method_invocation_return_value(invocation,
							phonebook_entry);
		} else if (g_strcmp0(method_name, "GetTotalObjectCount") == 0) {
			GVariant *phonebook_size = NULL;
			gchar *path;

			g_variant_get(parameters, "(&s)", &path);
			phonebook_size = __bt_pb_get_total_object_count(agent,
								path, &err);
			if (err)
				goto fail;
			g_dbus_method_invocation_return_value(invocation,
								phonebook_size);
		} else if (g_strcmp0(method_name, "AddContact") == 0) {
			const char *filename;

			g_variant_get(parameters, "(&s)", &filename);
			__bt_pb_add_contact(agent, filename, &err);
			if (err)
				goto fail;
			g_dbus_method_invocation_return_value(invocation, NULL);
		} else if (g_strcmp0(method_name, "DestroyAgent") == 0) {
			g_dbus_method_invocation_return_value(invocation, NULL);
			__bt_pb_destroy_agent();
		}
	} else if (g_strcmp0(interface_name, "org.bluez.PbAgent.At") == 0) {
		if (g_strcmp0(method_name, "GetPhonebookSizeAt") == 0) {
			GVariant *phonebook_size = NULL;
			const gchar *command;

			g_variant_get(parameters, "(&s)", &command);
			phonebook_size = __bt_pb_get_phonebook_size_at(agent,
								command, &err);
			if (err)
				goto fail;
			g_dbus_method_invocation_return_value(invocation,
								phonebook_size);
		} else if (g_strcmp0(method_name,
					"GetPhonebookEntriesAt") == 0) {
			GVariant *phonebook_entries = NULL;
			const gchar *command;
			gint32 start_index;
			gint32 end_index;

			g_variant_get(parameters, "(&sii)",
					&command, &start_index, &end_index);
			phonebook_entries = __bt_pb_get_phonebook_entries_at(agent,
							command, start_index,
							end_index, &err);
			if (err)
				goto fail;
			g_dbus_method_invocation_return_value(invocation,
							phonebook_entries);
		} else if (g_strcmp0(method_name,
					"GetPhonebookEntriesFindAt") == 0) {
			GVariant *phonebook_entries = NULL;
			const gchar *command;
			const gchar *find_text;

			g_variant_get(parameters, "(&s&s)", &command, &find_text);
			phonebook_entries = __bt_pb_get_phonebook_entries_find_at(agent,
							command, find_text, &err);
			if (err)
				goto fail;
			g_dbus_method_invocation_return_value(invocation,
							phonebook_entries);
		}
	}

	FN_END;
	return;

fail:
	g_dbus_method_invocation_return_gerror(invocation, err);
	g_clear_error(&err);
	FN_END;
	return;
}

static void bluetooth_pb_agent_clear(PbAgentData *agent)
{
	FN_START;
	agent->pb_type = TELECOM_NONE;
	FN_END;
}

static GDBusConnection *__bt_pb_get_gdbus_connection(void)
{
	FN_START;
	GError *err = NULL;

	if (pb_dbus_conn)
		return pb_dbus_conn;

	pb_dbus_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
	if (!pb_dbus_conn) {
		if (err) {
			ERR("Unable to connect to dbus: %s", err->message);
			g_clear_error(&err);
		}
		return NULL;
	}
	FN_END;
	return pb_dbus_conn;
}

static GVariant *__bt_pb_get_phonebook_folder_list(GError **error)
{
	FN_START;
	GVariant *folder_list;
	gint size;
	gint i;
	GVariantBuilder *builder = g_variant_builder_new(G_VARIANT_TYPE("as"));

	size = G_N_ELEMENTS(bluetooth_pb_agent_folder_list);

	for (i = 0; i < size; i++)
		g_variant_builder_add(builder, "s",
					bluetooth_pb_agent_folder_list[i]);

	folder_list = g_variant_new("(as)", builder);
	g_variant_builder_unref(builder);

	FN_END;
	return folder_list;
}


static GVariant *__bt_pb_get_phonebook(PbAgentData *agent, const char *name,
			guint64 filter, guint8 format, guint16 max_list_count,
			guint16 list_start_offset, GError **err)
{
	FN_START;
	GVariant *phonebook;
	PhoneBookType pb_type = TELECOM_NONE;
	GVariantBuilder *vcards = g_variant_builder_new(G_VARIANT_TYPE("as"));

	INFO("name: %s filter: %lld format: %d max_list_count: %d list_start_offset: %d\n",
			name, filter, format, max_list_count, list_start_offset);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_pb_type(name);

	if (pb_type == TELECOM_NONE) {
		*err = __bt_pb_error(G_FILE_ERROR_INVAL,
						"unsupported name defined");
		return NULL;
	}

	if (max_list_count > 0) {
		__bluetooth_pb_get_vcards(agent, pb_type, filter, format,
				max_list_count, list_start_offset, vcards);
	}

	if (pb_type == TELECOM_MCH) {
		phonebook = g_variant_new("(asu)", vcards,
						unnotified_missed_call_count);
		INFO("Notified [%d] missed call count",
						unnotified_missed_call_count);
		unnotified_missed_call_count = 0;
	} else {
		phonebook = g_variant_new("(asu)", vcards, 0);
	}

	g_variant_builder_unref(vcards);

	FN_END;
	return phonebook;
}

static GVariant *__bt_pb_get_phonebook_size(PbAgentData *agent,
						const char *name, GError **err)
{
	FN_START;
	GVariant *phonebook_size;
	PhoneBookType pb_type = TELECOM_NONE;
	guint count = 0;

	DBG_SECURE("name: %s\n", name);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_pb_type(name);

	if (__bluetooth_pb_get_count(pb_type, &count) == FALSE) {
		*err = __bt_pb_error(G_FILE_ERROR_INVAL,
						"unsupported name defined");
		return NULL;
	}

	/* for owner */
#ifdef PBAP_SIM_ENABLE
	if (pb_type == TELECOM_PB || pb_type == SIM_PB)
		count++;
#else
	if (pb_type == TELECOM_PB)
		count++;
#endif
	if (pb_type == TELECOM_MCH) {
		phonebook_size = g_variant_new("(uu)", count,
						unnotified_missed_call_count);
		INFO("Notified [%d] missed call count",
						unnotified_missed_call_count);
		unnotified_missed_call_count = 0;
	} else {
		phonebook_size = g_variant_new("(uu)", count, 0);
	}

	FN_END;
	return phonebook_size;
}


static GVariant *__bt_pb_get_phonebook_list(PbAgentData *agent,
						const char *name, GError **err)
{
	FN_START;
	GVariant *phonebook_list;
	PhoneBookType pb_type = TELECOM_NONE;

	GVariantBuilder *builder = g_variant_builder_new(G_VARIANT_TYPE("a(ssu)"));

	DBG_SECURE("name: %s\n", name);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_pb_type(name);

	if (pb_type == TELECOM_NONE) {
		*err = __bt_pb_error(G_FILE_ERROR_INVAL,
						"unsupported name defined");
		return NULL;
	}

	__bluetooth_pb_get_list(agent, pb_type, builder);

	INFO("pb_type[%d] / number of missed_call[%d]", pb_type,
						unnotified_missed_call_count);

	if (pb_type == TELECOM_MCH) {
		phonebook_list = g_variant_new("(a(ssu)u)", builder,
						unnotified_missed_call_count);
		INFO("Notified [%d] missed call count",
						unnotified_missed_call_count);
		unnotified_missed_call_count = 0;
	} else {
		phonebook_list = g_variant_new("(a(ssu)u)", builder, 0);
	}

	if (builder)
		g_variant_builder_unref(builder);

	FN_END;
	return phonebook_list;
}

static GVariant *__bt_pb_get_phonebook_entry(PbAgentData *agent,
			const gchar *folder, const gchar *id, guint64 filter,
			guint8 format, GError **err)
{
	FN_START;
	GVariant *phonebook_entry;
	PhoneBookType pb_type = TELECOM_NONE;
	gint handle = 0;
	gchar *str = NULL;
	const gchar *attr = NULL;

	DBG_SECURE("folder: %s id: %s filter: %ld format: %d\n",
			folder, id, filter, format);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	if (!g_str_has_suffix(id, ".vcf")) {
		*err = __bt_pb_error(G_FILE_ERROR_INVAL, "invalid vcf file");
		return NULL;
	}

	handle = (gint)g_ascii_strtoll(id, NULL, 10);

	pb_type = __bluetooth_pb_get_pb_type(folder);

	if (pb_type == TELECOM_NONE) {
		*err = __bt_pb_error(G_FILE_ERROR_INVAL,
						"unsupported name defined");
		return NULL;
	}

	/* create index cache */
	__bluetooth_pb_get_list(agent, pb_type, NULL);

	switch (pb_type) {
	case TELECOM_PB:
		if (handle == 0) {
			str = _bluetooth_pb_vcard_contact_owner(agent->tel_number,
								filter, format);
		} else {
			if (_bluetooth_get_contact_addressbook(handle) == PBAP_ADDRESSBOOK_PHONE)
				str = _bluetooth_pb_vcard_contact(handle,
								filter, format);
		}
		break;

	case TELECOM_ICH:
		str = _bluetooth_pb_vcard_call(handle, filter, format,
								"RECEIVED");
		break;
	case TELECOM_OCH:
		str = _bluetooth_pb_vcard_call(handle, filter, format, "DIALED");
		break;
	case TELECOM_MCH:
		str = _bluetooth_pb_vcard_call(handle, filter, format, "MISSED");
		break;
	case TELECOM_CCH: {
		contacts_record_h record = NULL;

		gint status;

		status = contacts_db_get_record(_contacts_phone_log._uri,
				handle, &record);

		if (status != CONTACTS_ERROR_NONE)
			break;

		attr = __bluetooth_pb_phone_log_get_log_type(record);
		str = _bluetooth_pb_vcard_call(handle, filter, format, attr);

		contacts_record_destroy(record, TRUE);
		break;
	}
#ifdef PBAP_SIM_ENABLE
	case SIM_PB:
		if (handle == 0) {
			str = _bluetooth_pb_vcard_contact_owner(agent->tel_number,
								filter, format);
		} else {
			if (_bluetooth_get_contact_addressbook(handle) == PBAP_ADDRESSBOOK_SIM)
				str = _bluetooth_pb_vcard_contact(handle,
								filter, format);
		}
		break;
#endif
	default:
		*err = __bt_pb_error(G_FILE_ERROR_INVAL,
						"unsupported name defined");
		return NULL;
	}

	phonebook_entry = g_variant_new("(s)", str);

	g_free(str);

	FN_END;
	return phonebook_entry;
}

static GVariant *__bt_pb_get_phonebook_size_at(PbAgentData *agent,
					const gchar *command, GError **err)
{
	FN_START;
	GVariant *phonebook_size;
	PhoneBookType pb_type = TELECOM_NONE;
	guint count = 0;

	DBG("command: %s\n", command);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_storage_pb_type(command);

	if (__bluetooth_pb_get_count(pb_type, &count) == FALSE) {
		*err = __bt_pb_error(G_FILE_ERROR_INVAL,
						"unsupported name defined");
		return NULL;
	}

	phonebook_size = g_variant_new("(u)", count);

	FN_END;
	return phonebook_size;
}

static GVariant *__bt_pb_get_phonebook_entries_at(PbAgentData *agent,
				const gchar *command, gint32 start_index,
				gint32 end_index, GError **err)
{
	FN_START;
	GVariant *phonebook_entries;
	PhoneBookType pb_type = TELECOM_NONE;
	GVariantBuilder *builder = g_variant_builder_new(G_VARIANT_TYPE("a(ssu)"));

	DBG("command: %s, start_index: %d, end_index: %d\n",
			command, start_index, end_index);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_storage_pb_type(command);

	if (pb_type == TELECOM_NONE || pb_type == TELECOM_CCH) {
		*err = __bt_pb_error(G_FILE_ERROR_INVAL,
						"unsupported name defined");
		return NULL;
	}

	__bluetooth_pb_get_list_number(agent, pb_type,
			start_index, end_index, builder);

	phonebook_entries = g_variant_new("(a(ssu))", builder);
	if (builder)
		g_variant_builder_unref(builder);

	FN_END;
	return phonebook_entries;
}

static GVariant *__bt_pb_get_phonebook_entries_find_at(PbAgentData *agent,
				const gchar *command, const gchar *find_text,
				GError **err)
{
	FN_START;
	GVariant *phonebook_entries;
	PhoneBookType pb_type = TELECOM_NONE;
	GVariantBuilder *builder = g_variant_builder_new(G_VARIANT_TYPE("a(ssu)"));

	DBG("command: %s, find text: %s\n", command, find_text);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_storage_pb_type(command);

	if (pb_type == TELECOM_NONE || pb_type == TELECOM_CCH) {
		*err = __bt_pb_error(G_FILE_ERROR_INVAL,
						"unsupported name defined");
		return NULL;
	}

	__bluetooth_pb_get_list_name(agent, pb_type, find_text, builder);

	phonebook_entries = g_variant_new("(a(ssu))", builder);

	if (builder)
		g_variant_builder_unref(builder);

	FN_END;
	return phonebook_entries;
}

static GVariant *__bt_pb_get_total_object_count(PbAgentData *agent,
						gchar *path, GError **err)
{
	FN_START;
	GVariant *phonebook_size;
	guint count = 0;
	PhoneBookType pb_type = TELECOM_NONE;

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_storage_pb_type(path);

	if (__bluetooth_pb_get_count(pb_type, &count) == FALSE) {
		*err = __bt_pb_error(G_FILE_ERROR_INVAL,
						"unsupported name defined");
		return NULL;
	}

	phonebook_size = g_variant_new("(u)", count);

	FN_END;
	return phonebook_size;
}

#if 0
static int __bluetooth_pb_agent_read_file(const char *file_path, char **stream)
{
	FN_START;
	FILE *fp = NULL;
	int read_len = -1;
	int received_file_size = 0;
	struct stat file_attr;

	if (file_path == NULL || stream == NULL) {
		ERR("Invalid data \n");
		return -1;
	}

	DBG_SECURE("file_path = %s\n", file_path);

	if ((fp = fopen(file_path, "r+")) == NULL) {
		ERR_SECURE("Cannot open %s\n", file_path);
		return -1;
	}

	if (fstat(fileno(fp), &file_attr) == 0) {
		received_file_size = file_attr.st_size;
		DBG("file_attr.st_size = %d, size = %d\n", file_attr.st_size,
							received_file_size);

		if (received_file_size <= 0) {
			ERR_SECURE("Some problem in the file size [%s]  \n",
								file_path);
			fclose(fp);
			fp = NULL;
			return -1;
		}

		*stream = (char *)malloc(sizeof(char) *received_file_size);
		if (NULL == *stream) {
			fclose(fp);
			fp = NULL;
			return -1;
		}
	} else {
		ERR_SECURE("Some problem in the file [%s]  \n", file_path);
		fclose(fp);
		fp = NULL;
		return -1;
	}

	read_len = fread(*stream, 1, received_file_size, fp);

	if (read_len == 0) {
		if (fp != NULL) {
			fclose(fp);
			fp = NULL;
		}
		DBG_SECURE("Cannot open %s\n", file_path);
		return -1;
	}

	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}
	FN_END;
	return 0;
}
#endif

static gboolean __bt_pb_add_contact(PbAgentData *agent, const char *filename,
					 GError **error)
{
	FN_START;
	/* Contact API is changed, Temporary blocked */
#if 0
	CTSstruct *contact_record = NULL;
	GSList *numbers_list = NULL, *cursor;
	int is_success = 0;
	int is_duplicated = 0;
	int err = 0;
	char *stream = NULL;

	DBG_SECURE("file_path = %s\n", filename);

	err = contacts_svc_connect();
	ERR("contact_db_service_connect fucntion call [error] = %d \n", err);

	err = __bluetooth_pb_agent_read_file(filename, &stream);

	if (err != 0) {
		contacts_svc_disconnect();
		ERR("contacts_svc_disconnect fucntion call [error] = %d \n", err);

		if (NULL != stream) {
			free(stream);
			stream = NULL;
		}
		return FALSE;
	}

	is_success = contacts_svc_get_contact_from_vcard((const void *)stream,
							&contact_record);

	DBG("contacts_svc_get_contact_from_vcard fucntion call [is_success] = %d \n", is_success);

	if (0 == is_success) {
		contacts_svc_struct_get_list(contact_record, CTS_CF_NUMBER_LIST,
								&numbers_list);
		cursor = numbers_list;

		for (; cursor; cursor = g_slist_next(cursor)) {
			if (contacts_svc_find_contact_by(CTS_FIND_BY_NUMBER,
					contacts_svc_value_get_str(cursor->data,
					CTS_NUM_VAL_NUMBER_STR)) > 0) {
				DBG("is_duplicated\n");
				is_duplicated = TRUE;
			}
		}

		if (is_duplicated == FALSE) {
			contacts_svc_insert_contact(0, contact_record);
		}
	} else {
		ERR("Fail \n");
	}

	err = contacts_svc_disconnect();
	ERR("contacts_svc_disconnect fucntion call [error] = %d \n", err);

	if (NULL != stream) {
		free(stream);
		stream = NULL;
	}
#endif
	FN_END;
	return TRUE;
}

/* Create GError from error code and error message*/
static GError *__bt_pb_error(gint error_code, const gchar *error_message)
{
	return g_error_new(g_quark_from_string("PB Agent"),
			error_code, "PB Agent Error: %s", error_message);
}

static PhoneBookType __bluetooth_pb_get_pb_type(const char *name)
{
	FN_START;
	gchar *suffix = ".vcf";
	gint len;
	gint size;
	gint i;

	if (name == NULL)
		return TELECOM_NONE;

	len = strlen(name);

	if (g_str_has_suffix(name, suffix))
		len -= strlen(suffix);

	size = G_N_ELEMENTS(bluetooth_pb_agent_folder_list) - 1;
	for (i = 0; i < size; i++) {
		if (strncmp(name, bluetooth_pb_agent_folder_list[i], len) == 0)
			return i;
	}

	FN_END;
	return TELECOM_NONE;
}

static PhoneBookType __bluetooth_pb_get_storage_pb_type(const char *name)
{
	FN_START;
	if (name == NULL)
		return TELECOM_NONE;

	if (g_strcmp0(name, "\"ME\"") == 0)
		return TELECOM_PB;

	if (g_strcmp0(name, "\"RC\"") == 0)
		return TELECOM_ICH;

	if (g_strcmp0(name, "\"DC\"") == 0)
		return TELECOM_OCH;

	if (g_strcmp0(name, "\"MC\"") == 0)
		return TELECOM_MCH;
#ifdef PBAP_SIM_ENABLE
	if (g_strcmp0(name, "\"SM\"") == 0)
		return SIM_PB;
#endif
	FN_END;
	return TELECOM_NONE;
}

static gint __bluetooth_pb_phone_log_filter_append(contacts_filter_h filter,
						gint *match, gint size)
{
	FN_START;
	gint i;
	gint status;

	for (i = 0; i < size; i++) {

		if (i > 0) {
			status = contacts_filter_add_operator(filter,
					CONTACTS_FILTER_OPERATOR_OR);

			if (status != CONTACTS_ERROR_NONE)
				return status;
		}

		status = contacts_filter_add_int(filter,
					_contacts_phone_log.log_type,
					CONTACTS_MATCH_EQUAL, match[i]);

		if (status != CONTACTS_ERROR_NONE)
			return status;
	}

	FN_END;
	return CONTACTS_ERROR_NONE;
}

static contacts_query_h __bluetooth_pb_query_phone_log(gint *match, gint size)
{
	FN_START;
	contacts_query_h query = NULL;
	contacts_filter_h filter = NULL;
	gint status;

	status = contacts_query_create(_contacts_phone_log._uri, &query);

	if (status != CONTACTS_ERROR_NONE)
		return NULL;

	status = contacts_filter_create(_contacts_phone_log._uri, &filter);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_query_destroy(query);
		return NULL;
	}

	status = __bluetooth_pb_phone_log_filter_append(filter, match, size);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_filter_destroy(filter);
		contacts_query_destroy(query);
		return NULL;
	}

	status = contacts_query_set_filter(query, filter);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_filter_destroy(filter);
		contacts_query_destroy(query);
		return NULL;
	}

	status = contacts_query_set_sort(query, _contacts_phone_log.log_time,
									false);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_filter_destroy(filter);
		contacts_query_destroy(query);
		return NULL;
	}

	contacts_filter_destroy(filter);

	FN_END;
	return query;
}

bool __bt_is_matching_addressbook(const char *addressbook_name, int addressbook)
{
	bool is_sim_addressbook = _bt_is_sim_addressbook(addressbook_name);

	if ((is_sim_addressbook == false
			&& addressbook == PBAP_ADDRESSBOOK_PHONE) ||
		(is_sim_addressbook == true
			&& addressbook == PBAP_ADDRESSBOOK_SIM))
		return true;

	return false;
}

static contacts_query_h __bluetooth_pb_query_person(int addressbook)
{
	FN_START;
	contacts_query_h query = NULL;
	contacts_filter_h filter = NULL;
	contacts_list_h recordList = NULL;
	contacts_record_h record = NULL;
	char *addressbook_name = NULL;
	int address_book_id = 0;
	int count = 0;
	unsigned int i = 0;
	gint status;
	bool is_first_condition = true;

	DBG("Addressbook [%d]", addressbook);
	/* Create query*/
	status = contacts_query_create(_contacts_person_contact._uri, &query);
	if (status != 0) {
		ERR("Could not create query");
		return NULL;
	}

	/* Create addressbook Filter*/
	status = contacts_db_get_all_records(_contacts_address_book._uri, 0, 0,
					&recordList);
	if (status != CONTACTS_ERROR_NONE)
		ERR("Contact list get api failed %d", status);

	contacts_filter_create(_contacts_person_contact._uri, &filter);
	contacts_list_get_count(recordList, &count);

	for (i = 0; i < count; i++) {
		status = contacts_list_get_current_record_p(recordList, &record);
		if (status != CONTACTS_ERROR_NONE) {
			ERR("Contact list get api failed %d", status);
			goto next;
		}
		status = contacts_record_get_str_p(record,
						_contacts_address_book.name,
						&addressbook_name);
		if (status != CONTACTS_ERROR_NONE) {
			ERR("Contact record get api failed %d", status);
			goto next;
		}
		status = contacts_record_get_int(record,
						_contacts_address_book.id,
						&address_book_id);
		if (status != CONTACTS_ERROR_NONE) {
			ERR("contacts record get int api failed %d", status);
			goto next;
		}

		DBG("Addressbook ID: [%d] Addressbook Name: [%s]",
				address_book_id, addressbook_name);

		if (__bt_is_matching_addressbook(addressbook_name,
							addressbook)) {
			if (is_first_condition)
				is_first_condition = false;
			else
				contacts_filter_add_operator(filter,
						CONTACTS_FILTER_OPERATOR_OR);
			DBG("SELECTED Addressbook ID: [%d] Addressbook Name: [%s]",
					address_book_id, addressbook_name);
			status = contacts_filter_add_int(filter,
					_contacts_person_contact.address_book_id,
					CONTACTS_MATCH_EQUAL, address_book_id);
			if (status != CONTACTS_ERROR_NONE)
				ERR("Contact filter add failed %d", status);
		}
next:
		if (contacts_list_next(recordList) != CONTACTS_ERROR_NONE)
			break;
	}

	contacts_list_destroy(recordList, true);

	status = contacts_query_set_filter(query, filter);
	if (status != CONTACTS_ERROR_NONE)
		ERR("Could not Apply Filter");

	contacts_filter_destroy(filter);
	FN_END;
	return query;
}

static contacts_query_h __bluetooth_pb_query_person_number(void)
{
	FN_START;
	contacts_query_h query = NULL;
	gint status;

	status = contacts_query_create(_contacts_person_number._uri, &query);

	if (status != CONTACTS_ERROR_NONE)
		return NULL;

	FN_END;
	return query;
}

static contacts_query_h __bluetooth_pb_query_phone_log_incoming(void)
{
	FN_START;
	gint size = 4;
	gint match[] = {
		CONTACTS_PLOG_TYPE_VOICE_INCOMING,
		CONTACTS_PLOG_TYPE_VIDEO_INCOMING,
		CONTACTS_PLOG_TYPE_VOICE_REJECT,
		CONTACTS_PLOG_TYPE_VIDEO_REJECT
	};

	FN_END;
	return __bluetooth_pb_query_phone_log(match, size);
}

static contacts_query_h __bluetooth_pb_query_phone_log_outgoing(void)
{
	FN_START;
	gint size = 2;
	gint match[] = {
		CONTACTS_PLOG_TYPE_VOICE_OUTGOING,
		CONTACTS_PLOG_TYPE_VIDEO_OUTGOING
	};

	FN_END;
	return __bluetooth_pb_query_phone_log(match, size);
}

static contacts_query_h __bluetooth_pb_query_phone_log_missed(void)
{
	FN_START;
	gint size = 4;
	gint match[] = {
		CONTACTS_PLOG_TYPE_VOICE_INCOMING_UNSEEN,
		CONTACTS_PLOG_TYPE_VIDEO_INCOMING_UNSEEN,
		CONTACTS_PLOG_TYPE_VOICE_INCOMING_SEEN,
		CONTACTS_PLOG_TYPE_VIDEO_INCOMING_SEEN
	};

	FN_END;
	return __bluetooth_pb_query_phone_log(match, size);
}

static contacts_query_h __bluetooth_pb_query_phone_log_combined(void)
{
	FN_START;
	gint size = 10;
	gint match[] = {
		CONTACTS_PLOG_TYPE_VOICE_INCOMING,
		CONTACTS_PLOG_TYPE_VIDEO_INCOMING,
		CONTACTS_PLOG_TYPE_VOICE_OUTGOING,
		CONTACTS_PLOG_TYPE_VIDEO_OUTGOING,
		CONTACTS_PLOG_TYPE_VOICE_INCOMING_UNSEEN,
		CONTACTS_PLOG_TYPE_VIDEO_INCOMING_UNSEEN,
		CONTACTS_PLOG_TYPE_VOICE_INCOMING_SEEN,
		CONTACTS_PLOG_TYPE_VIDEO_INCOMING_SEEN,
		CONTACTS_PLOG_TYPE_VOICE_REJECT,
		CONTACTS_PLOG_TYPE_VIDEO_REJECT
	};

	FN_END;
	return __bluetooth_pb_query_phone_log(match, size);
}

static gboolean __bluetooth_pb_get_count(PhoneBookType pb_type,
				guint *count)
{
	FN_START;
	contacts_query_h query = NULL;
	gint status;
	gint signed_count;

	switch (pb_type) {
	case TELECOM_PB:
		query = __bluetooth_pb_query_person(PBAP_ADDRESSBOOK_PHONE);
		break;
	case TELECOM_ICH:
		query = __bluetooth_pb_query_phone_log_incoming();
		break;
	case TELECOM_OCH:
		query = __bluetooth_pb_query_phone_log_outgoing();
		break;
	case TELECOM_MCH:
		query = __bluetooth_pb_query_phone_log_missed();
		break;
	case TELECOM_CCH:
		query = __bluetooth_pb_query_phone_log_combined();
		break;
#ifdef PBAP_SIM_ENABLE
	case SIM_PB:
		query = __bluetooth_pb_query_person(PBAP_ADDRESSBOOK_SIM);
		break;
#endif
	default:
		return FALSE;
	}

	if (query == NULL)
		return FALSE;

	status = contacts_db_get_count_with_query(query, &signed_count);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_query_destroy(query);
		return FALSE;
	}

	contacts_query_destroy(query);

	if (signed_count < 0)
		signed_count = 0;

	*count = (gint) signed_count;

	FN_END;
	return TRUE;
}

static gboolean __bluetooth_pb_get_count_new_missed_call(guint *count)
{
	FN_START;
	contacts_query_h query = NULL;
	gint status;
	gint signed_count;
	gint size = 2;
	gint match[] = {
		CONTACTS_PLOG_TYPE_VOICE_INCOMING_UNSEEN,
		CONTACTS_PLOG_TYPE_VIDEO_INCOMING_UNSEEN
	};

	query = __bluetooth_pb_query_phone_log(match, size);

	if (query == NULL)
		return FALSE;

	status = contacts_db_get_count_with_query(query, &signed_count);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_query_destroy(query);
		return FALSE;
	}

	contacts_query_destroy(query);

	if (signed_count < 0)
		signed_count = 0;

	*count = (guint)signed_count;

	FN_END;
	return TRUE;
}

static const char *__bluetooth_pb_phone_log_get_log_type(contacts_record_h record)
{
	FN_START;
	gint status;
	gint log_type;

	status = contacts_record_get_int(record, _contacts_phone_log.log_type,
								&log_type);

	if (status != CONTACTS_ERROR_NONE)
		return NULL;

	switch (log_type) {
	case CONTACTS_PLOG_TYPE_VOICE_INCOMING:
	case CONTACTS_PLOG_TYPE_VIDEO_INCOMING:
	case CONTACTS_PLOG_TYPE_VOICE_REJECT:
	case CONTACTS_PLOG_TYPE_VIDEO_REJECT:
		return "RECEIVED";
	case CONTACTS_PLOG_TYPE_VOICE_OUTGOING:
	case CONTACTS_PLOG_TYPE_VIDEO_OUTGOING:
		return "DIALED";
	case CONTACTS_PLOG_TYPE_VOICE_INCOMING_UNSEEN:
	case CONTACTS_PLOG_TYPE_VIDEO_INCOMING_UNSEEN:
	case CONTACTS_PLOG_TYPE_VOICE_INCOMING_SEEN:
	case CONTACTS_PLOG_TYPE_VIDEO_INCOMING_SEEN:
		return "MISSED";
	default:
		return NULL;
	}
	FN_END;
}

static void __bluetooth_pb_get_vcards(PbAgentData *agent, PhoneBookType pb_type,
			guint64 filter, guint8 format, guint16 max_list_count,
			guint16 list_start_offset, GVariantBuilder *vcards)
{
	FN_START;
	contacts_list_h record_list = NULL;
	contacts_query_h query = NULL;
	gint status;
	gint limit;
	gint offset;
	guint property_id = 0;
	const char *attr = NULL;
	gboolean get_log = FALSE;

	/* contact offset is n - 1 of PBAP */
	offset = (gint)list_start_offset - 1;

	if (max_list_count >= 65535)
		limit = -1;	/* contact limit -1 means unrestricted */
	else
		limit = (gint)max_list_count;

	switch (pb_type) {
	case TELECOM_PB:
#ifdef PBAP_SIM_ENABLE
	case SIM_PB:
#endif
		/* for owner */
		if (list_start_offset == 0) {
			char *vcard;

			vcard = _bluetooth_pb_vcard_contact_owner(agent->tel_number,
								filter, format);
			if (vcard)
				g_variant_builder_add(vcards, "s", vcard);

			offset = 0;

			if (limit == 1)
				return;
			else if (limit > 1)
				limit--;
		}

		if (pb_type == TELECOM_PB)
			query = __bluetooth_pb_query_person(PBAP_ADDRESSBOOK_PHONE);
#ifdef PBAP_SIM_ENABLE
		else if (pb_type == SIM_PB)
			query = __bluetooth_pb_query_person(PBAP_ADDRESSBOOK_SIM);
#endif

		property_id = _contacts_person.id;
		break;
	case TELECOM_ICH:
		query = __bluetooth_pb_query_phone_log_incoming();
		property_id = _contacts_phone_log.id;
		attr = "RECEIVED";
		break;
	case TELECOM_OCH:
		query = __bluetooth_pb_query_phone_log_outgoing();
		property_id = _contacts_phone_log.id;
		attr = "DIALED";
		break;
	case TELECOM_MCH:
		query = __bluetooth_pb_query_phone_log_missed();
		property_id = _contacts_phone_log.id;
		attr = "MISSED";
		break;
	case TELECOM_CCH:
		query = __bluetooth_pb_query_phone_log_combined();
		property_id = _contacts_phone_log.id;
		get_log = TRUE;
		break;
	default:
		return;
	}
	INFO("Limit is = %d and offset is =%d\n", limit, offset);

	/* When limit is passed as ZERO to contacts_db_get_records_with_query
	 * API then this API will provide all available contacts in its database
	 * (unrestricted). Now consider a case when client requests for
	 * maxlistcount of 1 and start offset as 0 then we have already read the
	 * owner card in above switch case and when it reads owner card it
	 * decrements the limit by 1.
	 */
	if (limit != 0) {
		status = contacts_db_get_records_with_query(query, offset,
							limit, &record_list);

		if (status != CONTACTS_ERROR_NONE) {
			contacts_list_destroy(record_list, TRUE);
			contacts_query_destroy(query);
			return;
		}

		status = contacts_list_first(record_list);

		if (status != CONTACTS_ERROR_NONE) {
			contacts_list_destroy(record_list, TRUE);
			contacts_query_destroy(query);
			return;
		}

		do {
			contacts_record_h record;
			gint id;
			gchar *vcard = NULL;

			status = contacts_list_get_current_record_p(record_list,
								&record);

			if (status != CONTACTS_ERROR_NONE)
				continue;
			status = contacts_record_get_int(record, property_id,
									&id);

			if (status != CONTACTS_ERROR_NONE)
				continue;

			if (property_id == _contacts_person.id)
				vcard = _bluetooth_pb_vcard_contact(id, filter,
									format);
			else {
				if (get_log)
					attr = __bluetooth_pb_phone_log_get_log_type(record);

				vcard = _bluetooth_pb_vcard_call(id, filter,
								format, attr);
			}

			if (vcard)
				g_variant_builder_add(vcards, "s", vcard);

		} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);
		contacts_list_destroy(record_list, TRUE);
	}

	contacts_query_destroy(query);

	FN_END;
}

static void __bluetooth_pb_get_contact_list(PbAgentData *agent,
			contacts_query_h query, GVariantBuilder *builder)
{
	FN_START;
	contacts_list_h record_list = NULL;
	gint status;

	/* Add owner */
	if (builder) {
		gchar *tmp;
		gchar *name;

		tmp = _bluetooth_pb_owner_name();
		name = g_strdup_printf("%s;;;;", tmp);
		g_free(tmp);

		__bluetooth_pb_list_ptr_array_add(builder, name,
							agent->tel_number, 0);

		g_free(name);
	}

	status = contacts_db_get_records_with_query(query, -1, -1,
								&record_list);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_list_destroy(record_list, TRUE);
		return;
	}

	status = contacts_list_first(record_list);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_list_destroy(record_list, TRUE);
		return;
	}

	do {
		contacts_record_h record;
		gint id;

		status = contacts_list_get_current_record_p(record_list,
								&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		status = contacts_record_get_int(record,
				_contacts_person_contact.person_id, &id);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		/* create list */
		if (builder) {
			gchar *name;
			gchar *number;

			name = _bluetooth_pb_name_from_person_id(id);
			number = _bluetooth_pb_number_from_person_id(id);

			__bluetooth_pb_list_ptr_array_add(builder, name,
								number,	id);

			g_free(name);
			g_free(number);
		}

	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);

	contacts_list_destroy(record_list, TRUE);
	FN_END;
}

static void __bluetooth_pb_get_phone_log_list(PbAgentData *agent,
			contacts_query_h query, GVariantBuilder *builder)
{
	FN_START;
	contacts_list_h record_list = NULL;
	gint status;

	status = contacts_db_get_records_with_query(query, -1, -1,
								&record_list);

	if (status != CONTACTS_ERROR_NONE)
		return;

	status = contacts_list_first(record_list);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_list_destroy(record_list, TRUE);
		return;
	}

	do {
		contacts_record_h record;
		gint id;

		status = contacts_list_get_current_record_p(record_list,
								&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		status = contacts_record_get_int(record,
						_contacts_phone_log.id, &id);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		/* create list */
		if (builder) {
			gchar *name;
			gchar *number;

			name = _bluetooth_pb_name_from_phonelog_id(id);

			contacts_record_get_str_p(record,
					_contacts_phone_log.address, &number);

			__bluetooth_pb_list_ptr_array_add(builder, name,
								number, id);

			g_free(name);
		}

	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);

	contacts_list_destroy(record_list, TRUE);
	FN_END;
}


static void __bluetooth_pb_get_list(PbAgentData *agent, PhoneBookType pb_type,
				GVariantBuilder *builder)
{
	FN_START;
	contacts_query_h query;

	/* no requires refresh cache */
	if (builder == NULL && agent->pb_type == pb_type)
		return;

	switch (pb_type) {
	case TELECOM_PB:
		query = __bluetooth_pb_query_person(PBAP_ADDRESSBOOK_PHONE);
		__bluetooth_pb_get_contact_list(agent, query, builder);
		break;
	case TELECOM_ICH:
		query = __bluetooth_pb_query_phone_log_incoming();
		__bluetooth_pb_get_phone_log_list(agent, query, builder);
		break;
	case TELECOM_OCH:
		query = __bluetooth_pb_query_phone_log_outgoing();
		__bluetooth_pb_get_phone_log_list(agent, query, builder);
		break;
	case TELECOM_MCH:
		query = __bluetooth_pb_query_phone_log_missed();
		__bluetooth_pb_get_phone_log_list(agent, query, builder);
		break;
	case TELECOM_CCH:
		query = __bluetooth_pb_query_phone_log_combined();
		__bluetooth_pb_get_phone_log_list(agent, query, builder);
		break;
#ifdef PBAP_SIM_ENABLE
	case SIM_PB:
		query = __bluetooth_pb_query_person(PBAP_ADDRESSBOOK_SIM);
		__bluetooth_pb_get_contact_list(agent, query, builder);
		break;
#endif
	default:
		return;
	}

	agent->pb_type = pb_type;

	if (query)
		contacts_query_destroy(query);
	FN_END;
}

static void __bluetooth_pb_get_contact_list_number(PbAgentData *agent,
				contacts_query_h query, gint start_index,
				gint end_index, GVariantBuilder *builder)
{
	FN_START;
	contacts_list_h record_list = NULL;
	gint status;
	gint i;
	gint from;
	gint to;
	gint offset;

	from = start_index;
	to = end_index;

	if (from < 1)
		from = 1;

	if (to < 1)
		to = 1;

	offset = to - from + 1;
	if (offset <= 0)
		return;

	i = from;

	status = contacts_db_get_records_with_query(query, from - 1 , offset,
			&record_list);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_list_destroy(record_list, TRUE);
		return;
	}

	status = contacts_list_first(record_list);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_list_destroy(record_list, TRUE);
		return;
	}

	do {
		contacts_record_h record;
		gchar *display_name;
		gchar *number;

		status = contacts_list_get_current_record_p(record_list,
								&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		contacts_record_get_str_p(record,
					_contacts_person_number.display_name,
					&display_name);
		contacts_record_get_str_p(record,
				_contacts_person_number.number, &number);

		__bluetooth_pb_list_ptr_array_add(builder, display_name,
								number, i);

		i++;
	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);

	contacts_list_destroy(record_list, TRUE);
	FN_END;
}

static void __bluetooth_pb_get_phone_log_list_number(PbAgentData *agent,
				contacts_query_h query, gint start_index,
				gint end_index, GVariantBuilder *builder)
{
	FN_START;
	contacts_list_h record_list = NULL;
	gint status;
	gint i;
	gint from;
	gint to;
	gint offset;

	from = start_index;
	to = end_index;

	if (from < 1)
		from = 1;

	if (to < 1)
		to = 1;

	offset = to - from + 1;
	if (offset <= 0)
		return;

	i = from;

	status = contacts_db_get_records_with_query(query, from - 1 , offset,
			&record_list);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_list_destroy(record_list, TRUE);
		return;
	}

	status = contacts_list_first(record_list);
	if (status != CONTACTS_ERROR_NONE) {
		contacts_list_destroy(record_list, TRUE);
		return;
	}

	do {
		contacts_record_h record;
		gint id;
		gchar *display_name;
		gchar *number;

		status = contacts_list_get_current_record_p(record_list,
								&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		status = contacts_record_get_int(record,
						_contacts_phone_log.id,	&id);
		if (status != CONTACTS_ERROR_NONE) {
			ERR("contact_record_get_int api failed %d", status);
			continue;
		}

		display_name = _bluetooth_pb_fn_from_phonelog_id(id);

		contacts_record_get_str_p(record, _contacts_phone_log.address,
								&number);

		__bluetooth_pb_list_ptr_array_add(builder, display_name,
								number, i);

		i++;

		g_free(display_name);

	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);

	contacts_list_destroy(record_list, TRUE);
	FN_END;
}

static void __bluetooth_pb_get_list_number(PbAgentData *agent,
				PhoneBookType pb_type, gint start_index,
				gint end_index, GVariantBuilder *builder)
{
	FN_START;
	contacts_query_h query;

	DBG("type = %d", pb_type);
	switch (pb_type) {
	case TELECOM_PB:
		query = __bluetooth_pb_query_person_number();
		__bluetooth_pb_get_contact_list_number(agent, query,
				start_index, end_index, builder);
		break;
	case TELECOM_ICH:
		query = __bluetooth_pb_query_phone_log_incoming();
		__bluetooth_pb_get_phone_log_list_number(agent, query,
				start_index, end_index, builder);
		break;
	case TELECOM_OCH:
		query = __bluetooth_pb_query_phone_log_outgoing();
		__bluetooth_pb_get_phone_log_list_number(agent, query,
				start_index, end_index, builder);
		break;
	case TELECOM_MCH:
		query = __bluetooth_pb_query_phone_log_missed();
		__bluetooth_pb_get_phone_log_list_number(agent, query,
				start_index, end_index, builder);
		break;
	case TELECOM_CCH:
		query = __bluetooth_pb_query_phone_log_combined();
		__bluetooth_pb_get_phone_log_list_number(agent, query,
				start_index, end_index, builder);
		break;
#ifdef PBAP_SIM_ENABLE
	case SIM_PB:
		query = __bluetooth_pb_query_person(PBAP_ADDRESSBOOK_SIM);
		__bluetooth_pb_get_contact_list_number(agent, query,
				start_index, end_index, builder);
		break;
#endif

	default:
		return;
	}

	if (query)
		contacts_query_destroy(query);
	FN_END;
}

static void __bluetooth_pb_get_contact_list_name(PbAgentData *agent,
				contacts_query_h query, const gchar *find_text,
				GVariantBuilder *builder)
{
	FN_START;
	contacts_list_h record_list = NULL;
	gint status;
	gint i = 1;

	status = contacts_db_get_records_with_query(query,
			-1, -1, &record_list);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_list_destroy(record_list, TRUE);
		return;
	}

	status = contacts_list_first(record_list);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_list_destroy(record_list, TRUE);
		return;
	}

	do {
		contacts_record_h record;
		gchar *display_name;

		status = contacts_list_get_current_record_p(record_list,
								&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		contacts_record_get_str_p(record,
			_contacts_person_number.display_name, &display_name);

		if (g_str_has_prefix(display_name, find_text)) {
			gchar *number;

			contacts_record_get_str_p(record,
				_contacts_person_number.number, &number);

			__bluetooth_pb_list_ptr_array_add(builder, display_name,
								number, i);
		}

		i++;
	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);
	contacts_list_destroy(record_list, TRUE);
	FN_END;
}

static void __bluetooth_pb_get_phone_log_list_name(PbAgentData *agent,
				contacts_query_h query, const gchar *find_text,
				GVariantBuilder *builder)
{
	FN_START;
	contacts_list_h record_list = NULL;
	gint status;
	gint i = 1;

	status = contacts_db_get_records_with_query(query, -1, -1,
								&record_list);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_list_destroy(record_list, TRUE);
		return;
	}

	status = contacts_list_first(record_list);

	if (status != CONTACTS_ERROR_NONE) {
		contacts_list_destroy(record_list, TRUE);
		return;
	}

	do {
		contacts_record_h record;
		gint id;
		gchar *display_name;

		status = contacts_list_get_current_record_p(record_list,
				&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		status = contacts_record_get_int(record,
						_contacts_phone_log.id, &id);
		if (status != CONTACTS_ERROR_NONE) {
			ERR("contacts_record_get_int failed %d", status);
			continue;
		}

		display_name = _bluetooth_pb_fn_from_phonelog_id(id);

		if (g_str_has_prefix(display_name, find_text)) {
			gchar *number;

			contacts_record_get_str_p(record,
					_contacts_phone_log.address, &number);

			__bluetooth_pb_list_ptr_array_add(builder, display_name,
								number, i);
		}

		i++;

		g_free(display_name);

	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);

	contacts_list_destroy(record_list, TRUE);
	FN_END;
}

static void __bluetooth_pb_get_list_name(PbAgentData *agent,
				PhoneBookType pb_type, const gchar *find_text,
				GVariantBuilder *builder)
{
	FN_START;
	contacts_query_h query;

	switch (pb_type) {
	case TELECOM_PB:
		query = __bluetooth_pb_query_person_number();
		__bluetooth_pb_get_contact_list_name(agent, query,
				find_text, builder);
		break;
	case TELECOM_ICH:
		query = __bluetooth_pb_query_phone_log_incoming();
		__bluetooth_pb_get_phone_log_list_name(agent, query,
				find_text, builder);
		break;
	case TELECOM_OCH:
		query = __bluetooth_pb_query_phone_log_outgoing();
		__bluetooth_pb_get_phone_log_list_name(agent, query,
				find_text, builder);
		break;
	case TELECOM_MCH:
		query = __bluetooth_pb_query_phone_log_missed();
		__bluetooth_pb_get_phone_log_list_name(agent, query,
				find_text, builder);
		break;
	case TELECOM_CCH:
		query = __bluetooth_pb_query_phone_log_combined();
		__bluetooth_pb_get_phone_log_list_name(agent, query,
				find_text, builder);
		break;
	default:
		return;
	}

	if (query)
		contacts_query_destroy(query);
	FN_END;
}

static void __bluetooth_pb_list_ptr_array_add(GVariantBuilder *builder,
			const gchar *name, const gchar *number, gint handle)
{
	FN_START;
	gchar *temp_name = g_strdup(name);
	gchar *temp_number = g_strdup(number);

	g_variant_builder_add(builder, "(ssu)", temp_name, temp_number, handle);

	g_free(temp_name);
	g_free(temp_number)
	FN_END;
}

static void __bluetooth_pb_agent_signal_handler(int signum)
{
	FN_START;
	if (g_mainloop) {
		g_main_loop_quit(g_mainloop);
	} else {
		DBG("Terminate Bluetooth PBAP agent");
		exit(0);
	}
}

static void __bluetooth_pb_contact_changed(const gchar *view_uri,
					void *user_data)
{
	FN_START;
	guint new_missed_call;
	PbAgentData *agent = (PbAgentData *)user_data;
	GDBusConnection *conn = __bt_pb_get_gdbus_connection();

	DBG("Received contact changed cb");

	g_dbus_connection_emit_signal(conn, "org.bluez.pb_agent",
				"/org/bluez/pb_agent", "org.bluez.PbAgent",
				"clear", NULL, NULL);

	bluetooth_pb_agent_clear(agent);

	__bluetooth_pb_get_count_new_missed_call(&new_missed_call);

	if (new_missed_call > total_missed_call_count)
		unnotified_missed_call_count += new_missed_call -
							total_missed_call_count;

	INFO("Missed call count : #prev[%d], #current[%d], #unnotified[%d]",
		total_missed_call_count, new_missed_call,
						unnotified_missed_call_count);

	total_missed_call_count = new_missed_call;
	FN_END;
}

static void __bluetooth_pb_agent_timeout_add_seconds(PbAgentData *agent)
{
	FN_START;

	if (agent->timeout_id)
		g_source_remove(agent->timeout_id);

	agent->timeout_id = g_timeout_add_seconds(BLUETOOTH_PB_AGENT_TIMEOUT,
				__bluetooth_pb_agent_timeout_calback, agent);
	FN_END;
}

static gboolean __bluetooth_pb_agent_timeout_calback(gpointer user_data)
{
	FN_START;
	PbAgentData *agent = (PbAgentData *)user_data;

	agent->timeout_id = 0;

	if (g_mainloop)
		g_main_loop_quit(g_mainloop);

	FN_END;
	return FALSE;
}

static void __bluetooth_pb_tel_callback(TapiHandle *handle, int result,
					void *data, void *user_data)
{
	FN_START;
	PbAgentData *agent = (PbAgentData *)user_data;
	TelSimMsisdnList_t *number;

	__bt_pb_dbus_init(agent);

	if (data != NULL) {
		number = (TelSimMsisdnList_t *)data;
		agent->tel_number = g_strdup(number->list[0].num);
	}

	tel_deinit(agent->tapi_handle);
	agent->tapi_handle = NULL;
	FN_END;
}

static gboolean __bt_pb_destroy_agent()
{
	FN_START;
	g_main_loop_quit(g_mainloop);
	FN_END;
	return TRUE;
}

static GDBusNodeInfo *__bt_pb_create_method_node_info
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

static gboolean __bt_pb_dbus_init(PbAgentData *agent)
{
	guint owner_id = 0;
	guint pb_id;
	GDBusNodeInfo *node_info = NULL;
	GError *error = NULL;
	GDBusConnection *conn = __bt_pb_get_gdbus_connection();

	if (conn == NULL) {
		ERR("Error in creating the gdbus connection");
		goto fail;
	}

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM, BT_PB_SERVICE_NAME,
					G_BUS_NAME_OWNER_FLAGS_NONE, NULL,
					NULL, NULL, NULL, NULL);
	if (owner_id == 0)
		goto fail;

	node_info = __bt_pb_create_method_node_info(pb_agent_introspection_xml);
	if (node_info == NULL)
		goto fail;

	pb_id = g_dbus_connection_register_object(conn, BT_PB_SERVICE_OBJECT_PATH,
					node_info->interfaces[0], &method_table,
					agent, NULL, &error);

	if (pb_id == 0) {
		ERR("Failed to register: %s", error->message);
		g_clear_error(&error);
		goto fail;
	}

	agent->pbagent_interface_id = pb_id;

	pb_id = g_dbus_connection_register_object(conn, BT_PB_SERVICE_OBJECT_PATH,
					node_info->interfaces[1], &method_table,
					agent, NULL, &error);

	if (pb_id == 0) {
		ERR("Failed to register: %s", error->message);
		g_clear_error(&error);
		goto fail;
	}

	g_dbus_node_info_unref(node_info);

	agent->pbagent_at_interface_id = pb_id;

	return TRUE;

fail:
	if (pb_dbus_conn) {
		g_object_unref(pb_dbus_conn);
		pb_dbus_conn = NULL;
	}

	if (conn)
		g_object_unref(conn);

	if (node_info)
		g_dbus_node_info_unref(node_info);

	if (owner_id > 0)
		g_bus_unown_name(owner_id);

	return FALSE;
}

static gboolean __bt_pb_dbus_deinit(PbAgentData *agent)
{
	if (pb_dbus_conn) {
		if (agent->pbagent_interface_id != 0) {
			g_dbus_connection_unregister_object(pb_dbus_conn,
						agent->pbagent_interface_id);
			agent->pbagent_interface_id = 0;
		}
		if (agent->pbagent_at_interface_id != 0) {
			g_dbus_connection_unregister_object(pb_dbus_conn,
						agent->pbagent_at_interface_id);
			agent->pbagent_at_interface_id = 0;
		}
		if (pb_dbus_conn) {
			g_object_unref(pb_dbus_conn);
			pb_dbus_conn = NULL;
		}
		return TRUE;
	}
	return FALSE;
}

int main(void)
{
	FN_START;
	PbAgentData *agent;
	gint ret = EXIT_SUCCESS;
	gint tapi_result;
	struct sigaction sa;

	DBG("Starting Bluetooth PBAP agent");

	g_mainloop = g_main_loop_new(NULL, FALSE);
	if (g_mainloop == NULL) {
		ERR("Couldn't create GMainLoop\n");
		return EXIT_FAILURE;
	}

	agent = (PbAgentData *)g_malloc(sizeof(PbAgentData));

	if (agent == NULL)
		return EXIT_FAILURE;

	agent->pbagent_interface_id = 0;
	agent->pbagent_at_interface_id = 0;
	agent->tel_number = NULL;

	/* connect contact */
	if (contacts_connect() != CONTACTS_ERROR_NONE) {
		ERR("Can not connect contacts server\n");
		g_free(agent);
		return EXIT_FAILURE;
	}

	__bluetooth_pb_get_count_new_missed_call(&total_missed_call_count);

	if (contacts_db_add_changed_cb(_contacts_contact._uri,
			__bluetooth_pb_contact_changed,
			(void *)agent) != CONTACTS_ERROR_NONE) {
		ERR("Can not add changed callback");
	}

	if (contacts_db_add_changed_cb(_contacts_phone_log._uri,
			__bluetooth_pb_contact_changed,
			(void *)agent) != CONTACTS_ERROR_NONE) {
		ERR("Can not add changed callback");
	}

	/* set signal */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = __bluetooth_pb_agent_signal_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	/* init tapi */
	agent->tapi_handle = tel_init(NULL);
	tapi_result = tel_get_sim_msisdn(agent->tapi_handle,
			__bluetooth_pb_tel_callback, agent);

	if (tapi_result != TAPI_API_SUCCESS) {
		__bt_pb_dbus_init(agent);
	}

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	g_main_loop_run(g_mainloop);

	if (contacts_db_remove_changed_cb(_contacts_phone_log._uri,
			__bluetooth_pb_contact_changed,
			(void *)agent) != CONTACTS_ERROR_NONE) {
		ERR("Cannot remove changed callback");
	}

	if (contacts_db_remove_changed_cb(_contacts_contact._uri,
			__bluetooth_pb_contact_changed,
			(void *)agent) != CONTACTS_ERROR_NONE) {
		ERR("Cannot remove changed callback");
	}

	if (contacts_disconnect() != CONTACTS_ERROR_NONE)
		ERR("contacts_disconnect failed \n");

	g_dbus_connection_emit_signal(pb_dbus_conn, "org.bluez.pb_agent",
				"/org/bluez/pb_agent", "org.bluez.PbAgent",
				"clear", NULL, NULL);

	bluetooth_pb_agent_clear(agent);

	if (agent->tapi_handle)
		tel_deinit(agent->tapi_handle);
	if (agent->tel_number)
		g_free(agent->tel_number);

	__bt_pb_dbus_deinit(agent);

	g_free(agent);

	DBG("Terminate Bluetooth PBAP agent");
	FN_END;
	return ret;
}
