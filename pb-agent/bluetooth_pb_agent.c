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
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <contacts.h>

#include <TapiUtility.h>
#include <ITapiSim.h>

#include "vconf.h"
#include "vconf-keys.h"
#include "bluetooth_pb_agent.h"
#include "bluetooth_pb_vcard.h"

#define BLUETOOTH_PB_AGENT_TIMEOUT 600
#define SIM_ADDRESSBOOK_PREFIX "http://tizen.samsung.com/addressbook/sim"


typedef struct {
	TapiHandle *tapi_handle;
	gchar *tel_number;
	guint timeout_id;

	PhoneBookType pb_type;
} BluetoothPbAgent;

static BluetoothPbAgent *agent;

enum {
	CLEAR,
	LAST_SIGNAL
};

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

GDBusConnection *pbap_gdbus_conn = NULL;
guint bus_id;
guint pb_agent_registration_id;
guint pb_at_agent_registration_id;

static GDBusNodeInfo *pbap_introspection_data;
static guint total_missed_call_count = 0;
static guint unnotified_missed_call_count = 0;

static GMainLoop *mainloop = NULL;

/*Below Inrospection data is exposed to bluez from agent*/
static const gchar pbap_introspection_xml[] =
"<node name='/'>"
"	<interface name='org.bluez.PbAgent'>"
"		<method name='GetPhonebookFolderList'>"
"			<arg type='as' name='folder_list' direction='out'/>"
"		</method>"
"		<method name='GetPhonebook'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='name'/>"
"			<arg type='t' name='filter'/>"
"			<arg type='y' name='format'/>"
"			<arg type='q' name='max_list_count'/>"
"			<arg type='q' name='list_start_offset'/>"
"			<arg type='as' name='phonebook' direction='out'/>"
"			<arg type='u' name='new_missed_call' direction='out'/>"
"		</method>"
"		<method name='GetPhonebookSize'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='name'/>"
"			<arg type='u' name='phonebook_size' direction='out'/>"
"			<arg type='u' name='new_missed_call' direction='out'/>"
"		</method>"
"		<method name='GetPhonebookList'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='name'/>"
"			<arg type='a(ssu)' name='phonebook_list' direction='out'/>"
"			<arg type='u' name='new_missed_call' direction='out'/>"
"		</method>"
"		<method name='GetPhonebookEntry'>"
"			<anno-tation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='folder'/>"
"			<arg type='s' name='id'/>"
"			<arg type='t' name='filter'/>"
"			<arg type='y' name='format'/>"
"			<arg type='s' name='phonebook_entry' direction='out'/>"
"		</method>"
"		<method name='GetTotalObjectCount'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='path'/>"
"			<arg type='u' name='phonebook_size' direction='out'/>"
"		</method>"
"		<method name='AddContact'>"
"			<arg type='s' name='filename'/>"
"		</method>"
"	</interface>"
"	<interface name='org.bluez.PbAgent.At'>"
"		<method name='GetPhonebookSizeAt'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='command'/>"
"			<arg type='u' name='phonebook_size' direction='out'/>"
"		</method>"
"		<method name='GetPhonebookEntriesAt'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='command'/>"
"			<arg type='i' name='start_index'/>"
"			<arg type='i' name='end_index'/>"
"			<arg type='a(ssu)' name='phonebook_entries' direction='out'/>"
"		</method>"
"		<method name='GetPhonebookEntriesFindAt'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='command'/>"
"			<arg type='s' name='find_text'/>"
"			<arg type='a(ssu)' name='phonebook_entries' direction='out'/>"
"		</method>"
"	</interface>"
"</node>";

static gboolean bluetooth_pb_destroy_agent(void);

static gboolean __bluetooth_pb_agent_dbus_init(void);
static PhoneBookType __bluetooth_pb_get_pb_type(const char *name);

static PhoneBookType __bluetooth_pb_get_storage_pb_type(const char *name);

static gint __bluetooth_pb_phone_log_filter_append(contacts_filter_h filter,
						gint *match,
						gint size);

static contacts_query_h __bluetooth_pb_query_phone_log(gint *match,
						gint size);

static contacts_query_h __bluetooth_pb_query_person(int addressbook);

static contacts_query_h __bluetooth_pb_query_person_number(void);

static contacts_query_h __bluetooth_pb_query_phone_log_incoming(void);

static contacts_query_h __bluetooth_pb_query_phone_log_outgoing(void);

static contacts_query_h __bluetooth_pb_query_phone_log_missed(void);

static contacts_query_h __bluetooth_pb_query_phone_log_combined(void);

static gboolean __bluetooth_pb_get_count(PhoneBookType pb_type,
				guint *count);

static gboolean __bluetooth_pb_get_count_new_missed_call(guint *count);

static const char *__bluetooth_pb_phone_log_get_log_type(contacts_record_h record);

static void __bluetooth_pb_get_vcards(PhoneBookType pb_type,
				guint64 filter,
				guint8 format,
				guint16 max_list_count,
				guint16 list_start_offset,
				GVariantBuilder *builder);

static void __bluetooth_pb_get_contact_list(contacts_query_h query,
					GVariantBuilder *builder);

static void __bluetooth_pb_get_phone_log_list(contacts_query_h query,
					GVariantBuilder *builder);

static void __bluetooth_pb_get_list(PhoneBookType pb_type,
				GVariantBuilder *builder);

static void __bluetooth_pb_get_contact_list_number(contacts_query_h query,
						gint start_index,
						gint end_index,
						GVariantBuilder *builder);

static void __bluetooth_pb_get_phone_log_list_number(contacts_query_h query,
						gint start_index,
						gint end_index,
						GVariantBuilder *builder);

static void __bluetooth_pb_get_list_number(PhoneBookType pb_type,
						gint start_index,
						gint end_index,
						GVariantBuilder *builder);

static void __bluetooth_pb_get_contact_list_name(contacts_query_h query,
						const gchar *find_text,
						GVariantBuilder *builder);

static void __bluetooth_pb_get_phone_log_list_name(contacts_query_h query,
						const gchar *find_text,
						GVariantBuilder *builder);

static void __bluetooth_pb_get_list_name(PhoneBookType pb_type,
					const gchar *find_text,
					GVariantBuilder *builder);

static void __bluetooth_pb_list_ptr_array_add(GVariantBuilder *builder,
						const gchar *name,
						const gchar *number,
						gint handle);

static void __bluetooth_pb_agent_timeout_add_seconds(BluetoothPbAgent *agent);

static gboolean __bluetooth_pb_agent_timeout_calback(gpointer user_data);

static GQuark __bt_pbap_agent_error_quark(void)
{
	FN_START;

	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string("pbap-agent");

	FN_END;
	return quark;
}

static GError *__bt_pbap_agent_set_error(bt_pbap_agent_error_t error)
{
	FN_START;
	ERR("error[%d]\n", error);

	switch (error) {
	case BT_PBAP_AGENT_ERROR_NOT_AVAILABLE:
		return g_error_new(BT_PBAP_AGENT_ERROR, error,
					BT_ERROR_NOT_AVAILABLE);
	case BT_PBAP_AGENT_ERROR_NOT_CONNECTED:
	return g_error_new(BT_PBAP_AGENT_ERROR, error,
					BT_ERROR_NOT_CONNECTED);
	case BT_PBAP_AGENT_ERROR_BUSY:
		return g_error_new(BT_PBAP_AGENT_ERROR, error,
						BT_ERROR_BUSY);
	case BT_PBAP_AGENT_ERROR_INVALID_PARAM:
		return g_error_new(BT_PBAP_AGENT_ERROR, error,
						BT_ERROR_INVALID_PARAM);
	case BT_PBAP_AGENT_ERROR_ALREADY_EXSIST:
		return g_error_new(BT_PBAP_AGENT_ERROR, error,
						BT_ERROR_ALREADY_EXSIST);
	case BT_PBAP_AGENT_ERROR_ALREADY_CONNECTED:
		return g_error_new(BT_PBAP_AGENT_ERROR, error,
						BT_ERROR_ALREADY_CONNECTED);
	case BT_PBAP_AGENT_ERROR_NO_MEMORY:
		return g_error_new(BT_PBAP_AGENT_ERROR, error,
						BT_ERROR_NO_MEMORY);
	case BT_PBAP_AGENT_ERROR_I_O_ERROR:
		return g_error_new(BT_PBAP_AGENT_ERROR, error,
						BT_ERROR_I_O_ERROR);
	case BT_PBAP_AGENT_ERROR_OPERATION_NOT_AVAILABLE:
		return g_error_new(BT_PBAP_AGENT_ERROR, error,
					BT_ERROR_OPERATION_NOT_AVAILABLE);
	case BT_PBAP_AGENT_ERROR_INTERNAL:
	default:
		return g_error_new(BT_PBAP_AGENT_ERROR, error,
						BT_ERROR_INTERNAL);
	}
	FN_END;
}
static gboolean bluetooth_pb_get_phonebook_folder_list(GDBusMethodInvocation *context)
{
	FN_START;
	gint size;
	gint i;
	gchar *folder;
	GVariantBuilder *builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	GVariant *value;

	DBG("+");
	size = G_N_ELEMENTS(bluetooth_pb_agent_folder_list);

	for (i = 0; i < size; i++) {
		folder = g_strdup(bluetooth_pb_agent_folder_list[i]);
		if (folder)
			g_variant_builder_add(builder, "(s)", folder);
	}

	value = g_variant_new("as", builder);
	g_dbus_method_invocation_return_value(context, value);

	FN_END;
	return TRUE;
}

static gboolean bluetooth_pb_get_phonebook(const char *name,
					guint64 filter,
					guint8 format,
					guint16 max_list_count,
					guint16 list_start_offset,
					GDBusMethodInvocation *context)
{
	FN_START;
	PhoneBookType pb_type = TELECOM_NONE;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;

	DBG("name: %s filter: %lld format: %d max_list_count: %d list_start_offset: %d\n",
			name, filter, format, max_list_count, list_start_offset);

	pb_type = __bluetooth_pb_get_pb_type(name);

	if (pb_type == TELECOM_NONE) {
		__bt_pbap_agent_set_error(BT_PBAP_AGENT_ERROR_NOT_AVAILABLE);
		return FALSE;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("(as)"));

	if (max_list_count > 0) {
		__bluetooth_pb_get_vcards(pb_type,
				filter, format,
				max_list_count, list_start_offset,
				builder);

	}

	if (pb_type == TELECOM_MCH) {
		value = g_variant_new("((as)u)", builder, unnotified_missed_call_count);
		INFO("Notified [%d] missed call count", unnotified_missed_call_count);
		unnotified_missed_call_count = 0;
	} else {
		value = g_variant_new("((as)u)", builder, 0);
	}

	g_dbus_method_invocation_return_value(context, value);

	FN_END;
	return TRUE;
}

static gboolean bluetooth_pb_get_phonebook_size(const char *name,
						GDBusMethodInvocation *context)
{
	FN_START;
	PhoneBookType pb_type = TELECOM_NONE;
	guint count = 0;
	GVariant *value;

	DBG_SECURE("name: %s\n", name);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_pb_type(name);

	if (__bluetooth_pb_get_count(pb_type, &count) == FALSE) {
		__bt_pbap_agent_set_error(BT_PBAP_AGENT_ERROR_NOT_AVAILABLE);
		return FALSE;
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
		value = g_variant_new("uu", count, unnotified_missed_call_count);
		INFO("Notified [%d] missed call count", unnotified_missed_call_count);
		unnotified_missed_call_count = 0;
	} else {
		value = g_variant_new("(uu)", count, 0);
	}

	g_dbus_method_invocation_return_value(context, value);

	FN_END;
	return TRUE;
}


static gboolean bluetooth_pb_get_phonebook_list(const char *name,
						GDBusMethodInvocation *context)
{
	FN_START;
	PhoneBookType pb_type = TELECOM_NONE;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;

	DBG_SECURE("name: %s\n", name);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_pb_type(name);

	if (pb_type == TELECOM_NONE) {
		__bt_pbap_agent_set_error(BT_PBAP_AGENT_ERROR_NOT_AVAILABLE);
		return FALSE;
	}
	builder = g_variant_builder_new(G_VARIANT_TYPE("(a(ssu))"));

	__bluetooth_pb_get_list(pb_type, builder);

	INFO("pb_type[%d] / number of missed_call[%d]", pb_type, unnotified_missed_call_count);

	if (pb_type == TELECOM_MCH) {
		value = g_variant_new("((a(ssu))u)", unnotified_missed_call_count, builder);
		INFO("Notified [%d] missed call count", unnotified_missed_call_count);
		unnotified_missed_call_count = 0;
	} else {
		value = g_variant_new("((a(ssu))u)", unnotified_missed_call_count, builder);
	}

	g_dbus_method_invocation_return_value(context, value);

	FN_END;
	return TRUE;
}


static gboolean bluetooth_pb_get_phonebook_entry(const gchar *folder,
						const gchar *id,
						guint64 filter,
						guint8 format,
						GDBusMethodInvocation *context)
{
	FN_START;
	PhoneBookType pb_type = TELECOM_NONE;

	gint handle = 0;
	gchar *str = NULL;
	GVariant *value;

	const gchar *attr = NULL;

	DBG_SECURE("folder: %s id: %s filter: %ld format: %d\n",
			folder, id, filter, format);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	if (!g_str_has_suffix(id, ".vcf")) {
		__bt_pbap_agent_set_error(BT_PBAP_AGENT_ERROR_INVALID_PARAM);
		return FALSE;
	}

	handle = (gint)g_ascii_strtoll(id, NULL, 10);

	pb_type = __bluetooth_pb_get_pb_type(folder);

	if (pb_type == TELECOM_NONE) {
		__bt_pbap_agent_set_error(BT_PBAP_AGENT_ERROR_NOT_AVAILABLE);
		return FALSE;
	}

	/* create index cache */
	__bluetooth_pb_get_list(pb_type, NULL);

	switch(pb_type) {
	case TELECOM_PB:
		if (handle == 0) {
			str = _bluetooth_pb_vcard_contact_owner(agent->tel_number,
								filter, format);
		} else {
			if (_bluetooth_get_contact_addressbook(handle) == PBAP_ADDRESSBOOK_PHONE)
				str = _bluetooth_pb_vcard_contact(handle, filter, format);
		}
		break;
	case TELECOM_ICH:
		str = _bluetooth_pb_vcard_call(handle, filter, format, "RECEIVED");
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
				str = _bluetooth_pb_vcard_contact(handle, filter, format);
		}
		break;
#endif
	default:
		__bt_pbap_agent_set_error(BT_PBAP_AGENT_ERROR_APPLICATION);


		return FALSE;
	}

	value = g_variant_new("s", str);

	g_dbus_method_invocation_return_value(context, value);
	g_free(str);

	FN_END;
	return TRUE;
}

static gboolean bluetooth_pb_get_phonebook_size_at(const gchar *command,
				GDBusMethodInvocation *context)
{
	FN_START;
	PhoneBookType pb_type = TELECOM_NONE;
	guint count = 0;
	GVariant *value;

	DBG("command: %s\n", command);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_storage_pb_type(command);

	if (__bluetooth_pb_get_count(pb_type, &count) == FALSE) {
		__bt_pbap_agent_set_error(BT_PBAP_AGENT_ERROR_NOT_AVAILABLE);
		return FALSE;
	}
	value = g_variant_new("u", count);

	g_dbus_method_invocation_return_value(context, value);

	FN_END;
	return TRUE;
}


static gboolean bluetooth_pb_get_phonebook_entries_at(const gchar *command,
					gint start_index,
					gint end_index,
					GDBusMethodInvocation *context)
{
	FN_START;
	PhoneBookType pb_type = TELECOM_NONE;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;

	DBG("command: %s, start_index: %d, end_index: %d\n",
			command, start_index, end_index);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_storage_pb_type(command);

	if (pb_type == TELECOM_NONE || pb_type == TELECOM_CCH) {
		__bt_pbap_agent_set_error(BT_PBAP_AGENT_ERROR_APPLICATION);
		return FALSE;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("(a(ssu))"));

	__bluetooth_pb_get_list_number(pb_type,
			start_index, end_index,
			builder);

	value = g_variant_new("a(ssu)", builder);

	g_dbus_method_invocation_return_value(context, value);

	FN_END;
	return TRUE;
}


static gboolean bluetooth_pb_get_phonebook_entries_find_at(const gchar *command,
					const gchar *find_text,
					GDBusMethodInvocation *context)
{
	FN_START;
	PhoneBookType pb_type = TELECOM_NONE;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;

	DBG("command: %s, find text: %s\n", command, find_text);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_storage_pb_type(command);

	if (pb_type == TELECOM_NONE || pb_type == TELECOM_CCH) {
		__bt_pbap_agent_set_error(BT_PBAP_AGENT_ERROR_APPLICATION);
		return FALSE;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("(a(ssu))"));

	__bluetooth_pb_get_list_name(pb_type,
			find_text, builder);

	value = g_variant_new("a(ssu)", builder);

	g_dbus_method_invocation_return_value(context, value);

	FN_END;
	return TRUE;
}

static gboolean bluetooth_pb_get_total_object_count(gchar *path,
					GDBusMethodInvocation *context)
{
	FN_START;
	guint count = 0;
	PhoneBookType pb_type = TELECOM_NONE;
	GVariant *value;

	DBG("%s() %d\n", __FUNCTION__, __LINE__);

	__bluetooth_pb_agent_timeout_add_seconds(agent);

	pb_type = __bluetooth_pb_get_storage_pb_type(path);

	if (__bluetooth_pb_get_count(pb_type, &count) == FALSE) {
		__bt_pbap_agent_set_error(BT_PBAP_AGENT_ERROR_NOT_AVAILABLE);
		return FALSE;
	}

	value = g_variant_new("u", count);

	g_dbus_method_invocation_return_value(context, value);

	DBG("%s() %d\n", __FUNCTION__, __LINE__);

	FN_END;
	return TRUE;
}

static gboolean bluetooth_pb_add_contact(const char *filename, 
				GDBusMethodInvocation *context)
{
	FN_START;
	/* Contact API is changed, Temporary blocked */

	FN_END;
	return TRUE;
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

	if (g_strcmp0(name, "\"ME\"") == 0 )
		return TELECOM_PB;

	if (g_strcmp0(name, "\"RC\"") == 0)
		return TELECOM_ICH;

	if (g_strcmp0(name, "\"DC\"") == 0)
		return TELECOM_OCH;

	if (g_strcmp0(name, "\"MC\"") == 0)
		return TELECOM_MCH;

	FN_END;
	return TELECOM_NONE;
}

static gint __bluetooth_pb_phone_log_filter_append(contacts_filter_h filter,
						gint *match,
						gint size)
{
	FN_START;
	gint i;
	gint status;

	for (i = 0; i < size; i++) {

		if ( i > 0) {
			status = contacts_filter_add_operator(filter,
					CONTACTS_FILTER_OPERATOR_OR);

			if (status != CONTACTS_ERROR_NONE)
				return status;
		}

		status = contacts_filter_add_int(filter,
				_contacts_phone_log.log_type,
				CONTACTS_MATCH_EQUAL,
				match[i]);

		if (status != CONTACTS_ERROR_NONE)
			return status;
	}

	FN_END;
	return CONTACTS_ERROR_NONE;
}

static contacts_query_h __bluetooth_pb_query_phone_log(gint *match,
						gint size)
{
	FN_START;
	contacts_query_h query = NULL;
	contacts_filter_h filter = NULL;

	gint status;

	status = contacts_query_create(_contacts_phone_log._uri,
				&query);

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

	status = contacts_query_set_sort(query,
			_contacts_phone_log.log_time,
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

	char* addressbook_name = NULL;
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
	contacts_db_get_all_records(_contacts_address_book._uri, 0, 0, &recordList);
	contacts_filter_create(_contacts_person_contact._uri, &filter);
	contacts_list_get_count(recordList, &count);

	for (i = 0; i < count; i++) {
		status = contacts_list_get_current_record_p(recordList, &record);
		if (status != CONTACTS_ERROR_NONE) {
			ERR("Contact list get api failed %d", status);
			goto next;
		}
		status = contacts_record_get_str_p(record, _contacts_address_book.name,
					&addressbook_name);
		if (status != CONTACTS_ERROR_NONE) {
			ERR("Contact record get api failed %d", status);
			goto next;
		}
		status = contacts_record_get_int(record, _contacts_address_book.id,
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

	status = contacts_query_create(_contacts_person_number._uri,
				&query);

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

	status = contacts_record_get_int(record,
			_contacts_phone_log.log_type,
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

static void __bluetooth_pb_get_vcards(PhoneBookType pb_type,
				guint64 filter,
				guint8 format,
				guint16 max_list_count,
				guint16 list_start_offset,
				GVariantBuilder *builder)
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

	if ( max_list_count >= 65535)
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
				g_variant_builder_add(builder, "(s)", vcard);

			offset = 0;

			if (limit == 1)
				return;
			else if (limit > 1)
				limit--;
		}

		if (pb_type == TELECOM_PB)
			query = __bluetooth_pb_query_person(PBAP_ADDRESSBOOK_PHONE);
#ifdef PBAP_SIM_ENABLE
		else if(pb_type == SIM_PB)
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

	/* When limit is passed as ZERO to contacts_db_get_records_with_query API
	 * then this API will provide all available contacts in its database (unrestricted).
	 * Now consider a case when client requests for maxlistcount of 1 and start offset as 0
	 * then we have already read the owner card in above switch case and when it reads owner
	 * card it decrements the limit by 1.
	 */
	if(limit != 0)
	{
		status = contacts_db_get_records_with_query(query, offset, limit, &record_list);

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

			record = NULL;
			status = contacts_list_get_current_record_p(record_list, &record);

			if (status != CONTACTS_ERROR_NONE)
				continue;
			id = 0;
			status = contacts_record_get_int(record, property_id, &id);

			if (status != CONTACTS_ERROR_NONE)
				continue;

			if (property_id == _contacts_person.id)
				vcard = _bluetooth_pb_vcard_contact(id, filter, format);
			else {
				if (get_log)
					attr = __bluetooth_pb_phone_log_get_log_type(record);

				vcard = _bluetooth_pb_vcard_call(id, filter, format, attr);
			}

			if (vcard)
				g_variant_builder_add(builder, "(s)", vcard);

		} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);
		contacts_list_destroy(record_list, TRUE);
	}

	contacts_query_destroy(query);

	FN_END;
}

static void __bluetooth_pb_get_contact_list(contacts_query_h query,
					GVariantBuilder *builder)
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

		__bluetooth_pb_list_ptr_array_add(builder,
				name, agent->tel_number, 0);

		g_free(name);
	}

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

		gint id;

		record = NULL;
		status = contacts_list_get_current_record_p(record_list,
				&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		id = 0;
		status = contacts_record_get_int(record,
				_contacts_person_contact.person_id,
				&id);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		/* create list */
		if (builder) {
			gchar *name;
			gchar *number;

			name = _bluetooth_pb_name_from_person_id(id);
			number = _bluetooth_pb_number_from_person_id(id);

			__bluetooth_pb_list_ptr_array_add(builder,
					name, number, id);

			g_free(name);
			g_free(number);
		}

	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);

	contacts_list_destroy(record_list, TRUE);
	FN_END;
}

static void __bluetooth_pb_get_phone_log_list(contacts_query_h query,
					GVariantBuilder *builder)
{
	FN_START;
	contacts_list_h record_list = NULL;

	gint status;

	status = contacts_db_get_records_with_query(query,
			-1, -1, &record_list);

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

		record = NULL;
		status = contacts_list_get_current_record_p(record_list,
				&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		id = 0;
		status = contacts_record_get_int(record,
				_contacts_phone_log.id,
				&id);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		/* create list */
		if (builder) {
			gchar *name;
			gchar *number;

			name = _bluetooth_pb_name_from_phonelog_id(id);

			number = NULL;
			contacts_record_get_str_p(record,
					_contacts_phone_log.address,
					&number);

			__bluetooth_pb_list_ptr_array_add(builder,
					name, number, id);

			g_free(name);
		}

	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);

	contacts_list_destroy(record_list, TRUE);
	FN_END;
}


static void __bluetooth_pb_get_list(PhoneBookType pb_type,
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
		__bluetooth_pb_get_contact_list(query, builder);
		break;
	case TELECOM_ICH:
		query = __bluetooth_pb_query_phone_log_incoming();
		__bluetooth_pb_get_phone_log_list(query, builder);
		break;
	case TELECOM_OCH:
		query = __bluetooth_pb_query_phone_log_outgoing();
		__bluetooth_pb_get_phone_log_list(query, builder);
		break;
	case TELECOM_MCH:
		query = __bluetooth_pb_query_phone_log_missed();
		__bluetooth_pb_get_phone_log_list(query, builder);
		break;
	case TELECOM_CCH:
		query = __bluetooth_pb_query_phone_log_combined();
		__bluetooth_pb_get_phone_log_list(query, builder);
		break;
#ifdef PBAP_SIM_ENABLE
	case SIM_PB:
		query = __bluetooth_pb_query_person(PBAP_ADDRESSBOOK_SIM);
		__bluetooth_pb_get_contact_list(query, builder);
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

static void __bluetooth_pb_get_contact_list_number(contacts_query_h query,
						gint start_index,
						gint end_index,
						GVariantBuilder *builder)
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

	status = contacts_db_get_records_with_query(query,
			from - 1 , offset,
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

		record = NULL;
		status = contacts_list_get_current_record_p(record_list,
				&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		display_name = NULL;
		number = NULL;

		contacts_record_get_str_p(record,
				_contacts_person_number.display_name,
				&display_name);
		contacts_record_get_str_p(record,
				_contacts_person_number.number,
				&number);

		__bluetooth_pb_list_ptr_array_add(builder,
				display_name, number, i);

		i++;
	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);

	contacts_list_destroy(record_list, TRUE);
	FN_END;
}

static void __bluetooth_pb_get_phone_log_list_number(contacts_query_h query,
						gint start_index,
						gint end_index,
						GVariantBuilder *builder)
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

	status = contacts_db_get_records_with_query(query,
			from - 1 , offset,
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
		contacts_record_h record = NULL;

		gint id;

		gchar *display_name;
		gchar *number;

		record = NULL;
		status = contacts_list_get_current_record_p(record_list,
				&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		id = 0;
		status = contacts_record_get_int(record,
				_contacts_phone_log.id,
				&id);
		if (status != CONTACTS_ERROR_NONE) {
			ERR("contact_record_get_int api failed %d", status);
			continue;
		}

		display_name = _bluetooth_pb_fn_from_phonelog_id(id);

		number = NULL;
		contacts_record_get_str_p(record,
				_contacts_phone_log.address,
				&number);


		__bluetooth_pb_list_ptr_array_add(builder,
				display_name, number, i);

		i++;

		g_free(display_name);

	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);

	contacts_list_destroy(record_list, TRUE);
	FN_END;
}

static void __bluetooth_pb_get_list_number(PhoneBookType pb_type,
						gint start_index,
						gint end_index,
						GVariantBuilder *builder)
{
	FN_START;
	contacts_query_h query;

	switch (pb_type) {
	case TELECOM_PB:
		query = __bluetooth_pb_query_person_number();
		__bluetooth_pb_get_contact_list_number(query,
				start_index, end_index, builder);
		break;
	case TELECOM_ICH:
		query = __bluetooth_pb_query_phone_log_incoming();
		__bluetooth_pb_get_phone_log_list_number(query,
				start_index, end_index, builder);
		break;
	case TELECOM_OCH:
		query = __bluetooth_pb_query_phone_log_outgoing();
		__bluetooth_pb_get_phone_log_list_number(query,
				start_index, end_index, builder);
		break;
	case TELECOM_MCH:
		query = __bluetooth_pb_query_phone_log_missed();
		__bluetooth_pb_get_phone_log_list_number(query,
				start_index, end_index, builder);
		break;
	case TELECOM_CCH:
		query = __bluetooth_pb_query_phone_log_combined();
		__bluetooth_pb_get_phone_log_list_number(query,
				start_index, end_index, builder);
		break;
	default:
		return;
	}

	if (query)
		contacts_query_destroy(query);
	FN_END;
}

static void __bluetooth_pb_get_contact_list_name(contacts_query_h query,
						const gchar *find_text,
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

		record = NULL;
		status = contacts_list_get_current_record_p(record_list,
				&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		display_name = NULL;
		contacts_record_get_str_p(record,
				_contacts_person_number.display_name,
				&display_name);

		if (g_str_has_prefix(display_name, find_text)) {
			gchar *number;

			number = NULL;
			contacts_record_get_str_p(record,
					_contacts_person_number.number,
					&number);

			__bluetooth_pb_list_ptr_array_add(builder,
					display_name, number, i);
		}

		i++;
	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);
	contacts_list_destroy(record_list, TRUE);
	FN_END;
}

static void __bluetooth_pb_get_phone_log_list_name(contacts_query_h query,
						const gchar *find_text,
						GVariantBuilder *builder)
{
	FN_START;
	contacts_list_h record_list = NULL;

	gint status;

	gint i = 1;

	status = contacts_db_get_records_with_query(query,
			-1, -1,
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
		contacts_record_h record = NULL;

		gint id;

		gchar *display_name;

		record = NULL;
		status = contacts_list_get_current_record_p(record_list,
				&record);

		if (status != CONTACTS_ERROR_NONE)
			continue;

		id = 0;
		status = contacts_record_get_int(record,
				_contacts_phone_log.id,
				&id);
		if (status != CONTACTS_ERROR_NONE) {
			ERR("contacts_record_get_int failed %d", status);
			continue;
		}

		display_name = _bluetooth_pb_fn_from_phonelog_id(id);

		if (g_str_has_prefix(display_name, find_text)) {
			gchar *number = NULL;

			number = NULL;
			contacts_record_get_str_p(record,
					_contacts_phone_log.address,
					&number);

			__bluetooth_pb_list_ptr_array_add(builder,
					display_name, number, i);
		}

		i++;

		g_free(display_name);

	} while (contacts_list_next(record_list) == CONTACTS_ERROR_NONE);

	contacts_list_destroy(record_list, TRUE);
	FN_END;
}

static void __bluetooth_pb_get_list_name(PhoneBookType pb_type,
					const gchar *find_text,
					GVariantBuilder *builder)
{
	FN_START;
	contacts_query_h query;

	switch (pb_type) {
	case TELECOM_PB:
		query = __bluetooth_pb_query_person_number();
		__bluetooth_pb_get_contact_list_name(query,
				find_text, builder);
		break;
	case TELECOM_ICH:
		query = __bluetooth_pb_query_phone_log_incoming();
		__bluetooth_pb_get_phone_log_list_name(query,
				find_text, builder);
		break;
	case TELECOM_OCH:
		query = __bluetooth_pb_query_phone_log_outgoing();
		__bluetooth_pb_get_phone_log_list_name(query,
				find_text, builder);
		break;
	case TELECOM_MCH:
		query = __bluetooth_pb_query_phone_log_missed();
		__bluetooth_pb_get_phone_log_list_name(query,
				find_text, builder);
		break;
	case TELECOM_CCH:
		query = __bluetooth_pb_query_phone_log_combined();
		__bluetooth_pb_get_phone_log_list_name(query,
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
						const gchar *name,
						const gchar *number,
						gint handle)
{
	FN_START;

	g_variant_builder_add(builder, "{ssu}", name, number, handle);

	FN_END;
}

static void handle_pbap_method_call(GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *method_name,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	DBG("method: %s", method_name);

	if (g_strcmp0(method_name, "GetPhonebookFolderList") == 0) {
		bluetooth_pb_get_phonebook_folder_list(invocation);
	} else if (g_strcmp0(method_name, "GetPhonebook") == 0) {
		gchar *name;
		guint64 filter;
		guint8 format;
		guint16 max_list_count;
		guint16 list_start_offset;

		g_variant_get(parameters, "styqq", &name, &filter, &format,
					&max_list_count, &list_start_offset);
		bluetooth_pb_get_phonebook(name, filter, format,
					max_list_count, list_start_offset, invocation);
	} else if (g_strcmp0(method_name, "GetPhonebookSize") == 0) {
		gchar *name;

		g_variant_get(parameters, "s", &name);
		bluetooth_pb_get_phonebook_size(name, invocation);
	} else if (g_strcmp0(method_name, "GetPhonebookList") == 0) {
		gchar *name;

		g_variant_get(parameters, "s", &name);
		bluetooth_pb_get_phonebook_list(name, invocation);
	} else if (g_strcmp0(method_name, "GetPhonebookEntry") == 0) {
		gchar *folder;
		gchar *id;
		guint64 filter;
		guint8 format;

		g_variant_get(parameters, "ssty", &folder, &id, &filter, &format);

		bluetooth_pb_get_phonebook_entry(folder, id, filter, format, invocation);
	} else if (g_strcmp0(method_name, "GetTotalObjectCount") == 0) {
		gchar *path;

		g_variant_get(parameters, "s", &path);
		bluetooth_pb_get_total_object_count(path, invocation);
	} else if (g_strcmp0(method_name, "AddContact") == 0) {
		gchar *filename;

		g_variant_get(parameters, "s", &filename);
		bluetooth_pb_add_contact(filename, invocation);
	} else if (g_strcmp0(method_name, "DestroyAgent") == 0) {
		DBG("DestroyAgent");
		bluetooth_pb_destroy_agent();
	} else {
		DBG("Unknown Method");
	}
}

static void handle_pbap_at_method_call(GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *method_name,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	DBG("method: %s", method_name);

	if (g_strcmp0(method_name, "GetPhonebookSizeAt") == 0) {
		gchar *command;

		g_variant_get(parameters, "s", &command);
		bluetooth_pb_get_phonebook_size_at(command, invocation);
	} else if (g_strcmp0(method_name, "GetPhonebookEntriesAt") == 0) {
		gchar *command;
		int start_idx;
		int end_idx;

		g_variant_get(parameters, "sii", &command, &start_idx, &end_idx);
		bluetooth_pb_get_phonebook_entries_at(command, start_idx, end_idx, invocation);
	} else if (g_strcmp0(method_name, "GetPhonebookEntriesFindAt") == 0) {
		gchar *command;
		gchar *find_text;

		g_variant_get(parameters, "ss", &command, &find_text);
		bluetooth_pb_get_phonebook_entries_find_at(command, find_text, invocation);
	} else {
		DBG("Unknown Method");
	}
}


static const GDBusInterfaceVTable pbap_interface_handle = {
	handle_pbap_method_call,
	NULL,
	NULL
};

static const GDBusInterfaceVTable pbap_st_interface_handle = {
	handle_pbap_at_method_call,
	NULL,
	NULL
};

static GDBusConnection *__bt_pbap_get_gdbus_connection(void)
{
	FN_START;

	GError *err = NULL;

	if (pbap_gdbus_conn)
		return pbap_gdbus_conn;

	pbap_gdbus_conn = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &err);
	if (!pbap_gdbus_conn) {
		if (err) {
			ERR("Unable to connect to dbus: %s", err->message);
			g_clear_error(&err);
		}
		return NULL;
	}

	FN_END;
	return pbap_gdbus_conn;
}

static void __bluetooth_pb_agent_signal_handler(int signum)
{
	FN_START;
	if (mainloop) {
		g_main_loop_quit(mainloop);
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

	DBG("Received contact changed cb");

	__bluetooth_pb_get_count_new_missed_call(&new_missed_call);

	if (new_missed_call > total_missed_call_count)
		unnotified_missed_call_count += new_missed_call - total_missed_call_count;

	INFO("Missed call count : #prev[%d], #current[%d], #unnotified[%d]",
		total_missed_call_count, new_missed_call, unnotified_missed_call_count);

	total_missed_call_count = new_missed_call;
	FN_END;
}

static void __bluetooth_pb_agent_timeout_add_seconds(BluetoothPbAgent *agent)
{
	FN_START;

	if(agent->timeout_id)
		g_source_remove(agent->timeout_id);

	agent->timeout_id = g_timeout_add_seconds(BLUETOOTH_PB_AGENT_TIMEOUT,
				__bluetooth_pb_agent_timeout_calback,
				agent);
	FN_END;
}


static gboolean __bluetooth_pb_agent_timeout_calback(gpointer user_data)
{
	FN_START;

	agent->timeout_id = 0;

	if (mainloop)
		g_main_loop_quit(mainloop);

	FN_END;
	return FALSE;
}

static void __bluetooth_pb_tel_callback(TapiHandle *handle,
					int result,
					void *data,
					void *user_data)
{
	FN_START;
	TelSimMsisdnList_t *number;

	__bluetooth_pb_agent_dbus_init();

	if (data != NULL) {
		number = (TelSimMsisdnList_t *)data;
		agent->tel_number = g_strdup(number->list[0].num);
	}

	tel_deinit(agent->tapi_handle);
	agent->tapi_handle = NULL;
	FN_END;
}

static void pb_agent_init(void)
{
	FN_START;

	agent->tapi_handle = NULL;
	agent->tel_number = NULL;
	agent->timeout_id = 0;
	agent->pb_type = TELECOM_NONE;

	FN_END;
}

static gboolean __bluetooth_pb_agent_dbus_init(void)
{
	FN_START;
	guint owner_id;
	GError *error = NULL;
	GDBusConnection *gdbus_conn = __bt_pbap_get_gdbus_connection();

	if (gdbus_conn == NULL) {
		ERR("Error in creating the gdbus connection");
		return FALSE;
	}

	owner_id = g_bus_own_name(G_BUS_TYPE_SESSION,
			BT_PB_SERVICE_NAME,
			G_BUS_NAME_OWNER_FLAGS_NONE,
			NULL, NULL, NULL,
			NULL, NULL);
	DBG("owner_id is [%d]", owner_id);

	pbap_introspection_data =
		g_dbus_node_info_new_for_xml(pbap_introspection_xml, NULL);

	if (pbap_introspection_data == NULL)
		return FALSE;

	pb_agent_registration_id = g_dbus_connection_register_object(
				gdbus_conn,
				BT_PB_SERVICE_OBJECT_PATH,
				pbap_introspection_data->
					interfaces[0],
				&pbap_interface_handle,
				NULL,
				NULL,
				NULL);

	g_assert(pb_agent_registration_id > 0);

	pb_at_agent_registration_id = g_dbus_connection_register_object(
			gdbus_conn,
			BT_PB_SERVICE_OBJECT_PATH,
			pbap_introspection_data->
				interfaces[1],
			&pbap_st_interface_handle,
			NULL,
			NULL,
			NULL);

	g_assert(pb_at_agent_registration_id > 0);

	if (pb_agent_registration_id == 0 || pb_at_agent_registration_id == 0) {
		ERR("Failed to register: %s", error->message);
		g_error_free(error);
		return FALSE;
	}
	pb_agent_init();

	return TRUE;
	FN_END;
}

static gboolean bluetooth_pb_destroy_agent(void)
{
	FN_START;
	g_main_loop_quit(mainloop);
	FN_END;
	return TRUE;
}

int main(void)
{
	FN_START;

	gint ret = EXIT_SUCCESS;
	gint tapi_result;

	struct sigaction sa;
	DBG("Starting Bluetooth PBAP agent");

	mainloop = g_main_loop_new(NULL, FALSE);
	if (mainloop == NULL) {
		ERR("Couldn't create GMainLoop\n");
		return EXIT_FAILURE;
	}

	pb_agent_init();

	/* connect contact */
	if (contacts_connect() != CONTACTS_ERROR_NONE) {
		ERR("Can not connect contacts server\n");
		return EXIT_FAILURE;
	}

	__bluetooth_pb_get_count_new_missed_call(&total_missed_call_count);

	if (contacts_db_add_changed_cb(_contacts_contact._uri,
			__bluetooth_pb_contact_changed,
			NULL) != CONTACTS_ERROR_NONE) {
		ERR("Can not add changed callback");
	}

	if (contacts_db_add_changed_cb(_contacts_phone_log._uri,
			__bluetooth_pb_contact_changed,
			NULL) != CONTACTS_ERROR_NONE) {
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
			__bluetooth_pb_tel_callback, NULL);

	if (tapi_result != TAPI_API_SUCCESS) {
		if (__bluetooth_pb_agent_dbus_init() == FALSE)
			goto failure;
	}
	__bluetooth_pb_agent_timeout_add_seconds(agent);

	g_main_loop_run(mainloop);

failure:
	if (contacts_db_remove_changed_cb(_contacts_phone_log._uri,
			__bluetooth_pb_contact_changed,
			NULL) != CONTACTS_ERROR_NONE) {
		ERR("Cannot remove changed callback");
	}

	if (contacts_db_remove_changed_cb(_contacts_contact._uri,
			__bluetooth_pb_contact_changed,
			NULL) != CONTACTS_ERROR_NONE) {
		ERR("Cannot remove changed callback");
	}

	if (contacts_disconnect() != CONTACTS_ERROR_NONE)
		ERR("contacts_disconnect failed \n");

	g_object_unref(agent);

	if (pb_agent_registration_id > 0) {
		g_dbus_connection_unregister_object(
			pbap_gdbus_conn,
			pb_agent_registration_id);
		pb_agent_registration_id = 0;
	}

	if (pb_at_agent_registration_id > 0) {
		g_dbus_connection_unregister_object(
			pbap_gdbus_conn,
			pb_at_agent_registration_id);
		pb_at_agent_registration_id = 0;
	}

	if (pbap_introspection_data)
		g_dbus_node_info_unref(pbap_introspection_data);

	DBG("Terminate Bluetooth PBAP agent");
	FN_END;
	return ret;
}
