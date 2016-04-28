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

#ifndef __DEF_MAP_EMAIL_H_
#define __DEF_MAP_EMAIL_H_

#include <glib.h>
#include "bluetooth_map_types.h"
#include "map_bmessage.h"

gboolean _bt_map_start_email_service(void);

gboolean _bt_map_stop_email_service(void);

gboolean _bt_map_email_get_supported_folders(gboolean folders[FOLDER_COUNT][MSG_TYPES]);

gboolean _bt_map_get_email_list(char *folder, int max,
		guint8 subject_len, map_msg_filter_t *filter,
		GSList **email_list, guint64 *count, gboolean *newmsg);

gboolean _bt_map_update_mailbox(char *folder);

gboolean _bt_map_set_email_read_status(int mail_id, int read_status);

gboolean _bt_map_set_email_delete_status(int mail_id, int read_status);

gboolean _bt_map_get_email_message(int mail_id, gboolean attach,
		gboolean transcode, gboolean first_request, gchar **bmseg);

gboolean _bt_map_push_email_data(struct bmsg_data *bmsg_info,
		msg_send_option_t *option, char *folder);

#endif /* __DEF_MAP_EMAIL_H_ */
