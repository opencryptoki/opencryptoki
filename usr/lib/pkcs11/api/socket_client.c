/*
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

 /* (C) COPYRIGHT Google Inc. 2013 */

//
// Pkcs11 Api Socket client routines
//

#include <stdio.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <errno.h>
#include <stdlib.h>

#include "apiproto.h"
#include "slotmgr.h"
#include "apictl.h"

extern  API_Proc_Struct_t  *Anchor;
//
// Will fill out the Slot_Mgr_Socket_t structure in the Anchor global data
// structure with the values passed by the pkcsslotd via a socket RPC.
int
init_socket_data() {
	int socketfd;
	struct sockaddr_un daemon_address;
	struct stat file_info;
	struct group *grp;
	int n, bytes_received = 0;
	Slot_Mgr_Socket_t *daemon_socket_data = NULL;
	int ret = FALSE;

	if (stat(SOCKET_FILE_PATH, &file_info)) {
		OCK_SYSLOG(LOG_ERR, "init_socket_data: failed to find socket file, errno=%d", errno);
		return FALSE;
	}

	grp = getgrnam("pkcs11");
	if ( !grp ) {
		OCK_SYSLOG(LOG_ERR, "init_socket_data: pkcs11 group does not exist, errno=%d", errno);
		return FALSE;
	}

	if (file_info.st_uid != 0 || file_info.st_gid != grp->gr_gid) {
		OCK_SYSLOG(LOG_ERR, "init_socket_data: incorrect permissions on socket file");
		return FALSE;
	}

	if ((socketfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		OCK_SYSLOG(LOG_ERR, "init_socket_data: failed to create socket, errno=%d", errno);
		return FALSE;
	}

	memset(&daemon_address, 0, sizeof(struct sockaddr_un));
	daemon_address.sun_family = AF_UNIX;
	strcpy(daemon_address.sun_path, SOCKET_FILE_PATH);

	if (connect(socketfd, (struct sockaddr *) &daemon_address,
				sizeof(struct sockaddr_un)) != 0) {
		OCK_SYSLOG(LOG_ERR, "init_socket_data: failed to connect to slotmanager daemon, errno=%d",
				errno);
		goto exit;
	}

	// allocate data buffer
	daemon_socket_data = (Slot_Mgr_Socket_t*) malloc(sizeof(*daemon_socket_data));
	if (!daemon_socket_data) {
		OCK_SYSLOG(LOG_ERR, "init_socket_data: failed to \
			allocate %lu bytes \
			for daemon data, errno=%d",
			sizeof(*daemon_socket_data), errno);
		goto exit;
	}

	while (bytes_received < sizeof(*daemon_socket_data)) {
		n = read(socketfd, ((char*)daemon_socket_data)+bytes_received,
				sizeof(*daemon_socket_data)-bytes_received);
		if (n < 0) {
			// read error
			if (errno == EINTR)
				continue;
			OCK_SYSLOG(LOG_ERR, "init_socket_data: read error \
				on daemon socket, errno=%d", errno );
			goto exit;
		} else if (n == 0) {
			// eof but we still expect some bytes
			OCK_SYSLOG(LOG_ERR, "init_socket_data: read returned \
				with eof but we still \
				expect %lu bytes from daemon",
				sizeof(*daemon_socket_data)-bytes_received);
			goto exit;
		} else {
			// n > 0, we got some bytes
			bytes_received += n;
		}
	}

	ret = TRUE;

	// copy the Slot_Mgr_Socket_t struct into global
	// Anchor SocketDataPdata buffer
	memcpy(&(Anchor->SocketDataP), daemon_socket_data,
			sizeof(*daemon_socket_data));

exit:
	//free the data buffer after copy
	if (daemon_socket_data)
		free(daemon_socket_data);

	close(socketfd);

	return ret;
}
