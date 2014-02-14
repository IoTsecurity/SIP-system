#include "csenn_eXosip2.h"
#include <pthread.h>
#include "dispatch.h"
#ifndef UAS_H
#define UAS_H

int handle_invite(eXosip_event_t * g_event);

int handle_message(eXosip_event_t * g_event);

int handle_bye(eXosip_event_t * g_event);

/*解析INVITE的SDP消息体，同时保存全局INVITE连接ID和全局会话ID*/
void uas_eXosip_paraseInviteBody(eXosip_event_t *p_event);

void uas_eXosip_processEvent(void);


#endif
