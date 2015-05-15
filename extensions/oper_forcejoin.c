/*
 * Charybdis: an advanced ircd
 * skeleton ripped from ip_cloaking-5.c
 * oper_forcejoin.c: Forcejoin opers to operchans
 */

#include <openssl/hmac.h>
#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "channel.h"
#include "ircd.h"
#include "send.h"
#include "hash.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"
#include "newconf.h"
#include "s_newconf.h"

char *operfjoin = "#opers";
char *adminfjoin = "#services";

static void
conf_set_operfjoin(void *data)
{
    operfjoin = rb_strdup(data);
}

static void
conf_set_adminfjoin(void *data)
{
    adminfjoin = rb_strdup(data);
}

static int
_modinit(void)
{
    /* add the usermode to the available slot */
    add_top_conf("operchans", NULL, NULL, NULL);
    add_conf_item("operchans", "oper", CF_QSTRING, conf_set_operfjoin);
    add_conf_item("operchans", "admin", CF_QSTRING, conf_set_adminfjoin);

    return 0;
}

static void
_moddeinit(void)
{
    /* disable the umode and remove it from the available list */
    add_top_conf("operchans", NULL, NULL, NULL);
    add_conf_item("operchans", "oper", CF_QSTRING, conf_set_operfjoin);
    add_conf_item("operchans", "admin", CF_QSTRING, conf_set_adminfjoin);
}

static void check_umode_change(void *data);
int operfjoin_ujoin(struct Client *source_p, struct Channel *chptr);
mapi_hfn_list_av1 oper_forcejoin_hfnlist[] = {
    { "umode_changed", (hookfn) check_umode_change },
    { NULL, NULL }
};

DECLARE_MODULE_AV1(oper_forcejoin, _modinit, _moddeinit, NULL, NULL,
                   oper_forcejoin_hfnlist, "$Revision: 3526 $");
int
operfjoin_ujoin(struct Client *source_p, struct Channel *chptr)
{
/*   This next portion ripped from: contrib/m_ojoin.c
 *   Copyright (C) 2002 Hybrid Development Team
 *   Copyright (C) 2004 ircd-ratbox Development Team
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
    if (IsMember(source_p, chptr)) return; //Nothing to do here -- janicez
    add_user_to_channel(chptr, source_p, CHFL_PEON);
    sendto_server(source_p, chptr, CAP_TS6, NOCAPS,
                  ":%s JOIN %ld %s +",
                   source_p->id, (long) chptr->channelts, chptr->chname);
    sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN %s",
                         source_p->name,
                         source_p->username, source_p->host, chptr->chname);
    /* send the topic... */
    if(chptr->topic != NULL) {
        sendto_one(source_p, form_str(RPL_TOPIC), me.name,
                   source_p->name, chptr->chname, chptr->topic);
        sendto_one(source_p, form_str(RPL_TOPICWHOTIME), me.name,
                   source_p->name, chptr->chname, chptr->topic_info, chptr->topic_time);
    }

    source_p->localClient->last_join_time = rb_current_time();
    channel_member_names(chptr, source_p, 1);

    return 0;
}


static void
check_umode_change(void *vdata)
{
    hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
    struct Client *source_p = data->client;
    char *p = NULL;
    char *name;
    struct Channel *chptr;

    if (!MyClient(source_p))
        return;

    /* didn't oper up, we don't need to do anything */
    if (!((data->oldumodes ^ source_p->umodes) & user_modes['o']))
        return;

    if (!IsOper(source_p))
        return;

    char *jbuf;
    if (IsOperAdmin(source_p)) {
        jbuf = rb_strdup(adminfjoin);
    } else
        jbuf = rb_strdup(operfjoin);

    for(name = rb_strtok_r(jbuf, ",", &p); name;
        name = rb_strtok_r(NULL, ",", &p)) {
        if ((chptr = find_channel(name))!=NULL)
            operfjoin_ujoin(source_p, chptr);
        else
            user_join(source_p, source_p, name, NULL);
    }
}

