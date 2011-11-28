/* packet-gluster.c
 *
 * Copyright (c) 2011 Niels de Vos <ndevos@redhat.com>, Red Hat UK, Ltd.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <rpc/xdr.h>
#include <string.h> /* strerror() */

#include "packet-gluster.h"

/* some debugging functions for temporary use */
#define DEBUG			printf
#define FIXME(fmt, msg...)	DEBUG("FIXME: " fmt, ##msg)
#define GETPOS(xdr)		DEBUG("xdr_pos: %d\n", xdr_getpos(xdr))

/* the main RPC decoding structure, defined at the end of this file */
static gluster_prog_t gluster_progs[];

gluster_prog_t* gluster_get_prog(uint32_t prognum, uint32_t progver);

const char* gluster_get_progname(uint32_t prognum, uint32_t progver)
{
	gluster_prog_t *prog = NULL;

	if (progver != GLUSTER_PROG_VERSION_ANY)
		prog = gluster_get_prog(prognum, progver);

	if (!prog || GLUSTER_PROG_VERSION_ANY) {
		int i = 0;

		while (gluster_progs[i].prognum != -1) {
			if (gluster_progs[i].prognum == prognum)
				prog = &gluster_progs[i];

			i++;
		}
	}

	if (prog)
		return prog->progname;

	DEBUG("FIXME: not implemented yet (prognum=%d, progver=%d)\n", prognum, progver);

	return NULL;
}

/* rpc/rpc-transport/socket/src/socket.c:SP_STATE_READ_RPCHDR1 */
void gluster_decode_call_rpchdr1(XDR *xdr, gluster_rpc_hdr_t *rpchdr)
{
	xdr_uint32_t(xdr, &rpchdr->rpcver);
	xdr_uint32_t(xdr, &rpchdr->prognum);
	xdr_uint32_t(xdr, &rpchdr->progver);
	xdr_uint32_t(xdr, &rpchdr->procnum);

	DEBUG("rpcver: %d\n", rpchdr->rpcver);
	DEBUG("prognum: %d (%s)\n", rpchdr->prognum, gluster_get_progname(rpchdr->prognum, rpchdr->progver));
	DEBUG("progver: %d\n", rpchdr->progver);
	DEBUG("procnum: %d\n", rpchdr->procnum);

}

bool_t gluster_decode_oa(XDR *xdr)
{
	uint32_t oa_flavor;
	xdr_uint32_t(xdr, &oa_flavor);

	char *oa_data = NULL;
	xdr_string(xdr, &oa_data, RPCSVC_MAX_AUTH_BYTES);

	DEBUG("oa_flavor: %d\n", oa_flavor);
	DEBUG("oa_length: %ld\n", strlen(oa_data));
	FIXME("oa_data is not decoded yet\n");

	free(oa_data);

	return TRUE;
}

/* rpc/rpc-lib/src/rpc-common.c xdr_gf_dump_rsp
101          if (!xdr_u_quad_t (xdrs, &objp->gfs_id))
102                  return FALSE;
103          if (!xdr_int (xdrs, &objp->op_ret))
104                  return FALSE;
105          if (!xdr_int (xdrs, &objp->op_errno))
106                  return FALSE;
107          if (!xdr_pointer (xdrs, (char **)&objp->prog, sizeof (gf_prog_detail),
108                            (xdrproc_t) xdr_gf_prog_detail))
109                  return FALSE;
110         return TRUE;
*/
bool_t gluster_xdr_dump_reply(XDR *xdr, gluster_pkt_hdr_t *hdr)
{
	gluster_decode_oa(xdr);

	uint32_t gfs_id;
	xdr_uint32_t(xdr, &gfs_id);

	uint32_t op_ret;
	xdr_uint32_t(xdr, &op_ret);

	uint32_t op_errno;
	xdr_uint32_t(xdr, &op_errno);

	DEBUG("gfs_id: 0x%x\n", gfs_id);
	DEBUG("op_ret: %d\n", op_ret);
	DEBUG("op_errno: %d (%s)\n", op_errno, strerror(op_errno));

	while (hdr->size > xdr_getpos(xdr)) {
		char *progname = NULL;
		xdr_string(xdr, &progname, RPCSVC_NAME_MAX);
		DEBUG("progname: %s\n", progname);

		FIXME("Decoding 4 bytes of <unknown>\n");
		uint32_t unknown;
		xdr_uint32_t(xdr, &unknown);
		xdr_uint32_t(xdr, &unknown);
		xdr_uint32_t(xdr, &unknown);
		xdr_uint32_t(xdr, &unknown);
	}

	return TRUE;
}

/* DUMP request */
bool_t gluster_xdr_dump_call(XDR *xdr, gluster_pkt_hdr_t *hdr)
{
	u_quad_t gfs_id;
	xdr_u_quad_t(xdr, &gfs_id);

	DEBUG("gfs_id: 0x%lx\n", gfs_id);

	return TRUE;
}

gluster_prog_t* gluster_get_prog(uint32_t prognum, uint32_t progver)
{
	int i = 0;

	while (gluster_progs[i].prognum != -1 && gluster_progs[i].progver != -1) {
		if (gluster_progs[i].prognum == prognum &&
		    gluster_progs[i].progver == progver)
			return &gluster_progs[i];

		i++;
	}

	DEBUG("FIXME: not implemented yet (prognum=%d, progver=%d)\n", prognum, progver);
	return NULL;
}

gluster_proc_t* gluster_get_proc(gluster_prog_t *prog, uint32_t procnum)
{
	int i;

	for (i = 0; i < prog->nr_procs; i++) {
		if (prog->procs[i].procnum == procnum)
			return &prog->procs[i];
	}

	DEBUG("FIXME: not implemented yet (prognum=%d, progver=%d, procnum=%d)\n", prog->prognum, prog->progver, procnum);
	return NULL;
}

bool_t gluster_decode_proc(XDR *xdr, gluster_pkt_hdr_t *hdr, gluster_proc_t *proc)
{
	switch (hdr->direction) {
		case CALL:
			if (proc->xdr_call)
				return proc->xdr_call(xdr, hdr);
		case REPLY:
			if (proc->xdr_reply)
				return proc->xdr_reply(xdr, hdr);
		default:
			FIXME("Direction %d not known\n", hdr->direction);
	}

	return TRUE;
}

void gluster_decode_call(XDR *xdr, gluster_pkt_hdr_t *hdr)
{
	gluster_rpc_hdr_t rpchdr;
	gluster_decode_call_rpchdr1(xdr, &rpchdr);

	/* oa_cred  */
	gluster_decode_oa(xdr);
	/* oa_verf */
	gluster_decode_oa(xdr);

	/* data is prognum/progver/procnum dependent */
	gluster_prog_t *prog = gluster_get_prog(rpchdr.prognum, rpchdr.progver);
	if (prog) {
		DEBUG("procname: %s\n", prog->progname);

		gluster_proc_t *proc = gluster_get_proc(prog, rpchdr.procnum);
		if (proc){
			DEBUG("procname: %s\n", proc->procname);
			gluster_decode_proc(xdr, hdr, proc);
		}
	} else {
		return;
	}
}

void gluster_decode_reply(XDR *xdr, gluster_pkt_hdr_t *hdr)
{
	uint32_t cb_rpcver;
	xdr_uint32_t(xdr, &cb_rpcver);

	uint32_t cb_prognum;
	xdr_uint32_t(xdr, &cb_prognum);

	uint32_t cb_progver;
	xdr_uint32_t(xdr, &cb_progver);

	uint32_t cb_procnum;
	xdr_uint32_t(xdr, &cb_procnum);

	DEBUG("cb_rpcver: %d\n", cb_rpcver);
	DEBUG("cb_prognum: %d\n", cb_prognum);
	DEBUG("cb_progver: %d\n", cb_progver);
	DEBUG("cb_procnum: %d\n", cb_procnum);

	/* data is depends on the prognum/progver/procnum of the xid */
	FIXME("Dissecting as GLUSTER_DUMP_PROGRAM reply...\n");
	gluster_prog_t *prog = gluster_get_prog(123451501, 1);
	gluster_proc_t *proc = gluster_get_proc(prog, 1);
	gluster_decode_proc(xdr, hdr, proc);
}

#define GLUSTER_HEADER_LAST_PKT		0x80000000U
bool_t gluster_is_last_pkt(uint32_t hdr)
{
	return (hdr & GLUSTER_HEADER_LAST_PKT) == GLUSTER_HEADER_LAST_PKT;
}

size_t gluster_payload_size(uint32_t hdr)
{
	return hdr & (~GLUSTER_HEADER_LAST_PKT);
}

void gluster_decode_packet(void *packet, size_t size)
{
	XDR xdr;
	xdrmem_create(&xdr, packet, size, XDR_DECODE);

	gluster_pkt_hdr_t hdr;

	/* the first 32 bits is the header */
	uint32_t header;
	xdr_uint32_t(&xdr, &header);

	hdr.last = gluster_is_last_pkt(header);
	hdr.size = gluster_payload_size(header);

	/* transaction id */
	xdr_uint32_t(&xdr, &hdr.xid);

	/* direction (call=0, reply=1) */
	xdr_uint32_t(&xdr, &hdr.direction);

	DEBUG("is_last_pkt: %d\n", hdr.last);
	DEBUG("payload_size: %d\n", hdr.size);
	DEBUG("xid: %d\n", hdr.xid);
	DEBUG("direction: %d\n", hdr.direction);

	switch (hdr.direction) {
		case CALL:
			gluster_decode_call(&xdr, &hdr);
			break;
		case REPLY:
			gluster_decode_reply(&xdr, &hdr);
			break;
		case UNIVERSAL_ANSWER:
			/* gluster < 3.0 protocol */
			FIXME("this is really unexpected - old protocol?\n");
			break;
		default:
			/* FIXME: bail out? */
			FIXME("this is really unexpected - new protocol?\n");
			break;
			goto cleanup;
	}

cleanup:
	xdr_destroy(&xdr);
}


#define ADD_PROC(name, num)			.procname = name, .procnum = num,
#define ADD_PROC_XDR(name, num, call, reply)	.procname = name, .procnum = num, .xdr_call = call, .xdr_reply = reply,

/* xlators/mgmt/glusterd/src/glusterd-rpc-ops.c */
static gluster_proc_t gluster_mgmt_procs[] = {
	{ ADD_PROC("NULL", GLUSTERD_MGMT_NULL) },
	{ ADD_PROC("PROBE_QUERY", GLUSTERD_MGMT_PROBE_QUERY) },
	{ ADD_PROC("FRIEND_ADD", GLUSTERD_MGMT_FRIEND_ADD) },
	{ ADD_PROC("CLUSTER_LOCK", GLUSTERD_MGMT_CLUSTER_LOCK) },
	{ ADD_PROC("CLUSTER_UNLOCK", GLUSTERD_MGMT_CLUSTER_UNLOCK) },
	{ ADD_PROC("STAGE_OP", GLUSTERD_MGMT_STAGE_OP) },
	{ ADD_PROC("COMMIT_OP", GLUSTERD_MGMT_COMMIT_OP) },
	{ ADD_PROC("FRIEND_REMOVE", GLUSTERD_MGMT_FRIEND_REMOVE) },
	{ ADD_PROC("FRIEND_UPDATE", GLUSTERD_MGMT_FRIEND_UPDATE) },
};

static gluster_proc_t gluster_glusterfs_mgmt_procs[] = {
	{ ADD_PROC("NULL", GD_MGMT_NULL) },
	{ ADD_PROC("BRICK_OP", GD_MGMT_BRICK_OP) },
};

/* procedures for GLUSTER_DUMP_PROGRAM */
static gluster_proc_t gluster_dump_procs[] = {
	{ ADD_PROC("NULL", GF_DUMP_NULL) },
	{ ADD_PROC_XDR("DUMP", GF_DUMP_DUMP, gluster_xdr_dump_call, gluster_xdr_dump_reply) },
};

/* procedures for GLUSTER_HNDSK_PROGRAM */
static gluster_proc_t gluster_hndsk_procs[] = {
	{ ADD_PROC("NULL", GF_HNDSK_NULL) },
	{ ADD_PROC("DUMP", GF_HNDSK_SETVOLUME) },
	{ ADD_PROC("GETSPEC", GF_HNDSK_GETSPEC) },
	{ ADD_PROC("PING", GF_HNDSK_PING) },
};

/* mapping all programs, versions to their procedures */
static gluster_prog_t gluster_progs[] = {
	{
		.progname = "glusterd clnt mgmt",
		.prognum  = GD_MGMT_PROGRAM,
		.progver  = 1,
		.procs    = gluster_mgmt_procs,
		.nr_procs = GLUSTERD_MGMT_MAXVALUE,
	},
	{
		.progname = "GF-DUMP",
		.prognum  = GLUSTER_DUMP_PROGRAM,
		.progver  = 1,
		.procs    = gluster_dump_procs,
		.nr_procs = GF_DUMP_MAXVALUE,
	},
	{
		.progname = "GlusterFS Handshake",
		.prognum  = GLUSTER_HNDSK_PROGRAM,
		.progver  = 1,
		.procs    = gluster_hndsk_procs,
		.nr_procs = GF_HNDSK_MAXVALUE,
	},
	{
		.progname  = "GlusterFS Mops",
		.prognum   = GLUSTERFS_PROGRAM,
		.progver   = 1,
		.procs     = gluster_glusterfs_mgmt_procs,
		.nr_procs  = GF_BRICK_MAXVALUE,
	},
	{	/* terminating entry */
		.progname  = "(unused termination entry)",
		.prognum   = -1,
		.progver   = -1,
		.nr_procs  = 0,
	},
};
