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

#include "packet-gluster.h"

#define DEBUG	printf

/* the main RPC decoding structure, defined at the end of this file */
static gluster_prog_t gluster_progs[];

bool_t gluster_decode_oa(XDR *xdr)
{
	uint32_t oa_flavor;
	xdr_uint32_t(xdr, &oa_flavor);

	uint32_t oa_length;
	xdr_uint32_t(xdr, &oa_length);

	uint32_t *oa_data = malloc(sizeof(uint32_t) * oa_length);
	uint32_t units_read = 0;
	/* FIXME: use xdr_bytes() instead? */
	while (units_read < (oa_length / BYTES_PER_XDR_UNIT)) {
		if (!xdr_uint32_t(xdr, oa_data + units_read)) {
			DEBUG("FAIL: could only read %d/%d \n", units_read, (oa_length / BYTES_PER_XDR_UNIT));
			return FALSE;
		}
		units_read++;
	}

	DEBUG("oa_flavor: %d\n", oa_flavor);
	DEBUG("oa_length: %d\n", oa_length);
	DEBUG("oa_data: (%d units of %d bytes read)\n", units_read, BYTES_PER_XDR_UNIT);

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

/* DUMP request */
bool_t gluster_dump_dump_xdr(XDR *xdr)
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

gluster_prog_proc_t* gluster_get_proc(gluster_prog_t *prog, uint32_t procnum)
{
	int i;

	for (i = 0; i < prog->nr_procs; i++) {
		if (prog->procs[i].procnum == procnum)
			return &prog->procs[i];
	}

	DEBUG("FIXME: not implemented yet (prognum=%d, progver=%d, procnum=%d)\n", prog->prognum, prog->progver, procnum);
	return NULL;
}

/* rpc/rpc-transport/socket/src/socket.c:SP_STATE_READ_RPCHDR1 */
void gluster_decode_call_rpchdr1(XDR *xdr, rpc_hdr_t *rpchdr)
{
	xdr_uint32_t(xdr, &rpchdr->rpcver);
	xdr_uint32_t(xdr, &rpchdr->prognum);
	xdr_uint32_t(xdr, &rpchdr->progver);
	xdr_uint32_t(xdr, &rpchdr->procnum);

	DEBUG("rpcver: %d\n", rpchdr->rpcver);
	DEBUG("prognum: %d\n", rpchdr->prognum);
	DEBUG("progver: %d\n", rpchdr->progver);
	DEBUG("procnum: %d\n", rpchdr->procnum);

}

void gluster_decode_call(XDR *xdr)
{
	rpc_hdr_t rpchdr;
	gluster_decode_call_rpchdr1(xdr, &rpchdr);

	/* oa_cred  */
	gluster_decode_oa(xdr);
	/* oa_verf */
	gluster_decode_oa(xdr);

	/* data is prognum/progver/procnum dependent */
	gluster_prog_t *prog = gluster_get_prog(rpchdr.prognum, rpchdr.progver);
	if (prog) {
		DEBUG("procname: %s\n", prog->progname);

		gluster_prog_proc_t *proc = gluster_get_proc(prog, rpchdr.procnum);
		if (proc){
			DEBUG("procname: %s\n", proc->procname);
			if (proc->xdr_decode)
				proc->xdr_decode(xdr);
		}
	} else {
		return;
	}

//	/* authentication type */
//	uint32_t oa_flavor;
//	xdr_uint32_t(&xdr, &oa_flavor);
//
//	/* authentication data length */
//	uint32_t oa_length;
//	xdr_uint32_t(&xdr, &oa_length);
//
//	/* authentication data */
//	char *oa_data = NULL; // malloc(oa_length);
//	xdr_string(&xdr, &oa_data, oa_length);
//
//	/* FIXME: gfs_id, sure? */
//#define GFS_ID_SIZE 16
//	char *gfs_id = NULL; //malloc(GFS_ID_SIZE);
//	xdr_string(&xdr, &gfs_id, GFS_ID_SIZE);
//
//	DEBUG("cb_proc: %d\n", cb_proc);
//	DEBUG("oa_flavor: %d\n", oa_flavor);
//	DEBUG("oa_length: %d\n", oa_length);
//	DEBUG("oa_data: %d\n", oa_data);
//
//cleanup:
//	xdr_free((xdrproc_t) xdr_string, (char*) &oa_data);
//	xdr_free((xdrproc_t) xdr_string, (char*) &gfs_id);
}

void gluster_decode_reply(XDR *xdr)
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

	gluster_decode_oa(xdr);

	/* data is prognum/progver/procnum dependent */

//	gluster_decode_call_rpchdr1(xdr);
#if 0
	gluster_prog_t *prog = gluster_get_prog(prognum, progver);
	if (prog) {
		DEBUG("procname: %s\n", prog->progname);

		gluster_prog_proc_t *proc = gluster_get_proc(prog, procnum);
		if (proc){
			DEBUG("procname: %s\n", proc->procname);
			if (proc->xdr_decode)
				proc->xdr_decode(xdr);
		}
	} else {
		DEBUG("NIY: prognum=%d, progver=%d\n", prognum, progver);
	}
#endif
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

	/* the first 32 bits is the header */
	uint32_t header;
	xdr_uint32_t(&xdr, &header);

	bool_t is_last_pkt = gluster_is_last_pkt(header);
	uint32_t payload_size = gluster_payload_size(header);

	/* transaction id */
	uint32_t xid;
	xdr_uint32_t(&xdr, &xid);

	/* direction (call=0, reply=1) */
	uint32_t direction;
	xdr_uint32_t(&xdr, &direction);

	DEBUG("is_last_pkt: %d\n", is_last_pkt);
	DEBUG("payload_size: %d\n", payload_size);
	DEBUG("xid: %d\n", xid);
	DEBUG("direction: %d\n", direction);

	switch (direction) {
		case CALL:
			gluster_decode_call(&xdr);
			break;
		case REPLY:
			gluster_decode_reply(&xdr);
			break;
		case UNIVERSAL_ANSWER:
			/* gluster < 3.0 protocol */
			DEBUG("FIXME: this is really unexpected - old protocol?\n");
			break;
		default:
			/* FIXME: bail out? */
			goto cleanup;
	}

cleanup:
	xdr_destroy(&xdr);
}


/* procedures for GD_MGMT_PROGRAM */
static gluster_prog_proc_t gluster_mgmt_procs[] = {
	{
		.procname = "procedure for mgmt",
		.procnum = 0 /*TODO*/,
	},
};

/* procedures for GLUSTER_DUMP_PROGRAM */
static gluster_prog_proc_t gluster_dump_procs[] = {
	{
		.procname = "NULL",
		.procnum = GF_DUMP_NULL,
	},
	{
		.procname = "DUMP",
		.procnum = GF_DUMP_DUMP,
		.xdr_decode = gluster_dump_dump_xdr,
	},
};

/* procedures for GLUSTER_HNDSK_PROGRAM */
static gluster_prog_proc_t gluster_hndsk_procs[] = {
	{
		.procname = "NULL",
		.procnum = GF_HNDSK_NULL,
	},
	{
		.procname = "DUMP",
		.procnum = GF_HNDSK_SETVOLUME,
//		.xdr_decode = gluster_hndsk_setvolume_xdr,
	},
	{
		.procname = "GETSPEC",
		.procnum = GF_HNDSK_GETSPEC,
//		.xdr_decode = gluster_hndsk_getspec_xdr,
	},
	{
		.procname = "PING",
		.procnum = GF_HNDSK_PING,
//		.xdr_decode = gluster_hndsk_setvolume_xdr,
	},
};

/* mapping all programs, versions to their procedures */
static gluster_prog_t gluster_progs[] = {
	{
		.progname = "prog for mgmt",
		.prognum = GD_MGMT_PROGRAM,
		.progver = 0,
		.procs = gluster_mgmt_procs,
		.nr_procs = GD_MGMT_MAXVALUE,
	},
	{
		.progname = "GF-DUMP",
		.prognum = GLUSTER_DUMP_PROGRAM,
		.progver = 1,
		.procs = gluster_dump_procs,
		.nr_procs = GF_DUMP_MAXVALUE,
	},
	{
		.progname = "GlusterFS Handshake",
		.prognum = GLUSTER_HNDSK_PROGRAM,
		.progver = 1,
		.procs = gluster_hndsk_procs,
		.nr_procs = GF_HNDSK_MAXVALUE,
	},
	{ /* terminating entry */
		.prognum = -1,
		.progver = -1,
		.nr_procs = 0,
	},
};

/* from rpc/rpc-lib/src/rpcsvc.h
311 #define RPCSVC_NAME_MAX            32
315 typedef struct rpcsvc_actor_desc {
316         char                    procname[RPCSVC_NAME_MAX];
317         int                     procnum;
318         rpcsvc_actor            actor;
328         rpcsvc_vector_actor     vector_actor;
329         rpcsvc_vector_sizer     vector_sizer;
330 
331 } rpcsvc_actor_t;
*/

/* from rpc/rpc-lib/src/rpcsvc.c
2380 rpcsvc_actor_t gluster_dump_actors[] = {
2381         [GF_DUMP_NULL] = {"NULL", GF_DUMP_NULL, NULL, NULL, NULL },
2382         [GF_DUMP_DUMP] = {"DUMP", GF_DUMP_DUMP, rpcsvc_dump, NULL, NULL },
2383         [GF_DUMP_MAXVALUE] = {"MAXVALUE", GF_DUMP_MAXVALUE, NULL, NULL, NULL },
2384 };
2385 
2386 
2387 struct rpcsvc_program gluster_dump_prog = {
2388         .progname  = "GF-DUMP",
2389         .prognum   = GLUSTER_DUMP_PROGRAM,
2390         .progver   = GLUSTER_DUMP_VERSION,
2391         .actors    = gluster_dump_actors,
2392         .numactors = 2,
2393 };
*/
