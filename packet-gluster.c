/* packet-gluster.c
 *
 * Copyright (c) 2011 Niels de Vos <ndevos@redhat.com>, Red Hat UK, Ltd.
 *
 * Base for a dissector that can be integrated in Wireshark.
 */


/* sending a handshake
 *
 * glusterd_peer_rpc_notify()
 * case RPC_CLNT_CONNECT:
 *   xlators/mgmt/glusterd/src/glusterd-handshake.c:
 *   glusterd_peer_handshake()
 *   gf_dump_req req
 *   req.gfs_id = 0xcafe
 *
 *   glusterd_submit_request()
 *     xlators/mgmt/glusterd/src/glusterd-utils.c:
 *     xdr_serialize_generic()
 *       proc() -> xdr_gf_dump_req()
 *         xdr_u_quad_t(objp->gfs_id)
 *
 *
 * rpcsvc_dump(rpcsvc_request_t *req)
 *   - "struct rpcsvc_request" = rpcsvc_request_t
 *   build_prog_details()
 *     loop through req->svc->programs and set attributes
 *   xdr_serialize_dump_rsp()
 *     xdr_serialize_generic()
 *     xdr_gf_dump_rsp() -> set gfs_id (quadruple), op_ret (int), op_errno (int)
 *       xdr_gf_prog_detail() -> progname, prognum, progver,
 *         (in case there is a ->next,  xdr_gf_prog_detail())
 *   rpcsvc_submit_generic()
 *     rpcsvc_record_build_record()
 *     rpcsvc_transport_submit()
 *   rpcsvc_submit_generic()
 *     rpcsvc_record_build_record()
 *       rpcsvc_fill_reply()
 *       rpcsvc_record_build_header()
 *   rpcsvc_transport_submit()
 *     rpc_transport_submit_reply()
 *       socket_submit_reply()
 *         __socket_ioq_new()
 *         __socket_ioq_churn_entry()
 *
 *
 * callback:
 * glusterd_peer_dump_version_cbk()
 *   xdr_to_generic()
 *     xdrmem_create(..., XDR_DECODE)
 *     xdr_gf_dump_rsp()
 *
 * server executes server_getspec()
 *   xdr_to_generic (req->msg[0], &args, (xdrproc_t)xdr_gf_getspec_req)
 *  1475      if (!xdr_u_int (xdrs, &objp->flags))
 *  1477      if (!xdr_string (xdrs, &objp->key, ~0))
 *
 */

/* peer probe from cli/src/cli-rpc-ops.c:
 * gf_cli3_1_probe() -> outgoing
 * gf_cli3_1_probe_cbk() <- incoming
 *
 * gf1_cli_probe_req req = {0,};
 * req.hostname          = hostname to peer probe
 * req.port              = (default) CLI_GLUSTERD_PORT
 *
 * cli/src/cli-rpc-ops.c:
 * 1715         ret = cli_cmd_submit (&req, frame, cli_rpc_prog,
 * 1716                               GLUSTER_CLI_PROBE, NULL,
 * 1717                               this, gf_cli3_1_probe_cbk,
 * 1718                               (xdrproc_t)xdr_gf1_cli_probe_req);
 *     cli/src/cli-rpc-ops.c -> cli_rpc_prog
 *     4152 struct rpc_clnt_program cli_prog = {
 *     4153         .progname  = "Gluster CLI",
 *     4154         .prognum   = GLUSTER_CLI_PROGRAM,
 *     4155         .progver   = GLUSTER_CLI_VERSION,
 *     4156         .numproc   = GLUSTER_CLI_PROCCNT,
 *     4157         .proctable = gluster_cli_actors,
 *     4158 };
 *
 *     rpc/rpc-lib/src/protocol-common.h:
 *     235 #define GLUSTER_CLI_PROGRAM      1238463 (= 0x12e5bf)
 *     236 #define GLUSTER_CLI_VERSION      1

 *
 *
 * cli/src/cli-cmd.c:
 * 376         ret = cli_submit_request (req, frame, prog,
 * 377                                   procnum, NULL, this, cbkfn, xdrproc);
 *
 * cli/src/cli.c:
 * 222 cli_submit_request (void *req, call_frame_t *frame,
 * 223                     rpc_clnt_prog_t *prog,
 * 224                     int procnum, struct iobref *iobref,
 * 225                     xlator_t *this, fop_cbk_fn_t cbkfn, xdrproc_t xdrproc)
 * ...
 * 237                 xdr_size = xdr_sizeof (xdrproc, req);
 * 238                 iobuf = iobuf_get2 (this->ctx->iobuf_pool, xdr_size);
 * ...
 * 268         ret = rpc_clnt_submit (global_rpc, prog, procnum, cbkfn,
 * 269                                &iov, count,
 * 270                                NULL, 0, iobref, frame, NULL, 0, NULL, 0, NULL);
 *
 * rpc/rpc-lib/src/rpc-clnt.c:
 * 1367 rpc_clnt_submit (struct rpc_clnt *rpc, rpc_clnt_prog_t *prog,
 * 1368                  int procnum, fop_cbk_fn_t cbkfn,
 * 1369                  struct iovec *proghdr, int proghdrcount,
 * 1370                  struct iovec *progpayload, int progpayloadcount,
 * 1371                  struct iobref *iobref, void *frame, struct iovec *rsphdr,
 * 1372                  int rsphdr_count, struct iovec *rsp_payload,
 * 1373                  int rsp_payload_count, struct iobref *rsp_iobref)
 * ....
 * 1379         rpc_transport_req_t    req;
 * ....
 * 1406         callid = rpc_clnt_new_callid (rpc);
 * 1407 
 * 1408         conn = &rpc->conn;
 * 1409 
 * 1410         rpcreq->prog = prog;
 * 1411         rpcreq->procnum = procnum;
 * 1412         rpcreq->conn = conn;
 * 1413         rpcreq->xid = callid;
 * 1414         rpcreq->cbkfn = cbkfn;
 * ....
 * 1418         if (proghdr) {
 * 1419                 proglen += iov_length (proghdr, proghdrcount);
 * 1420         }
 * 1421 
 * 1422         if (progpayload) {
 * 1423                 proglen += iov_length (progpayload,
 * 1424                                        progpayloadcount);
 * 1425         }
 * 1426 
 * 1427         request_iob = rpc_clnt_record (rpc, frame, prog,
 * 1428                                        procnum, proglen,
 * 1429                                        &rpchdr, callid);
 *     rpc/rpc-lib/src/rpc-clnt.c:
 *     1253 struct iobuf *
 *     1254 rpc_clnt_record (struct rpc_clnt *clnt, call_frame_t *call_frame,
 *     1255                  rpc_clnt_prog_t *prog,int procnum, size_t payload_len,
 *     1256                  struct iovec *rpchdr, uint64_t callid)
 *     ....
 *     1285         request_iob = rpc_clnt_record_build_record (clnt, prog->prognum,
 *     1286                                                     prog->progver,
 *     1287                                                     procnum, payload_len,
 *     1288                                                     callid, &au,
 *     1289                                                     rpchdr);
 *     
 *       rpc/rpc-lib/src/rpc-clnt.c:
 *       1193 rpc_clnt_record_build_record (struct rpc_clnt *clnt, int prognum, int progver,
 *       1194                               int procnum, size_t payload, uint64_t xid,
 *       1195                               struct auth_glusterfs_parms *au,
 *       1196                               struct iovec *recbuf)
 *       ....
 *       1223         ret = rpc_clnt_fill_request (prognum, progver, procnum, payload, xid,
 *       1224                                      au, &request, auth_data);
 *         
 *
 *         1113 int
 *         1114 rpc_clnt_fill_request (int prognum, int progver, int procnum, int payload,
 *         1115                        uint64_t xid, struct auth_glusterfs_parms *au,
 *         1116                        struct rpc_msg *request, char *auth_data)
 *         ....
 *         1126         request->rm_xid = xid;
 *         1127         request->rm_direction = CALL;
 *         1128 
 *         1129         request->rm_call.cb_rpcvers = 2;
 *         1130         request->rm_call.cb_prog = prognum;
 *         1131         request->rm_call.cb_vers = progver;
 *         1132         request->rm_call.cb_proc = procnum;
 *         ....
 *         1137         ret = xdr_serialize_glusterfs_auth (auth_data, au);
 *         ....
 *         1143         request->rm_call.cb_cred.oa_flavor = AUTH_GLUSTERFS;
 *         1144         request->rm_call.cb_cred.oa_base   = auth_data;
 *         1145         request->rm_call.cb_cred.oa_length = ret;
 *         1146 
 *         1147         request->rm_call.cb_verf.oa_flavor = AUTH_NONE;
 *         1148         request->rm_call.cb_verf.oa_base = NULL;
 *         1149         request->rm_call.cb_verf.oa_length = 0;
 *
 *                                
 *
 *       1231         recordhdr = rpc_clnt_record_build_header (record, pagesize, &request,
 *       1232                                                   payload);
 *         
 *         rpc/rpc-lib/src/rpc-clnt.c:
 *         1157 struct iovec
 *         1158 rpc_clnt_record_build_header (char *recordstart, size_t rlen,
 *         1159                               struct rpc_msg *request, size_t payload)
 *         ....
 *         1166         ret = rpc_request_to_xdr (request, recordstart, rlen, &requesthdr);
 *
 *           rpc/rpc-lib/src/xdr-rpcclnt.c
 *           76 rpc_request_to_xdr (struct rpc_msg *request, char *dest, size_t len,
 *           77                     struct iovec *dst)
 *           ..
 *           86         xdrmem_create (&xdr, dest, len, XDR_ENCODE);
 *           87         if (!xdr_callmsg (&xdr, request)) {
 *           88                 gf_log ("rpc", GF_LOG_WARNING, "failed to encode call msg");
 *
 *
 *             http://sourceware.org/git/?p=glibc.git;a=blob;f=sunrpc/rpc_cmsg.c#l63
 *             41 bool_t
 *             42 xdr_callmsg (XDR *xdrs, struct rpc_msg *cmsg)
 *             ..
 *             63           (void) IXDR_PUT_LONG (buf, cmsg->rm_xid);
 *             64           (void) IXDR_PUT_ENUM (buf, cmsg->rm_direction);
 *             ..
 *             67           (void) IXDR_PUT_LONG (buf, cmsg->rm_call.cb_rpcvers);
 *             ..
 *             70           (void) IXDR_PUT_LONG (buf, cmsg->rm_call.cb_prog);
 *             71           (void) IXDR_PUT_LONG (buf, cmsg->rm_call.cb_vers);
 *             72           (void) IXDR_PUT_LONG (buf, cmsg->rm_call.cb_proc);
 *             73           oa = &cmsg->rm_call.cb_cred;
 *             74           (void) IXDR_PUT_ENUM (buf, oa->oa_flavor);
 *             75           (void) IXDR_PUT_INT32 (buf, oa->oa_length);
 *             76           if (oa->oa_length)
 *             77             {
 *             78               memcpy ((caddr_t) buf, oa->oa_base, oa->oa_length);
 *             79               buf = (int32_t *) ((char *) buf + RNDUP (oa->oa_length));
 *             80             }
 *             81           oa = &cmsg->rm_call.cb_verf;
 *             82           (void) IXDR_PUT_ENUM (buf, oa->oa_flavor);
 *             83           (void) IXDR_PUT_INT32 (buf, oa->oa_length);
 *             84           if (oa->oa_length)
 *             85             {
 *             86               memcpy ((caddr_t) buf, oa->oa_base, oa->oa_length);
 *
 * 
 *     1126         request->rm_xid = xid;
 *     1127         request->rm_direction = CALL;
 *     1128 
 *     1129         request->rm_call.cb_rpcvers = 2;
 *     1130         request->rm_call.cb_prog = prognum;
 *     1131         request->rm_call.cb_vers = progver;
 *     1132         request->rm_call.cb_proc = procnum;
 *     1133 
 *     ....
 *     1137         ret = xdr_serialize_glusterfs_auth (auth_data, au);
 *     1138         if (ret == -1) {
 *     1139                 gf_log ("rpc-clnt", GF_LOG_DEBUG, "cannot encode credentials");
 *     1140                 goto out;
 *     1141         }
 *     1142 
 *     1143         request->rm_call.cb_cred.oa_flavor = AUTH_GLUSTERFS;
 *     1144         request->rm_call.cb_cred.oa_base   = auth_data;
 *     1145         request->rm_call.cb_cred.oa_length = ret;
 *     1146 
 *     1147         request->rm_call.cb_verf.oa_flavor = AUTH_NONE;
 *     1148         request->rm_call.cb_verf.oa_base = NULL;
 *     1149         request->rm_call.cb_verf.oa_length = 0;
 *
 * ....
 * 1436         iobref_add (iobref, request_iob);
 * 1437 
 * 1438         req.msg.rpchdr = &rpchdr;
 * 1439         req.msg.rpchdrcount = 1;
 * 1440         req.msg.proghdr = proghdr;
 * 1441         req.msg.proghdrcount = proghdrcount;
 * 1442         req.msg.progpayload = progpayload;
 * 1443         req.msg.progpayloadcount = progpayloadcount;
 * 1444         req.msg.iobref = iobref;
 * 1445 
 * 1446         req.rsp.rsphdr = rsphdr;
 * 1447         req.rsp.rsphdr_count = rsphdr_count;
 * 1448         req.rsp.rsp_payload = rsp_payload;
 * 1449         req.rsp.rsp_payload_count = rsp_payload_count;
 * 1450         req.rsp.rsp_iobref = rsp_iobref;
 * 1451         req.rpc_req = rpcreq;
 * ....
 * 1455                 if (conn->connected == 0) {
 * 1456                         ret = rpc_transport_connect (conn->trans,
 * 1457                                                      conn->config.remote_port);
 * ....
 * 1464                 ret = rpc_transport_submit_request (rpc->conn.trans,
 * 1465                                                     &req);
 * 1466                 if (ret == -1) {
 * 1467                         gf_log (conn->trans->name, GF_LOG_WARNING,
 * 1468                                 "failed to submit rpc-request "
 * 1469                                 "(XID: 0x%ux Program: %s, ProgVers: %d, "
 * 1470                                 "Proc: %d) to rpc-transport (%s)", rpcreq->xid,
 * 1471                                 rpcreq->prog->progname, rpcreq->prog->progver,
 * 1472                                 rpcreq->procnum, rpc->conn.trans->name);
 *
 * rpc/rpc-lib/src/rpc-transport.c:
 * -> ops->submit_request = socket_submit_request
 *  2312                 entry = __socket_ioq_new (this, &req->msg);
 *  ....
 *  2317                         ret = __socket_ioq_churn_entry (this, entry);
 *
 *  rpc/rpc-lib/src/rpc-transport.h:
 *  113 struct rpc_transport_msg {
 *  114         struct iovec     *rpchdr;
 *  115         int               rpchdrcount;
 *  116         struct iovec     *proghdr;
 *  117         int               proghdrcount;
 *  118         struct iovec     *progpayload;
 *  119         int               progpayloadcount;
 *  120         struct iobref    *iobref;
 *  121 };
 *  122 typedef struct rpc_transport_msg rpc_transport_msg_t;
 *
 *  rpc/rpc-transport/socket/src/socket.h:
 *   97 struct ioq {
 *   98         union {
 *   99                 struct list_head list;
 *  100                 struct {
 *  101                         struct ioq    *next;
 *  102                         struct ioq    *prev;
 *  103                 };
 *  104         };
 *  105 
 *  106         uint32_t           fraghdr;
 *  107         struct iovec       vector[MAX_IOVEC];
 *  108         int                count;
 *  109         struct iovec      *pending_vector;
 *  110         int                pending_count;
 *  111         struct iobref     *iobref;
 *  112 };
 *
 *
 *
 *   rpc/rpc-transport/socket/src/socket.c:
 *   518 struct ioq *
 *   519 __socket_ioq_new (rpc_transport_t *this, rpc_transport_msg_t *msg)
 *   ...
 *   521         struct ioq       *entry = NULL;
 *   ...
 *   532         count = msg->rpchdrcount + msg->proghdrcount + msg->progpayloadcount;
 *   ...
 *   550         entry->vector[0].iov_base = (char *)&entry->fraghdr;
 *   551         entry->vector[0].iov_len = sizeof (entry->fraghdr);
 *   552         entry->count = 1;
 *
 *
 *  rpc/rpc-transport/socket/src/socket.c:
 *   624 __socket_ioq_churn_entry (rpc_transport_t *this, struct ioq *entry)
 *   ...
 *   628         ret = __socket_writev (this, entry->pending_vector,
 *   629                                entry->pending_count,
 *   630                                &entry->pending_vector,
 *   631                                &entry->pending_count);
 *
 *    258 __socket_writev (rpc_transport_t *this, struct iovec *vector, int count,
 *    259                  struct iovec **pending_vector, int *pending_count)
 *    ...
 *    263         ret = __socket_rwv (this, vector, count,
 *    264                             pending_vector, pending_count, NULL, 1);
 *
 *     147 __socket_rwv (rpc_transport_t *this, struct iovec *vector, int count,
 *     148               struct iovec **pending_vector, int *pending_count, size_t *bytes,
 *     149               int write)
 *     ...
 *     172                 if (write) {
 *     173                         ret = writev (sock, opvector, opcount);
 *     ...
 *     180                 } else {
 *     181                         ret = readv (sock, opvector, opcount);
 *
 *                      
 */

#include <rpc/xdr.h>

#define DEBUG	printf

struct gluster_prog_proc {
	const char* procname;  /* user readable description */
	uint32_t procnum;      /* procedure number */

	bool_t (*xdr_decode)(XDR *xdr); /* xdr decoding */
};
typedef struct gluster_prog_proc gluster_prog_proc_t;

struct gluster_prog {
	const char* progname;  /* user readable description */
	uint32_t prognum;      /* program numner */
	uint32_t progver;      /* program version */

	gluster_prog_proc_t *procs; /* procedures of a program */
};
typedef struct gluster_prog gluster_prog_t;


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
bool_t gluster_dump_dump_xdr(XDR *xdr)
{
	u_quad_t gfs_id;
	xdr_u_quad_t(xdr, &gfs_id);

	int32_t op_ret;
	xdr_int(xdr, &op_ret);

//	void* prog;
//	xdr_pointer(xdr, &prog);

	return TRUE;
}


enum gluster_msg_direction {
	CALL = 0,
	REPLY = 1,
	UNIVERSAL_ANSWER = 42,
};

/* numbers are spread over a load of files */
enum gluster_prognums {
	GD_MGMT_PROGRAM        = 1238433,
	GLUSTER3_1_FOP_PROGRAM = 1298437,
	GLUSTER_CBK_PROGRAM    = 52743234,
	GLUSTER_CLI_PROGRAM    = 1238463,
	GLUSTERD1_MGMT_PROGRAM = 1298433,
	GLUSTER_DUMP_PROGRAM   = 123451501,
	GLUSTERFS_PROGRAM      = 4867634,
	GLUSTER_HNDSK_PROGRAM  = 14398633,
	GLUSTER_PMAP_PROGRAM   = 34123456,
	MOUNT_PROGRAM          = 100005,
	NFS_PROGRAM            = 100003,
};

/* rpc/rpc-lib/src/xdr-common.h:gf_dump_procnum
 * gf_dump_procnum does not contain a 0-value */
enum gluster_prog_dump_procs {
	GF_DUMP_NULL /* = 0 */,
	GF_DUMP_DUMP,
	GF_DUMP_MAXVALUE,
};

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

/* mapping all programg, versions to their procedures */
static gluster_prog_t gluster_progs[] = {
	{ /* TODO: I really have no idea what GD_MGMT_PROGRAM does */
		.progname = "prog for mgmt",
		.prognum = GD_MGMT_PROGRAM,
		.progver = 0,
		.procs = gluster_mgmt_procs,
	},
	{
		.progname = "GF-DUMP",
		.prognum = GLUSTER_DUMP_PROGRAM,
		.progver = 1,
		.procs = gluster_dump_procs,
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

gluster_prog_proc_t* gluster_get_proc(uint32_t prognum, uint32_t progver, uint32_t procnum)
{
	int i = 0, j;
	/* FIXME: is this a valid check? */
	while (gluster_progs[i].progname != NULL) {
		if (gluster_progs[i].prognum == prognum &&
		    gluster_progs[i].progver == progver) {

			/* prognum and progver matches */
			j = 0;
			/* FIXME: is this a valid check? */
			while (gluster_progs[i].procs[j].procname != NULL) {
				if (gluster_progs[i].procs[j].procnum == procnum)
					return &gluster_progs[i].procs[j];
				j++;
			}
		}

		i++;
	}

	return NULL;
}

/* rpc/rpc-transport/socket/src/socket.c:SP_STATE_READ_RPCHDR1 */
void gluster_decode_call_rpchdr1(XDR *xdr)
{
	uint32_t prognum;
	xdr_uint32_t(xdr, &prognum);

	uint32_t progver;
	xdr_uint32_t(xdr, &progver);

	uint32_t procnum;
	xdr_uint32_t(xdr, &procnum);

	/* data is prognum/progver/procnum dependent */
	gluster_get_proc(prognum, progver, procnum);

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
	DEBUG("prognum: %d\n", prognum);
	DEBUG("progver: %d\n", progver);
	DEBUG("procnum: %d\n", procnum);
//	DEBUG("cb_proc: %d\n", cb_proc);
//	DEBUG("oa_flavor: %d\n", oa_flavor);
//	DEBUG("oa_length: %d\n", oa_length);
//	DEBUG("oa_data: %d\n", oa_data);
//
//cleanup:
//	xdr_free((xdrproc_t) xdr_string, (char*) &oa_data);
//	xdr_free((xdrproc_t) xdr_string, (char*) &gfs_id);
}

void gluster_decode_call(XDR *xdr)
{
	gluster_decode_call_rpchdr1(xdr);
}

void gluster_decode_reply(XDR *xdr)
{
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
			break;
		default:
			/* FIXME: bail out? */
			goto cleanup;
	}

cleanup:
	xdr_destroy(&xdr);
}
