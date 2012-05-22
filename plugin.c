const char* version = PACKAGE_VERSION;

void proto_register_gluster(void);
void proto_reg_handoff_gluster(void);
void proto_register_gluster_cli(void);
void proto_reg_handoff_gluster_cli(void);
void proto_register_gluster_dump(void);
void proto_reg_handoff_gluster_dump(void);
void proto_register_glusterfs(void);
void proto_reg_handoff_glusterfs(void);
void proto_register_gluster_gd_mgmt(void);
void proto_reg_handoff_gluster_gd_mgmt(void);
void proto_register_gluster_hndsk(void);
void proto_reg_handoff_gluster_hndsk(void);
void proto_register_gluster_pmap(void);
void proto_reg_handoff_gluster_pmap(void);

void
plugin_register(void)
{
	proto_register_gluster();
	proto_reg_handoff_gluster();
	proto_register_gluster_cli();
	proto_reg_handoff_gluster_cli();
	proto_register_gluster_dump();
	proto_reg_handoff_gluster_dump();
	proto_register_glusterfs();
	proto_reg_handoff_glusterfs();
	proto_register_gluster_gd_mgmt();
	proto_reg_handoff_gluster_gd_mgmt();
	proto_register_gluster_hndsk();
	proto_reg_handoff_gluster_hndsk();
	proto_register_gluster_pmap();
	proto_reg_handoff_gluster_pmap();
}
