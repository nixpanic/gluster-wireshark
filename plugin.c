const char* version = PACKAGE_VERSION;

void proto_register_gluster(void);
void proto_reg_handoff_glsuter(void);

void
plugin_register(void)
{
  proto_register_gluster();
  proto_reg_handoff_gluster();
}
