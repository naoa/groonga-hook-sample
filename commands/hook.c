#include <groonga/plugin.h>

#ifdef __GNUC__
# define GNUC_UNUSED __attribute__((__unused__))
#else
# define GNUC_UNUSED
#endif

static grn_obj *
command_log_set(grn_ctx *ctx, GNUC_UNUSED int nargs, GNUC_UNUSED grn_obj **args,
                GNUC_UNUSED grn_user_data *user_data)
{
  grn_obj *flags = grn_ctx_pop(ctx);
  grn_obj *newvalue = grn_ctx_pop(ctx);
  grn_obj *oldvalue = grn_ctx_pop(ctx);
  grn_obj *id = grn_ctx_pop(ctx);
  GRN_PLUGIN_LOG(ctx, GRN_LOG_WARNING,
                 "[hook][set] id=%d newvalue=%s oldvalue=%s flags=%d\n",
                 GRN_INT32_VALUE(id),
                 GRN_TEXT_VALUE(newvalue),
                 GRN_TEXT_VALUE(oldvalue),
                 GRN_INT32_VALUE(flags));
  return NULL;
}

static grn_obj *
command_log_insert(grn_ctx *ctx, GNUC_UNUSED int nargs, GNUC_UNUSED grn_obj **args,
                   GNUC_UNUSED grn_user_data *user_data)
{
  grn_obj *flags = grn_ctx_pop(ctx);
  grn_obj *value = grn_ctx_pop(ctx);
  grn_obj *oldvalue = grn_ctx_pop(ctx);
  grn_obj *id = grn_ctx_pop(ctx);
  GRN_PLUGIN_LOG(ctx, GRN_LOG_WARNING,
                 "[hook][insert] id=%d oldvalue=%s value=%s flags=%d\n",
                 GRN_INT32_VALUE(id),
                 GRN_TEXT_VALUE(oldvalue),
                 GRN_TEXT_VALUE(value),
                 GRN_INT32_VALUE(flags));
  return NULL;
}

static grn_obj *
command_log_delete(grn_ctx *ctx, GNUC_UNUSED int nargs, GNUC_UNUSED grn_obj **args,
                   GNUC_UNUSED grn_user_data *user_data)
{
  grn_obj *flags = grn_ctx_pop(ctx);
  grn_obj *value = grn_ctx_pop(ctx);
  grn_obj *oldvalue = grn_ctx_pop(ctx);
  grn_obj *id = grn_ctx_pop(ctx);
  GRN_PLUGIN_LOG(ctx, GRN_LOG_WARNING,
                 "[hook][delete] id=%d oldvalue=%s value=%s flags=%d\n",
                 GRN_INT32_VALUE(id),
                 GRN_TEXT_VALUE(oldvalue),
                 GRN_TEXT_VALUE(value),
                 GRN_INT32_VALUE(flags));
  return NULL;
}

static grn_obj *
command_example_hook_delete(grn_ctx *ctx, GNUC_UNUSED int nargs, GNUC_UNUSED grn_obj **args,
                            grn_user_data *user_data)
{
  grn_obj *var, *table, *column;
  unsigned int nhooks = 0;

  char *table_name = NULL;
  unsigned int table_len = 0;
  char *column_name = NULL;
  unsigned int column_len = 0;

  var = grn_plugin_proc_get_var(ctx, user_data, "table", -1);
  if (GRN_TEXT_LEN(var) != 0) {
    table_name = GRN_TEXT_VALUE(var);
    table_len = GRN_TEXT_LEN(var);
  }
  var = grn_plugin_proc_get_var(ctx, user_data, "column", -1);
  if (GRN_TEXT_LEN(var) != 0) {
    column_name = GRN_TEXT_VALUE(var);
    column_len = GRN_TEXT_LEN(var);
  }

  table = grn_ctx_get(ctx, table_name, table_len);
  column = grn_obj_column(ctx, table, column_name, column_len);

  grn_obj_delete_hook(ctx, column, GRN_HOOK_SET, 0);
  grn_obj_delete_hook(ctx, table, GRN_HOOK_INSERT, 0);
  grn_obj_delete_hook(ctx, table, GRN_HOOK_DELETE, 0);

  grn_ctx_output_array_open(ctx, "RESULT", 3);
  nhooks = grn_obj_get_nhooks(ctx, column, GRN_HOOK_SET);
  grn_ctx_output_int32(ctx, nhooks);
  nhooks = grn_obj_get_nhooks(ctx, table, GRN_HOOK_INSERT);
  grn_ctx_output_int32(ctx, nhooks);
  nhooks = grn_obj_get_nhooks(ctx, table, GRN_HOOK_DELETE);
  grn_ctx_output_int32(ctx, nhooks);
  grn_ctx_output_array_close(ctx);

  return NULL;
}

static grn_obj *
command_example_hook_add(grn_ctx *ctx, GNUC_UNUSED int nargs, GNUC_UNUSED grn_obj **args,
                         grn_user_data *user_data)
{
  grn_obj *var, *proc, *table, *column;
  unsigned int nhooks = 0;

  char *table_name = NULL;
  unsigned int table_len = 0;
  char *column_name = NULL;
  unsigned int column_len = 0;

  var = grn_plugin_proc_get_var(ctx, user_data, "table", -1);
  if (GRN_TEXT_LEN(var) != 0) {
    table_name = GRN_TEXT_VALUE(var);
    table_len = GRN_TEXT_LEN(var);
  }
  var = grn_plugin_proc_get_var(ctx, user_data, "column", -1);
  if (GRN_TEXT_LEN(var) != 0) {
    column_name = GRN_TEXT_VALUE(var);
    column_len = GRN_TEXT_LEN(var);
  }

  table = grn_ctx_get(ctx, table_name, table_len);
  column = grn_obj_column(ctx, table, column_name, column_len);

  proc = grn_ctx_get(ctx, "log_set", -1);
  grn_obj_add_hook(ctx, column, GRN_HOOK_SET, 0, proc, 0);

  proc = grn_ctx_get(ctx, "log_insert", -1);
  grn_obj_add_hook(ctx, table, GRN_HOOK_INSERT, 0, proc, 0);

  proc = grn_ctx_get(ctx, "log_delete", -1);
  grn_obj_add_hook(ctx, table, GRN_HOOK_DELETE, 0, proc, 0);

  grn_ctx_output_array_open(ctx, "RESULT", 3);
  nhooks = grn_obj_get_nhooks(ctx, column, GRN_HOOK_SET);
  grn_ctx_output_int32(ctx, nhooks);
  nhooks = grn_obj_get_nhooks(ctx, table, GRN_HOOK_INSERT);
  grn_ctx_output_int32(ctx, nhooks);
  nhooks = grn_obj_get_nhooks(ctx, table, GRN_HOOK_DELETE);
  grn_ctx_output_int32(ctx, nhooks);
  grn_ctx_output_array_close(ctx);

  return NULL;
}

static grn_obj *
command_example_hook_add_value(grn_ctx *ctx, GNUC_UNUSED int nargs, GNUC_UNUSED grn_obj **args,
                               grn_user_data *user_data)
{
  grn_obj *var, *table, *column, *value;
  unsigned int nhooks = 0;

  char *table_name = NULL;
  unsigned int table_len = 0;
  char *column_name = NULL;
  unsigned int column_len = 0;

  var = grn_plugin_proc_get_var(ctx, user_data, "table", -1);
  if (GRN_TEXT_LEN(var) != 0) {
    table_name = GRN_TEXT_VALUE(var);
    table_len = GRN_TEXT_LEN(var);
  }
  var = grn_plugin_proc_get_var(ctx, user_data, "column", -1);
  if (GRN_TEXT_LEN(var) != 0) {
    column_name = GRN_TEXT_VALUE(var);
    column_len = GRN_TEXT_LEN(var);
  }

  value = grn_plugin_proc_get_var(ctx, user_data, "value", -1);
  table = grn_ctx_get(ctx, table_name, table_len);
  column = grn_obj_column(ctx, table, column_name, column_len);

  grn_obj_add_hook(ctx, column, GRN_HOOK_SELECT, 0, NULL, value);

  grn_ctx_output_array_open(ctx, "RESULT", 1);
  nhooks = grn_obj_get_nhooks(ctx, column, GRN_HOOK_SELECT);
  grn_ctx_output_int32(ctx, nhooks);
  grn_ctx_output_array_close(ctx);

  return NULL;
}

static grn_obj *
command_example_hook_get_value(grn_ctx *ctx, GNUC_UNUSED int nargs, GNUC_UNUSED grn_obj **args,
                               grn_user_data *user_data)
{
  grn_obj *var, *table, *column;

  char *table_name = NULL;
  unsigned int table_len = 0;
  char *column_name = NULL;
  unsigned int column_len = 0;

  var = grn_plugin_proc_get_var(ctx, user_data, "table", -1);
  if (GRN_TEXT_LEN(var) != 0) {
    table_name = GRN_TEXT_VALUE(var);
    table_len = GRN_TEXT_LEN(var);
  }
  var = grn_plugin_proc_get_var(ctx, user_data, "column", -1);
  if (GRN_TEXT_LEN(var) != 0) {
    column_name = GRN_TEXT_VALUE(var);
    column_len = GRN_TEXT_LEN(var);
  }

  table = grn_ctx_get(ctx, table_name, table_len);
  column = grn_obj_column(ctx, table, column_name, column_len);

  grn_obj buf;
  GRN_TEXT_INIT(&buf, 0);
  GRN_BULK_REWIND(&buf);
  grn_obj_get_hook(ctx, column, GRN_HOOK_SELECT, 0, &buf);

  grn_ctx_output_array_open(ctx, "RESULT", 1);
  grn_ctx_output_cstr(ctx, GRN_TEXT_VALUE(&buf));
  grn_ctx_output_array_close(ctx);

  grn_obj_unlink(ctx, &buf);
  return NULL;
}

static grn_obj *
command_example_hook_delete_value(grn_ctx *ctx, GNUC_UNUSED int nargs, GNUC_UNUSED grn_obj **args,
                                  grn_user_data *user_data)
{
  grn_obj *var, *table, *column;
  unsigned int nhooks = 0;

  char *table_name = NULL;
  unsigned int table_len = 0;
  char *column_name = NULL;
  unsigned int column_len = 0;

  var = grn_plugin_proc_get_var(ctx, user_data, "table", -1);
  if (GRN_TEXT_LEN(var) != 0) {
    table_name = GRN_TEXT_VALUE(var);
    table_len = GRN_TEXT_LEN(var);
  }
  var = grn_plugin_proc_get_var(ctx, user_data, "column", -1);
  if (GRN_TEXT_LEN(var) != 0) {
    column_name = GRN_TEXT_VALUE(var);
    column_len = GRN_TEXT_LEN(var);
  }

  table = grn_ctx_get(ctx, table_name, table_len);
  column = grn_obj_column(ctx, table, column_name, column_len);

  grn_obj_delete_hook(ctx, column, GRN_HOOK_SELECT, 0);
  grn_ctx_output_array_open(ctx, "RESULT", 1);
  nhooks = grn_obj_get_nhooks(ctx, column, GRN_HOOK_SELECT);
  grn_ctx_output_int32(ctx, nhooks);
  grn_ctx_output_array_close(ctx);

  return NULL;
}

grn_rc
GRN_PLUGIN_INIT(GNUC_UNUSED grn_ctx *ctx)
{
  return GRN_SUCCESS;
}

grn_rc
GRN_PLUGIN_REGISTER(grn_ctx *ctx)
{
  grn_expr_var vars[3];

  grn_plugin_command_create(ctx, "log_set", -1, command_log_set, 0, vars);
  grn_plugin_command_create(ctx, "log_insert", -1, command_log_insert, 0, vars);
  grn_plugin_command_create(ctx, "log_delete", -1, command_log_delete, 0, vars);

  grn_plugin_expr_var_init(ctx, &vars[0], "table", -1);
  grn_plugin_expr_var_init(ctx, &vars[1], "column", -1);
  grn_plugin_command_create(ctx, "example_hook_add", -1, command_example_hook_add, 2, vars);

  grn_plugin_expr_var_init(ctx, &vars[0], "table", -1);
  grn_plugin_expr_var_init(ctx, &vars[1], "column", -1);
  grn_plugin_command_create(ctx, "example_hook_delete", -1, command_example_hook_delete, 2, vars);

  grn_plugin_expr_var_init(ctx, &vars[0], "table", -1);
  grn_plugin_expr_var_init(ctx, &vars[1], "column", -1);
  grn_plugin_expr_var_init(ctx, &vars[2], "value", -1);
  grn_plugin_command_create(ctx, "example_hook_add_value", -1, command_example_hook_add_value, 3, vars);

  grn_plugin_expr_var_init(ctx, &vars[0], "table", -1);
  grn_plugin_expr_var_init(ctx, &vars[1], "column", -1);
  grn_plugin_command_create(ctx, "example_hook_get_value", -1, command_example_hook_get_value, 2, vars);

  grn_plugin_expr_var_init(ctx, &vars[0], "table", -1);
  grn_plugin_expr_var_init(ctx, &vars[1], "column", -1);
  grn_plugin_command_create(ctx, "example_hook_delete_value", -1, command_example_hook_delete_value, 2, vars);

  return ctx->rc;
}

grn_rc
GRN_PLUGIN_FIN(GNUC_UNUSED grn_ctx *ctx)
{
  return GRN_SUCCESS;
}
