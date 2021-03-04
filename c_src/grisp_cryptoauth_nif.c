#include "erl_nif.h"
#include "atca_basic.h"


ATCAIfaceCfg grisp_default_config = {
    .iface_type                 = ATCA_I2C_IFACE,
    .devtype                    = ATECC608A,
    {
        .atcai2c.address        = 0xC0,
        .atcai2c.bus            = 1,
        .atcai2c.baud           = 100000,
    },
    .wake_delay                 = 1500,
    .rx_retries                 = 20
};


#define EXEC_CA_FUN_STATUS(STATUS, fun, args...) { \
    ATCA_STATUS STATUS = fun(args); \
    if (STATUS != ATCA_SUCCESS) \
        return mk_error_with_status(env, #fun, STATUS); \
    }
#define UNIQ_CA_STATUS __func__##__LINE__##_status
#define EXEC_CA_FUN(fun, args...) EXEC_CA_FUN_STATUS(UNIQ_CA_STATUS, fun, args)
#define INIT_CA_FUN EXEC_CA_FUN(atcab_init, &grisp_default_config)


struct device_type_nif {
    ATCADeviceType type;
    const char *name;
};


static ERL_NIF_TERM mk_atom(ErlNifEnv* env, const char* atom)
{
    ERL_NIF_TERM ret;

    if (!enif_make_existing_atom(env, atom, &ret, ERL_NIF_LATIN1))
        return enif_make_atom(env, atom);

    return ret;
}


static ERL_NIF_TERM mk_string(ErlNifEnv* env, char* string)
{
    return enif_make_string(env, string, ERL_NIF_LATIN1);
}


static ERL_NIF_TERM mk_error(ErlNifEnv* env, const char* mesg)
{
    return enif_make_tuple2(env, mk_atom(env, "error"), mk_atom(env, mesg));
}


static ERL_NIF_TERM mk_error_with_status(ErlNifEnv* env, const char* mesg, ATCA_STATUS status)
{
    return enif_make_tuple3(env, mk_atom(env, "error"), mk_atom(env, mesg), enif_make_int(env, status));
}


static ERL_NIF_TERM mk_success_atom(ErlNifEnv* env, const char* mesg)
{
    return enif_make_tuple2(env, mk_atom(env, "ok"), mk_atom(env, mesg));
}


static ERL_NIF_TERM mk_success_string(ErlNifEnv* env, char* mesg)
{
    return enif_make_tuple2(env, mk_atom(env, "ok"), mk_string(env, mesg));
}


static void bytes_to_hex(uint8_t *bytes, int len, char *hex)
{
    /* NOTE: we always need three times the byte array length plus one here */
    for (int idx = 0; idx < len; idx++)
        sprintf(&hex[3 * idx], "%02X ", bytes[idx]);

    /* sprintf sets the terminating \0, but one character too late */
    hex[3 * len - 1] = '\0';
}


static ERL_NIF_TERM device_info_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    INIT_CA_FUN;

    const struct device_type_nif types[] =
    { { ATSHA204A, "ATSHA204A" },
      { ATECC108A, "ATECC108A" },
      { ATECC508A, "ATECC508A" },
      { ATECC608A, "ATECC608A" },
      { ATECC608B, "ATECC608B" } };

    ATCADeviceType dt = atcab_get_device_type();
    char* name = NULL;

    for (size_t i = 0; i < sizeof(types)/sizeof(struct device_type_nif); ++i) {
        if (types[i].type == dt) {
            name = (char *) types[i].name;
            break;
        }
    }

    return name ? mk_success_atom(env, name) : mk_error(env, "unknown_device");
}


static ERL_NIF_TERM config_locked_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    INIT_CA_FUN;

    bool is_locked = false;
    EXEC_CA_FUN(atcab_is_config_locked, &is_locked);

    return mk_success_atom(env, is_locked ? "true" : "false");
}


static ERL_NIF_TERM data_locked_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    INIT_CA_FUN;

    bool is_locked = false;
    EXEC_CA_FUN(atcab_is_data_locked, &is_locked);

    return mk_success_atom(env, is_locked ? "true" : "false");
}


static ERL_NIF_TERM serial_number_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    INIT_CA_FUN;

    uint8_t sn[9];
    EXEC_CA_FUN(atcab_read_serial_number, sn);

    char sn_str[28];
    bytes_to_hex(sn, 9, sn_str);

    return mk_success_string(env, sn_str);
}

static ERL_NIF_TERM read_config_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    INIT_CA_FUN;

    uint8_t config_zone[ATCA_ECC_CONFIG_SIZE];
    EXEC_CA_FUN(atcab_read_config_zone, config_zone);

    char config_zone_str[3 * ATCA_ECC_CONFIG_SIZE + 1];
    bytes_to_hex(config_zone, ATCA_ECC_CONFIG_SIZE, config_zone_str);

    return mk_success_string(env, config_zone_str);
}


static ErlNifFunc nif_funcs[] = {
    {"device_info",     0, device_info_nif},
    {"config_locked",   0, config_locked_nif},
    {"data_locked",     0, data_locked_nif},
    {"serial_number",   0, serial_number_nif},
    {"read_config",     0, read_config_nif},
};

ERL_NIF_INIT(grisp_cryptoauth, nif_funcs, NULL, NULL, NULL, NULL);
