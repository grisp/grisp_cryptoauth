#include "erl_nif.h"
#include "atca_basic.h"


ATCAIfaceCfg grisp_atcab_default_config = {
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


/*
 * Device Configuration, shamelessly stolen from Microchip's Trust Platform. This configuration
 * is supposed to support all our envisioned usecases based on the TrustFLEX configuration, in
 * particular the following usecases are supported:
 *
 *   1. Secure Boot
 *   2. Custom PKI
 *   3. Public Key Rotation
 *
 * There are way more supported usecases, you can checkout the Trust Platform for explanations.
 * In the following the supposed usage and purpose of each slot is explained: 
 *
 * Slot 0   Primary private key; Primary authentication key; Permanent, Ext Sign, ECDH
 * Slot 1   Internal sign private key; Private key that can only be used to attest internal keys and
 *          state of the a device; Can't be used to sign arbitrary messages; Permanent, Int Sign
 * Slot 2   Secondary private key 1; Secondary private key for other uses; Updatable, Ext Sign, ECDH, Lockable
 * Slot 3   Secondary private key 2; Secondary private key for other uses; Updatable, Ext Sign, ECDH, Lockable
 * Slot 4   Secondary private key 3; Secondary private key for other uses; Updatable, Ext Sign, ECDH, Lockable
 * Slot 5   Secret key; Storage for a secret key; No Read, Encrypted write(6), Lockable, AES key
 * Slot 6   IO protection key; Key used to protect the I2C bus communication (IO) of certain commands;
 *          Requires setup before use; No read, Clear write, Lockable
 * Slot 7   Secure boot digest; Storage location for secureboot digest; This is an internal function, so no
 *          reads or writes are enabled; No read, No write
 * Slot 8   General data; General public data storage (416 bytes); Clear read, Always write, Lockable
 * Slot 9   AES key; Intermediate key storage for ECDH and KDF output; No read, Always write, AES key
 * Slot 10  Device compressed certificate; Certificate primary public key in the Crypto Authentication
 *          compressed format; Clear read, No write
 * Slot 11  Signer public key; Public key for the CA (signer) that signed the device cert; Clear read, No write
 * Slot 12  Signer compressed certificate; Certificate for the CA (signer) certificate for the device
 *          certificate in the CryptoAuthentication compressed format; Clear read, No write
 * Slot 13  Parent public key or general data; Parent public key for validating/invalidating the validated
 *          public key; Can also be used just as a public key or general data storage (72 bytes);
 *          Clear read, Always write, Lockable
 * Slot 14  Validated public key; Validated public key cannot be used (Verify command) or changed without
 *          authorization via the parent public key; Clear read, Always write, Validated (13)
 * Slot 15  Secure boot public key; Secure boot public key; Clear read, Always write, Lockable
 *
 *
 * The configuration is written at the very beginning of the provisioning process onto the device. Don't
 * touch this without informing yourself, be very careful. Unfortunately there are some unknown variables
 * in the Trust Platform XML description. For the sake of documentation these are: 
 *
 *   <UseLock>00</UseLock>
 *   <VolatileKeyPermission>00</VolatileKeyPermission>
 *   <SecureBoot Size="2">03 F7</SecureBoot>
 *   <KdfIvLoc>00</KdfIvLoc>
 *   <KdfIvStr Size="2">69 76</KdfIvStr>
 *   <Reserved Address="75" Size="9">00 00 00 00 00 00 00 00 00</Reserved>
 *   <SlotLocked>FF FF</SlotLocked>
 *   <ChipOptions Size="2">0E 60</ChipOptions>
 *
 * Since we don't have access to the 608A/B documentation (only 508A) we can only make guesses where
 * these values belong to. Here's the link to the 508A datasheet:
 *
 *   https://content.arduino.cc/assets/mkr-microchip_atecc508a_cryptoauthentication_device_summary_datasheet-20005927a.pdf
 *
 * And finally, here's the configuration ...
 */
static const uint8_t grisp_device_default_config[] = {
    0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x60, 0x01,  // 0   - 7      ignored on write (dummy data)
    0x00, 0x00, 0x00, 0x00, 0xEE, 0x01, 0x01, 0x00,  // 8   - 15     ignored on write (dummy data)
    0xC0, 0x00, 0x55, 0x01,                          // 16  - 19     16: I2C address, 18: OTP mode
    // Start of Slot configuration, two bytes per slot; config taken from Microchip's Trust Platform
    0x85, 0x00, 0x82, 0x00, 0x85, 0x20, 0x85, 0x20,  // 20  - 27     Slots 0  - 3
    0x85, 0x20, 0x8F, 0x46, 0x8F, 0x0F, 0x9F, 0x8F,  // 28  - 35     Slots 4  - 7
    0x0F, 0x0F, 0x8F, 0x0F, 0x0F, 0x8F, 0x0F, 0x8F,  // 36  - 43     Slots 8  - 11
    0x0F, 0x8F, 0x0F, 0x0F, 0x0D, 0x1F, 0x0F, 0x0F,  // 44  - 51     Slots 12 - 15
    // End of Slot configuration, next comes more general stuff
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,  // 52  - 59     Monotonic Counter connected to keys
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,  // 60  - 67     Monotonic Counter (not connected to keys)
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 68  - 75     128 bits to control limited use for KeyID 15
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 76  - 83     see above and 3.2.6 in the datasheet
    0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,  // 84  - 91     Lock bytes (ignored on write) and additional stuff
    0x00, 0x00, 0x00, 0x00,                          // 92  - 95     X.509 certificate formatting
    // Slot Key configuration, two bytes per slot; config taken from Microchip's Trust Platform
    0x53, 0x00, 0x53, 0x00, 0x73, 0x00, 0x73, 0x00,  // 96  - 103    Slots 0  - 3
    0x73, 0x00, 0x38, 0x00, 0x7C, 0x00, 0x1C, 0x00,  // 104 - 111    Slots 4  - 7
    0x3C, 0x00, 0x1A, 0x00, 0x1C, 0x00, 0x10, 0x00,  // 112 - 119    Slots 8  - 11
    0x1C, 0x00, 0x30, 0x00, 0x12, 0x00, 0x30, 0x00,  // 120 - 127    Slots 12 - 15
};


#define EXEC_CA_FUN_STATUS(STATUS, fun, args...) { \
    ATCA_STATUS STATUS = fun(args); \
    if (STATUS != ATCA_SUCCESS) \
        return mk_error_with_status(env, #fun, STATUS); \
    }
#define UNIQ_CA_STATUS __func__##__LINE__##_status
#define EXEC_CA_FUN(fun, args...) EXEC_CA_FUN_STATUS(UNIQ_CA_STATUS, fun, args)
#define INIT_CA_FUN EXEC_CA_FUN(atcab_init, &grisp_atcab_default_config)


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


static ERL_NIF_TERM mk_ok(ErlNifEnv* env)
{
    return mk_atom(env, "ok");
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


static ERL_NIF_TERM mk_success(ErlNifEnv* env, ERL_NIF_TERM term)
{
    return enif_make_tuple2(env, mk_atom(env, "ok"), term);
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


static ERL_NIF_TERM write_config_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    INIT_CA_FUN;

    EXEC_CA_FUN(atcab_write_config_zone, grisp_device_default_config);

    return mk_ok(env);
}


static ERL_NIF_TERM lock_config_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    INIT_CA_FUN;

    EXEC_CA_FUN(atcab_lock_config_zone);

    return mk_ok(env);
}


static ERL_NIF_TERM lock_data_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    INIT_CA_FUN;

    EXEC_CA_FUN(atcab_lock_data_zone);

    return mk_ok(env);
}


static ERL_NIF_TERM gen_private_key_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    INIT_CA_FUN;

    // TODO: should be configurable
    uint16_t default_slot = 0;

    uint8_t pubkey[ATCA_PUB_KEY_SIZE];
    EXEC_CA_FUN(atcab_genkey, default_slot, pubkey);

    ERL_NIF_TERM pubkey_term;
    char *bin_data = enif_make_new_binary(env, ATCA_PUB_KEY_SIZE, &pubkey_term);

    memcpy(bin_data, pubkey, ATCA_PUB_KEY_SIZE);

    return mk_success(env, pubkey_term);
}


static ERL_NIF_TERM gen_public_key_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    INIT_CA_FUN;

    // TODO: should be configurable
    uint16_t default_slot = 0;

    uint8_t pubkey[ATCA_PUB_KEY_SIZE];
    EXEC_CA_FUN(atcab_get_pubkey, default_slot, pubkey);

    ERL_NIF_TERM pubkey_term;
    char *bin_data = enif_make_new_binary(env, ATCA_PUB_KEY_SIZE, &pubkey_term);

    memcpy(bin_data, pubkey, ATCA_PUB_KEY_SIZE);

    return mk_success(env, pubkey_term);
}


static ErlNifFunc nif_funcs[] = {
    {"device_info",     0, device_info_nif},
    {"config_locked",   0, config_locked_nif},
    {"data_locked",     0, data_locked_nif},
    {"serial_number",   0, serial_number_nif},
    {"read_config",     0, read_config_nif},
    {"write_config",    0, write_config_nif},
    {"lock_config",     0, lock_config_nif},
    {"lock_data",       0, lock_data_nif},
    {"gen_private_key", 0, gen_private_key_nif},
    {"gen_public_key",  0, gen_public_key_nif},
};

ERL_NIF_INIT(grisp_cryptoauth, nif_funcs, NULL, NULL, NULL, NULL);
