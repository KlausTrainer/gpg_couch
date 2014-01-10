#include "gpg_couch.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

typedef struct {
	ErlNifMutex* mutex;
	gpgme_ctx_t* ctx;
} PrivData;

static void
init_gpgme (void)
{
	/* initialize the locale environment. */
	setlocale(LC_ALL, "");
	gpgme_check_version(NULL);
	gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
	#ifdef LC_MESSAGES
	gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
	#endif
}

static void
check_gpgme_version (void)
{
	if (!gpgme_check_version(GPG_COUCH_MIN_REQUIRED_GPGME_VERSION)) {
		fprintf(stderr,
			"gpg_couch: The required GpgMe version is %s or greater, got version %s.\n",
			GPG_COUCH_MIN_REQUIRED_GPGME_VERSION,
			gpgme_check_version(NULL));
		exit(1);
	}
}

static int
check_for_valid_signature (gpgme_ctx_t* ctx)
{
	gpgme_signature_t signature;
	gpgme_error_t err;
	gpgme_key_t key;
	gpgme_user_id_t uid;

	signature = gpgme_op_verify_result(*ctx)->signatures;

	if (signature != NULL) {
		do {
			err = signature->status;

			if (gpgme_err_code(err) == GPG_ERR_NO_ERROR) {
				err = gpgme_get_key(*ctx, signature->fpr, &key, 0);
			}

			if (gpgme_err_code(err) == GPG_ERR_NO_ERROR
			    && !(key->revoked || key->expired || key->disabled || key->invalid)) {
				uid = key->uids;
				while (uid != NULL) {
					if (!(uid->revoked || uid->invalid)
					    && (uid->validity == GPGME_VALIDITY_FULL
						|| uid->validity == GPGME_VALIDITY_ULTIMATE)) {
						return 0;
					}
					uid = uid->next;
				}
			}

			signature = signature->next;
		} while (signature != NULL);
	}

	return 1;
}

static ERL_NIF_TERM
validate_signature (ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM result;
	ErlNifBinary arg0, arg1;
	gpgme_data_t sig = NULL;
	gpgme_data_t signed_data = NULL;
	gpgme_error_t err;
	PrivData* priv_data = (PrivData*) enif_priv_data(env);
	ErlNifMutex* mutex = priv_data->mutex;
	gpgme_ctx_t* ctx = priv_data->ctx;

	if (argc < 2
		|| !enif_inspect_binary(env, argv[0], &arg0)
		|| !enif_inspect_binary(env, argv[1], &arg1))
    		return enif_make_badarg(env);

	err = gpgme_data_new_from_mem(&sig, (char*) arg0.data, (size_t) arg0.size, 0);
	err = err | gpgme_data_new_from_mem(&signed_data, (char*) arg1.data,
					    (size_t) arg1.size, 0);
	if (err) {
		fprintf(stderr, "Error: GpgMe cannot allocate memory\n");
		result = enif_make_tuple2(
				env,
				enif_make_atom(env, "error"),
				enif_make_atom(env, "enomem"));
		goto cleanup;
	}

	enif_mutex_lock(mutex);
	err = gpgme_op_verify(*ctx, sig, signed_data, NULL);
	if (err) {
		enif_mutex_unlock(mutex);
		result = enif_make_tuple2(
				env,
				enif_make_atom(env, "error"),
				enif_make_atom(env, "invalid_signature"));
	} else {
		err = check_for_valid_signature(ctx);
		enif_mutex_unlock(mutex);
		if (err)
			result = enif_make_tuple2(
					env,
					enif_make_atom(env, "error"),
					enif_make_atom(env, "invalid_signature"));
		else
			result = enif_make_atom(env, "ok");
	}

cleanup:
	gpgme_data_release(sig);
	gpgme_data_release(signed_data);

	return result;
}

static int
load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info)
{

	PrivData* priv_data = enif_alloc(sizeof(PrivData));
	gpgme_ctx_t* ctx = enif_alloc(sizeof(gpgme_ctx_t));
	ErlNifMutex* mutex = enif_mutex_create("gpg_couch");
	gpgme_error_t err;

	init_gpgme();
	check_gpgme_version();
	err = gpgme_new(ctx);

	if (!priv_data || !mutex || err) {
		if (!err)
			fprintf(stderr, "Error: failed to initialize gpg_couch\n");
		else
			fprintf(stderr, "Error: creating GpgME context failed: %s\n",
				gpgme_strerror(err));
		return 1;
	}

	priv_data->ctx = ctx;
	priv_data->mutex = mutex;

	*priv = priv_data;

	return 0;
}

static int
upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM info)
{
	*priv = *old_priv;
	return 0;
}

static void
unload(ErlNifEnv* env, void* priv)
{
	gpgme_release(*((PrivData*) priv)->ctx);
	enif_free(((PrivData*) priv)->ctx);
	enif_mutex_destroy(((PrivData*) priv)->mutex);
	enif_free(priv);
	return;
}


static ErlNifFunc funcs[] =
{
	{"validate_signature", 2, validate_signature}
};

ERL_NIF_INIT(gpg_couch, funcs, &load, NULL, &upgrade, &unload)
