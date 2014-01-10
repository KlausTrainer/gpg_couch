-module(gpg_couch).
-on_load(init/0).

-export([validate_signature/2]).

init() ->
    PrivDir = case code:priv_dir(?MODULE) of
    {error, _} ->
        EbinDir = filename:dirname(code:which(?MODULE)),
        AppPath = filename:dirname(EbinDir),
        filename:join(AppPath, "priv");
    Path ->
        Path
    end,
    erlang:load_nif(filename:join(PrivDir, "gpg_couch"), 0).

-spec validate_signature(binary(), binary()) -> ok | {error, invalid_signature | enomem}.
validate_signature(_Signature, _SignedData) ->
    erlang:nif_error("NIF library not loaded", [{module, ?MODULE}, {line, ?LINE}]).
