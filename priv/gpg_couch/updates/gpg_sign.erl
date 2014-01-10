fun(_OldDoc, {Req}) ->
    Doc = ejson:decode(proplists:get_value(<<"body">>, Req)),
    Log(io_lib:format("Doc: ~p~nReq: ~p~n", [Doc, Req])),
    [Doc, {[{<<"body">>, <<"{\"ok\":true}">>}]}]
end.
