fun({NewDoc}, _OldDoc, _UserCtx, _SecObj) ->
%  Log(io_lib:format("NewDoc: ~p~nOldDoc: ~p~nUserCtx: ~p~nSecObj: ~p~n", [NewDoc, OldDoc, UserCtx, SecObj])),
%  Log(io_lib:format("NewDoc: ~p~n", [NewDoc])),
  NewDoc1 = proplists:delete(<<"_rev">>, NewDoc),
  NewDoc2 = proplists:delete(<<"_revisions">>, NewDoc1),
%  Log(io_lib:format("NewDoc JSON: ~p~n", [ejson:encode({NewDoc2})])),
  1
end.
