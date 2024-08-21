-module(totally_ffi).

-export([encode32/1]).

% source: https://github.com/dnsimple/base32_erlang/blob/main/src/base32.erl
encode32(Bin) when is_binary(Bin) ->
    Fun = fun(I) -> std_enc(I) end,
    {Encoded0, Rest} = encode_body(Fun, Bin),
    {Encoded1, _PadBy} = encode_rest(Fun, Rest),
    <<Encoded0/binary, Encoded1/binary>>.

encode_body(Fun, Bin) ->
    Offset = 5 * (byte_size(Bin) div 5),
    <<Body:Offset/binary, Rest/binary>> = Bin,
    {<<<<(Fun(I))>> || <<I:5>> <= Body>>, Rest}.

encode_rest(Fun, Bin) ->
    Whole = bit_size(Bin) div 5,
    Offset = 5 * Whole,
    <<Body:Offset/bits, Rest/bits>> = Bin,
    Body0 = <<<<(Fun(I))>> || <<I:5>> <= Body>>,
    {Body1, Pad} =
        case Rest of
            <<I:3>> -> {<<(Fun(I bsl 2))>>, 6};
            <<I:1>> -> {<<(Fun(I bsl 4))>>, 4};
            <<I:4>> -> {<<(Fun(I bsl 1))>>, 3};
            <<I:2>> -> {<<(Fun(I bsl 3))>>, 1};
            <<>> -> {<<>>, 0}
        end,
    {<<Body0/binary, Body1/binary>>, Pad}.

std_enc(I) when is_integer(I) andalso I >= 26 andalso I =< 31 -> I + 24;
std_enc(I) when is_integer(I) andalso I >= 0 andalso I =< 25 ->
    I + $A.
