-module(radix64).

-export([ decode/1
        , crc24/1
        ]).

-define(CRC24_INIT, 16#B704CE).
-define(CRC24_POLY, 16#1864CFB).

%% The following type is a subtype of string() for return values
%% of encoding functions.
-type base64_binary() :: binary().

-spec decode(Base64) -> Data when
      Base64 :: base64_binary(),
      Data :: binary().

decode(Bin) when is_binary(Bin) ->
    {Dec, Rest} = decode_binary(Bin, <<>>),
    CRC = decode_binary(Rest, <<>>),
    CRC24 = crc24(Dec),
    case CRC == CRC24 of
        true ->
            {ok, Dec};
        false ->
            {error, {bad_crc24, CRC, CRC24}}
    end.

decode_binary(<<C1:8, Cs/bits>>, A) ->
    case b64d(C1) of
        ws -> decode_binary(Cs, A);
        eq -> {A, Cs};
        B1 -> decode_binary(Cs, A, B1)
    end;
decode_binary(<<>>, A) ->
    A.

decode_binary(<<C2:8, Cs/bits>>, A, B1) ->
    case b64d(C2) of
        ws -> decode_binary(Cs, A, B1);
        B2 -> decode_binary(Cs, A, B1, B2)
    end.

decode_binary(<<C3:8, Cs/bits>>, A, B1, B2) ->
    case b64d(C3) of
        ws -> decode_binary(Cs, A, B1, B2);
        B3 -> decode_binary(Cs, A, B1, B2, B3)
    end.

decode_binary(<<C4:8, Cs/bits>>, A, B1, B2, B3) ->
    case b64d(C4) of
        ws                -> decode_binary(Cs, A, B1, B2, B3);
        eq when B3 =:= eq -> decode_binary(Cs, <<A/bits,B1:6,(B2 bsr 4):2>>);
        eq                -> decode_binary(Cs, <<A/bits,B1:6,B2:6,(B3 bsr 2):4>>);
        B4                -> decode_binary(Cs, <<A/bits,B1:6,B2:6,B3:6,B4:6>>)
    end.

%% ### 6.1.  An Implementation of the CRC-24 in "C"
%%     #define CRC24_INIT 0xB704CEL
%%     #define CRC24_POLY 0x1864CFBL

%%     typedef long crc24;
%%     crc24 crc_octets(unsigned char *octets, size_t len)
%%     {
%%         crc24 crc = CRC24_INIT;
%%         int i;
%%         while (len--) {
%%             crc ^= (*octets++) << 16;
%%             for (i = 0; i < 8; i++) {
%%                 crc <<= 1;
%%                 if (crc & 0x1000000)
%%                     crc ^= CRC24_POLY;
%%             }
%%         }
%%         return crc & 0xFFFFFFL;
%%     }

crc24(Bin) ->
    do_crc24(Bin, ?CRC24_INIT).

do_crc24(<<H, T/binary>>, CRC0) ->
    CRC1 = CRC0 bxor (H bsl 16),
    CRC2 = shift8(8, CRC1),
    do_crc24(T, CRC2);
do_crc24(<<>>, CRC24) ->
    <<(CRC24 band 16#FFFFFF):24>>.

shift8(0, CRC) ->
    CRC;
shift8(N, CRC0) ->
    CRC1 = CRC0 bsl 1,
    case CRC1 band 16#1000000 of
        16#1000000 ->
            CRC2 = CRC1 bxor ?CRC24_POLY,
            shift8(N-1, CRC2);
        0 ->
            shift8(N-1, CRC1)
    end.

%% verify_crc(, A)

%% only_ws_binary(<<>>, A) ->
%%     A;
%% only_ws_binary(<<C:8, Cs/bits>>, A) ->
%%     case b64d(C) of
%%         ws -> only_ws_binary(Cs, A)
%%     end.

%%%========================================================================
%%% Internal functions
%%%========================================================================

%% accessors
-compile({inline, [{b64d, 1}]}).
%% One-based decode map.
b64d(X) ->
    element(X,
            {bad,bad,bad,bad,bad,bad,bad,bad,ws,ws,bad,bad,ws,bad,bad, %1-15
             bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad, %16-31
             ws,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,62,bad,bad,bad,63, %32-47
             52,53,54,55,56,57,58,59,60,61,bad,bad,bad,eq,bad,bad, %48-63
             bad,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
             15,16,17,18,19,20,21,22,23,24,25,bad,bad,bad,bad,bad,
             bad,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
             41,42,43,44,45,46,47,48,49,50,51,bad,bad,bad,bad,bad,
             bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
             bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
             bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
             bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
             bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
             bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
             bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
             bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad}).

%% -compile({inline, [{b64e, 1}]}).
%% b64e(X) ->
%%     element(X+1,
%% 	    {$A, $B, $C, $D, $E, $F, $G, $H, $I, $J, $K, $L, $M, $N,
%% 	     $O, $P, $Q, $R, $S, $T, $U, $V, $W, $X, $Y, $Z,
%% 	     $a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k, $l, $m, $n,
%% 	     $o, $p, $q, $r, $s, $t, $u, $v, $w, $x, $y, $z,
%% 	     $0, $1, $2, $3, $4, $5, $6, $7, $8, $9, $+, $/}).

%%%========================================================================
%%% eunit
%%%========================================================================

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

crc24_test() ->
    ?assertEqual(<<71,245,138>>, crc24(<<"hello">>)),
    ok.
-endif.
