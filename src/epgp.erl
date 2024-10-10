-module(epgp).

-export([ parse/1
        , parse/2
        , sym_encrypt/2
        , testmsg/0
        ]).

-define(EXPBIAS, 6).

-record(pgp_pke_skey, {}).
-record(pgp_sig, {}).
-record(pgp_ske_skey, { alg
                      , skey
                      }).
-record(pgp_op_sig, {}).
-record(pgp_sec_key, {}).
-record(pgp_pub_key, {}).
-record(pgp_sec_subkey, {}).
-record(pgp_comp_data, { alg
                       , data
                       }).
-record(pgp_sym_enc_data, {}).
-record(pgp_marker, {}).
-record(pgp_lit_data, { type
                      , filename
                      , timestamp
                      , data
                      }).
-record(pgp_trust, {}).
-record(pgp_userid, {}).
-record(pgp_pub_subkey, {}).
-record(pgp_user_attr, {}).
-record(pgp_se_n_ip_data, {data}).
-record(pgp_mod_det_code, {}).

-record(pgp_skey, { alg
                  , skey_fun
                  }).

-record(pgp_ctx, { pw_fun
                 , skey
                 }).

sym_encrypt(Message, Password) when is_binary(Message) andalso
                                    is_binary(Password) ->
    case {unicode:characters_to_nfc_binary(Message),
          unicode:characters_to_nfc_binary(Password)} of
        {{error, _, _}, _} -> {error, non_utf8_message};
        {_, {error, _, _}} -> {error, non_utf8_password};
        {B1, B2} when is_binary(B1) andalso
                      is_binary(B2) ->
            PassFun = fun () -> Password end,
            ArmorR64 = do_sym_encrypt(Message,
                                      #pgp_ctx{ pw_fun = PassFun }),
            <<"-----BEGIN PGP MESSAGE-----\n\n", ArmorR64/binary,
              "-----END PGP MESSAGE-----\n">>
    end.

do_sym_encrypt(Message, Ctx0) ->
    {SeshKeyData, Ctx1} = pack_ske_skey(Ctx0),
    LitData = pack_lit_data(utf8, Message),
    CompData = pack_comp_data(zip, LitData),
    EncData = pack_se_n_ip_data(CompData, Ctx1),
    radix64:encode(<<SeshKeyData/binary, EncData/binary>>).

pack_ske_skey(#pgp_ctx{pw_fun = PassFun} = Ctx) ->
    CountField = 255,
    SymAlg = aes_256_cfb128,
    case {crypto:strong_rand_bytes(8), crypto:strong_rand_bytes(32)} of
        {{error, Reason}, _} ->
            error(Reason);
        {_, {error, Reason}} ->
            error(Reason);
        {Salt, SeshKey0} ->
            SKey = s2k(iter_salted_s2k, CountField, PassFun, Salt,
                       sha256),
            S2KTag = s2k_tag(iter_salted_s2k),
            CryptTag = sym_tag(SymAlg),
            SeshKey1 = <<CryptTag, SeshKey0/binary>>,
            EncSeshKey = crypto:crypto_one_time(SymAlg, SKey, iv(SymAlg),
                                                SeshKey1, true),
            HashTag = hash_tag(sha256),
            CtxSesh = #pgp_skey{ alg = SymAlg
                               , skey_fun = fun () -> SeshKey0 end
                               },
            {packet(3, <<4,CryptTag,S2KTag,HashTag,Salt/binary,CountField,
                         EncSeshKey/binary>>),
             Ctx#pgp_ctx{skey = CtxSesh}}
    end.

pack_lit_data(utf8, Data) ->
    UnixTs = unix_ts_32(),
    %% Filename length = 0, no filename
    packet(11, <<$u, 0, UnixTs/binary, Data/binary>>).

pack_comp_data(zip, Data) ->
    Z = zlib:open(),
    zlib:deflateInit(Z, default, deflated, -13, 8, default),
    [Zip] = zlib:deflate(Z, Data, finish),
    zlib:close(Z),
    Tag = comp_tag(zip),
    packet(8, <<Tag, Zip/binary>>).

pack_se_n_ip_data(Data, #pgp_ctx{skey = #pgp_skey{ alg = SeshAlg
                                                 , skey_fun = SKeyFun
                                                 }}) ->
    case crypto:strong_rand_bytes(bsize(SeshAlg)) of
        {error, Reason} ->
            error(Reason);
        Nonce ->
            ChSum = binary:part(Nonce, bsize(SeshAlg)-2, 2),
            IVData = <<Nonce/binary, ChSum/binary, Data/binary,
                       16#d3, 16#14>>,
            Digest = crypto:hash(sha, IVData),
            Plain = <<IVData/binary, Digest/binary>>,
            Encrypted = crypto:crypto_one_time(SeshAlg, SKeyFun(),
                                               iv(SeshAlg),
                                               Plain, true),
            packet(18, <<1, Encrypted/binary>>)
    end.

packet(Tag, Message) when Tag >= 0 andalso Tag < 64->
    Len = packet_len(byte_size(Message)),
    <<1:1,1:1,Tag:6,Len/binary,Message/binary>>.

packet_len(N) when N >= 0 andalso N < 192 ->
    <<N>>;
packet_len(N) when N >= 192 andalso N < 8384 ->
    <<N0, N1>> = <<(N - 192):16>>,
    <<(N0 + 192), N1>>;
packet_len(N) when N >= 8384  ->
    <<255, N:32/big-unsigned-integer>>.

parse(Message) when is_binary(Message) ->
    do_parse(Message, #pgp_ctx{}).

parse(Message, Password) when is_binary(Message) andalso
                              is_binary(Password) ->
    PassFun = fun () -> Password end,
    do_parse(Message, #pgp_ctx{pw_fun = PassFun}).

do_parse([], _) ->
    [];
do_parse(Message, Ctx) ->
    case binary:split(Message, <<"-----BEGIN PGP MESSAGE-----">>) of
        [_] -> [];
        [_, Msg1] ->
            find_end(Msg1, Ctx)
    end.

find_end(Message, Ctx) ->
    case binary:split(Message, <<"-----END PGP MESSAGE-----\n">>) of
        [Msg1] ->
            [Msg1];
        [Msg1, Rest] ->
            parse_msg(Msg1, Ctx) ++ do_parse(Rest, Ctx)
    end.

parse_msg(Msg, Ctx) ->
    [_Hdr, Msg1] = binary:split(Msg, <<"\n\n">>),
    {ok, Msg2} = radix64:decode(Msg1),
    parse_packets(Msg2, Ctx).

%% TODO: support old format packets
parse_packets(<<1:1,1:1,Tag:6,R/binary>>, Ctx) ->
    find_length_new(R, tag2rec(Tag), Ctx);
parse_packets(<<1:1,0:1,_Tag:6,_R/binary>>, _Ctx) ->
    error(no_support_for_old_format_pkts);
parse_packets(<<>>, _Ctx) ->
    [].

tag2rec(1) -> #pgp_pke_skey{};
tag2rec(2) -> #pgp_sig{};
tag2rec(3) -> #pgp_ske_skey{};
tag2rec(4) -> #pgp_op_sig{};
tag2rec(5) -> #pgp_sec_key{};
tag2rec(6) -> #pgp_pub_key{};
tag2rec(7) -> #pgp_sec_subkey{};
tag2rec(8) -> #pgp_comp_data{};
tag2rec(9) -> #pgp_sym_enc_data{};
tag2rec(10) -> #pgp_marker{};
tag2rec(11) -> #pgp_lit_data{};
tag2rec(12) -> #pgp_trust{};
tag2rec(13) -> #pgp_userid{};
tag2rec(14) -> #pgp_pub_subkey{};
tag2rec(17) -> #pgp_user_attr{};
tag2rec(18) -> #pgp_se_n_ip_data{};
tag2rec(19) -> #pgp_mod_det_code{}.

%% TODO: partial length packets
find_length_new(<<L,R0/binary>>, Tag, Ctx0) when L < 192 ->
    <<Packet:L/binary,R1/binary>> = R0,
    {Res, Ctx1} = parse_packet(Tag, Packet, Ctx0),
    [Res] ++ parse_packets(R1, Ctx1);
find_length_new(<<L0,L1,R0/binary>>, Tag, Ctx0) when L0 >= 192 andalso
                                                    L0 < 224 ->
    L = (L0 - 192) bsl 8 + L1 + 192,
    <<Packet:L/binary,R1/binary>> = R0,
    {Res, Ctx1} = parse_packet(Tag, Packet, Ctx0),
    [Res] ++ parse_packets(R1, Ctx1);
find_length_new(<<255,L:32/big-unsigned-integer,R0/binary>>, Tag,
                Ctx0) ->
    <<Packet:L/binary,R1/binary>> = R0,
    {Res, Ctx1} = parse_packet(Tag, Packet, Ctx0),
    [Res] ++ parse_packets(R1, Ctx1).

parse_packet(#pgp_ske_skey{} = Rec, Packet, Ctx) ->
    parse_ske_skey(Packet, Rec, Ctx);
parse_packet(#pgp_se_n_ip_data{} = Rec, Packet, Ctx) ->
    parse_se_n_ip_data(Packet, Rec, Ctx);
parse_packet(#pgp_comp_data{} = Rec, Packet, Ctx) ->
    parse_comp_data(Packet, Rec, Ctx);
parse_packet(#pgp_lit_data{} = Rec, Packet, Ctx) ->
    parse_lit_data(Packet, Rec, Ctx);
parse_packet(Tag, Packet, Ctx) ->
    {{Tag, Packet}, Ctx}.

parse_ske_skey(<<4,SymAlg,S2K,R/binary>>, Rec, Ctx) ->
    s2k_hash(s2k_spec(S2K), R, sym_alg(SymAlg), Rec, Ctx).

s2k_hash(iter_salted_s2k, <<Hash,Salt:8/binary,C,R/binary>>,
         SymAlg, Rec0, #pgp_ctx{pw_fun = PassFun} = Ctx) ->
    HashAlg = hash_alg(Hash),
    SKey = s2k(iter_salted_s2k, C, PassFun, Salt, HashAlg),
    <<SAlg, Decrypted/binary>> =
        crypto:crypto_one_time(SymAlg, SKey, iv(SymAlg), R, false),
    SeshAlg = sym_alg(SAlg),
    SKeyFun = fun () -> Decrypted end,
    Rec1 = Rec0#pgp_ske_skey{ alg = SeshAlg
                            , skey = Decrypted
                            },
    SRec = #pgp_skey{ alg = SeshAlg
                    , skey_fun = SKeyFun
                    },
    %% logger:debug("~p~n", [{iter_salted_s2k, HashAlg, Salt, SymAlg,
    %%                        SKey, R, Decrypted, Rec1}]),
    {Rec1, Ctx#pgp_ctx{skey = SRec}}.

s2k(iter_salted_s2k, CountField, PassFun, Salt, HashAlg) ->
    Res = do_s2k(iter_salted_s2k, CountField, PassFun, Salt, HashAlg),
    erlang:garbage_collect(),
    Res.

do_s2k(iter_salted_s2k, CountField, PassFun, Salt, HashAlg) ->
    <<Exp:4, C1:4>> = <<CountField>>,
    Count = (16 + C1) bsl (Exp + ?EXPBIAS),
    Password = PassFun(),
    SaltedPw = <<Salt/binary, Password/binary>>,
    IterC = Count div byte_size(SaltedPw) + 1,
    IterPre = binary:copy(SaltedPw, IterC),
    Iter = binary:part(IterPre, 0, Count),
    SKey = crypto:hash(HashAlg, Iter),
    SKey.

parse_se_n_ip_data(<<1,Encrypted/binary>>, Rec,
                   #pgp_ctx{skey = #pgp_skey{ alg = SeshAlg
                                            , skey_fun = SKeyFun
                                            }} = Ctx) ->
    NonceSizish = bsize(SeshAlg) - 2,
    DecSize = byte_size(Encrypted) - bsize(SeshAlg) - 2 - 2 - 20,
    Decrypted =
        crypto:crypto_one_time(SeshAlg, SKeyFun(), iv(SeshAlg),
                               Encrypted, false),
    case Decrypted of
        <<_:NonceSizish/binary, ChSum:16, ChSum:16, Data:DecSize/binary,
          16#d3, 16#14, Digest:20/binary>> ->
            IVData = binary:part(Decrypted, 0, byte_size(Encrypted) - 20),
            ExpDigest = crypto:hash(sha, IVData),
            case Digest == ExpDigest of
                true ->
                    Res = parse_packets(Data, Ctx),
                    %% logger:debug("~p~n", [{se_n_ip_data, Encrypted,
                    %%                        Decrypted, Data, Res}]),
                    {Rec#pgp_se_n_ip_data{data = Res}, Ctx};
                false ->
                    error(bad_digest)
            end;
        _ ->
            error(decryption_failed)
    end.

parse_comp_data(<<CompAlg, Packet/binary>>, Rec, Ctx) ->
    do_decompress(comp_alg(CompAlg), Packet, Rec, Ctx).

do_decompress(none, Packet, Rec, Ctx) ->
    {Rec#pgp_comp_data{alg=none,data=parse_packets(Packet, Ctx)}, Ctx};
do_decompress(zip, Zipped, Rec, Ctx) ->
    Z = zlib:open(),
    zlib:inflateInit(Z, -15),
    [Unzipped] = zlib:inflate(Z, Zipped),
    zlib:close(Z),
    {Rec#pgp_comp_data{alg=zip,data=parse_packets(Unzipped, Ctx)}, Ctx}.

parse_lit_data(<<$u, L, Utf8/binary>>, Rec, Ctx) ->
    <<Filename:L/binary, UnixTS:32, Message/binary>> = Utf8,
    {Rec#pgp_lit_data{type = utf8, filename = Filename,
                      timestamp = UnixTS, data = Message}, Ctx}.

sym_alg(9) -> aes_256_cfb128.

sym_tag(aes_256_cfb128) -> 9.

iv(aes_256_cfb128) -> <<0:128>>.

bsize(aes_256_cfb128) -> 16.

s2k_spec(0) -> simple_s2k;
s2k_spec(1) -> salted_s2k;
s2k_spec(3) -> iter_salted_s2k.

s2k_tag(simple_s2k) -> 0;
s2k_tag(salted_s2k) -> 1;
s2k_tag(iter_salted_s2k) -> 3.

hash_alg(1) -> md5;
hash_alg(2) -> sha;
hash_alg(3) -> ripemd160;
hash_alg(8) -> sha256;
hash_alg(9) -> sha384;
hash_alg(10) -> sha512;
hash_alg(11) -> sha224.

hash_tag(md5) -> 1;
hash_tag(sha) -> 2;
hash_tag(ripemd160) -> 3;
hash_tag(sha256) -> 8;
hash_tag(sha384) -> 9;
hash_tag(sha512) -> 10;
hash_tag(sha224) -> 11.

comp_alg(0) -> none;
comp_alg(1) -> zip;
comp_alg(2) -> zlib;
comp_alg(3) -> bzip2.

comp_tag(zip) -> 1.

unix_ts_32() ->
    UnixTS =
        calendar:datetime_to_gregorian_seconds(
          calendar:universal_time()) -
        calendar:datetime_to_gregorian_seconds(
          {{1970,1,1},{0,0,0}}),
    <<UnixTS:32>>.

%% password is <<"apa">>
testmsg() ->
    <<"-----BEGIN PGP MESSAGE-----\n"
      "\n"
      "wy4ECQMIBZqMPAWKH0j/YSwkc0ms5H4KRmEb/2Fiv88midukE/4znnTGgB02u4Du\n"
      "0l0B/OqYE91z9iro37nsYqXnE1tnpRd5rVcav1M/01DG+AB9VdK7TlFBIU3iNEHR\n"
      "wxRVbHzTP3CLMKJRRidT/BQF/r8GWBvdoOvhD0CVPvttyErT665a2KoQThwOpo8=\n"
      "=QEAt\n"
      "-----END PGP MESSAGE-----\n">>.
