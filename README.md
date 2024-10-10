epgp
=====

A minimal erlang library for PGP symmetric encryption.

For now we have only implemented the absolute minimally that we needed.
But feel free to add the rest from the RFC.

Build
-----

    $ make

REPL
-----

    $ make repl
    epgp:sym_encrypt(<<"The secret wørds are squeamish ossifrage"/utf8>>, <<"apa">>).
    epgp:parse(epgp:sym_encrypt(<<"The secret wørds are squeamish ossifrage"/utf8>>,
                                <<"apa">>), <<"apa">>).

Limitations
-----

- Only handles symmetric encryption
- Only iter_salted_s2k
- Only aes_256_cfb128
- Only sha256
- Only utf8
- Only ZIP
