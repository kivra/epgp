all: compile xref eunit

compile:
	rebar3 compile

xref:
	rebar3 xref

eunit:
	rebar3 eunit

dialyzer:
	rebar3 dialyzer

repl:
	rebar3 shell
