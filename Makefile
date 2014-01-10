REBAR ?= $(shell which rebar)

all:
	$(REBAR) compile

clean:
	$(REBAR) clean
