.PHONY: all compile ct cover check dialyzer clean docclean realclean \
	distclean doc

#
# This Makefile works with rebar3 and the profiles that rebar3 supports. This
# makefile will run with the 'default' profile unless REBAR_PROFILE is
# provided, e.g. in bash,
#
# make rel REBAR_PROFILE=prod
#
REBAR_PROFILE ?= default
THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

$(info $(THIS_MAKEFILE) is using REBAR_PROFILE=$(REBAR_PROFILE))

REBAR3_URL = https://s3.amazonaws.com/rebar3/rebar3

# If there is a rebar in the current directory, use it
ifeq ($(wildcard rebar3),rebar3)
REBAR = $(CURDIR)/rebar3
endif

# Fallback to rebar on PATH
REBAR ?= $(shell which rebar3)

# And finally, prep to download rebar if all else fails
ifeq ($(REBAR),)
REBAR = $(CURDIR)/rebar3
endif

all: compile

compile: $(REBAR)
	$(REBAR) as $(REBAR_PROFILE) do clean, compile

ct: $(REBAR)
	$(REBAR) as test do clean, ct, cover

cover: $(REBAR)
	$(REBAR) as test do clean, compile, cover

dialyzer: $(REBAR)
	$(REBAR) as $(REBAR_PROFILE) do clean, dialyzer

check: ct dialyzer

clean: $(REBAR)
	$(REBAR) clean

realclean: $(REBAR) docclean
	$(REBAR) clean --all

distclean: realclean
	@rm -rf _build logs .test

docclean: clean
	@rm -f doc/*.html doc/*.md doc/edoc-info

doc: $(REBAR)
	$(REBAR) edoc

$(REBAR):
	curl -s -Lo rebar3 $(REBAR3_URL) || wget $(REBAR3_URL)
	chmod a+x $(REBAR)

