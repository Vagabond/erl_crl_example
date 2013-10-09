.PHONY: compile check

all: compile

compile: ebin
	erlc -o ebin src/*.erl

ebin:
	@mkdir ebin

CA:
	@echo -n "Generating Certificates..."
	@erl -pa ebin -noshell -run make_certs all /tmp $(shell pwd)/CA -s init stop
	@echo " done"

check: compile CA
	@./check.sh
