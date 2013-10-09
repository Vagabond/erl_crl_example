.PHONY: compile check

all: compile

compile: ebin
	erlc -o ebin src/*.erl

ebin:
	mkdir ebin

check: compile
	@./check.sh
