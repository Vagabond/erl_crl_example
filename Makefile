.PHONY: compile check

all: compile

compile:
	erlc -o ebin src/*.erl

check: compile
	@./check.sh
