#/bin/sh

erl -pa ebin -noshell -run make_certs all "${PWD}/CA" "${PWD}/CA" -s init stop

erl -pa ebin -noshell -s server -s init stop > server.log 2>&1 &
pid=$!
sleep 2
erl -pa ebin -noshell -s client -s init stop > client.log 2>&1


if [ $? -eq 0 ]; then
	echo "TEST PASSED"
else
	kill $pid
	echo "TEST FAILED"
fi
