#/bin/sh

echo -n "Generating Certificates..."
erl -pa ebin -noshell -run make_certs all /tmp $(pwd)/CA -s init stop
echo " done"

erl -pa ebin -noshell -s server -s init stop>/dev/null 2>&1 &
pid=$!
sleep 2
erl -pa ebin -noshell -s client -s init stop >/dev/null 2>&1


if [ $? -eq 0 ]; then
	echo "TEST PASSED"
else
	kill $pid
	echo "TEST FAILED"
fi
