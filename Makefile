INPUT1 = "input/trace1.pcapng"
OUTPUT1 = "output/out1.txt"
# INPUT2 = "input/trace2.pcapng"
# OUTPUT2 = "output/out2.txt"
# INPUT3 = "input/trace3.pcapng"
# OUTPUT3 = "output/out3.txt"
# INPUT4 = "input/trace4.pcapng"
# OUTPUT4 = "output/out4.txt"
# INPUT5 = "input/trace5.pcapng"
# OUTPUT5 = "output/out5.txt"
# INPUT6 = "input/traceroute-frag.pcapng"
# OUTPUT6 = "output/out6frag.txt"
# INPUT7 = "input/win_trace1.pcapng"
# OUTPUT7 = "output/out7win.txt"
# INPUT8 = "input/win_trace2.pcapng"
# OUTPUT8 = "output/out8win.txt"

.c.o:
	gcc -g -c $?

all:
	@ gcc -o run src/traceroute.c \
	src/traceroute_print.c \
	src/traceroute_helpers.c \
	src/traceroute_error.c \
	src/traceroute_time.c -lpcap -lm 
	./run ${INPUT1} > ${OUTPUT1}
	# ./run ${INPUT2} > ${OUTPUT2}
	# ./run ${INPUT3} > ${OUTPUT3}
	# ./run ${INPUT4} > ${OUTPUT4}
	# ./run ${INPUT5} > ${OUTPUT5}
	# ./run ${INPUT6} > ${OUTPUT6}
	# ./run ${INPUT7} > ${OUTPUT7}
	# ./run ${INPUT8} > ${OUTPUT8}