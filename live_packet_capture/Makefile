
cleaner: live_packet_capture
	rm -rf *.o

live_packet_capture: package.i main.o device.o network.o
	rm -rf live_packet_capture
	gcc -o live_packet_capture main.o device.o network.o -lpcap

main.o: main.c
	gcc -c -o main.o main.c

device.o: $(PWD)/modules/device.c
	gcc -c -o device.o $(PWD)/modules/device.c

network.o: $(PWD)/modules/network.c
	gcc -c -o network.o $(PWD)/modules/network.c

package.i:
	sudo apt-get install libnet-dev
