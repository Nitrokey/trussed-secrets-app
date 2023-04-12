APPNAME=udp_sim
FLAGS=--features=enable-logs

all: | start-sim attach finish-message

.PHONY: finish-message
finish-message:
	@echo "###################################################"
	@echo "Done. Device should be visible in your system now. Run 'make stop' to disconnect it."

.PHONY: start-sim
start-sim: $(APPNAME)
	-$(MAKE) stop
	env RUST_LOG=info RUST_BACKTRACE=1 cargo run $(FLAGS) &
	sleep 1

.PHONY: autoattach
autoattach:
	 while true; do $(MAKE) attach; sleep 1; inotifywait ${CARGO_TARGET_DIR}/debug/usbip-simulation; sleep 5; done;

.PHONY: attach
attach: 
	lsmod | grep vhci-hcd || sudo modprobe vhci-hcd
	sudo usbip list -r "localhost"
	sudo usbip attach -r "localhost" -b "1-1"
	sudo usbip attach -r "localhost" -b "1-1"
	sleep 5
	-notify-send 'Webcrypt USB/IP' 'Attached'


.PHONY: ci
ci:
	timeout 10 -k 5 $(MAKE)

.PHONY: build
build: $(APPNAME)

.PHONY: build-clean
build-clean: | clean build

.PHONY: $(APPNAME)
$(APPNAME):
	 cargo build $(FLAGS)

.PHONY: stop
stop:
	-sudo usbip detach -p "00"
	killall $(APPNAME) usbip-simulation

.PHONY: setup-fedora
setup-fedora:
	sudo dnf install usbip -y
	sudo dnf install fuse-devel -y
	sudo dnf install clang-libs clang -y
	sudo ln -s /usr/lib64/libclang.so.15 /usr/lib64/libclang.so

.PHONY: clean
clean:
	cargo clean
	rm $(APPNAME) -v

.PHONY: build-docker
CMD=make -C /app/runners/pc-usbip/ build
build-docker:
	docker build -t usbip .
	mkdir -p cargo-cache
	docker run -it --rm -v $(PWD)/cargo-cache:/root/.cargo -v $(PWD)/../../:/app usbip $(CMD)
	touch $(APPNAME)


LFS=./tmp/littlefs-fuse/lfs
$(LFS):
	mkdir -p tmp
	-cd tmp && git clone https://github.com/littlefs-project/littlefs-fuse
	cd tmp/littlefs-fuse && make

fs=./trussed-state.bin
mount=/tmp/mnt/bee
state=mount.state

.PHONY: mount umount
mount: $(LFS)
	# https://github.com/littlefs-project/littlefs-fuse#usage-on-linux
	mkdir -p $(mount)
	lsmod | grep loop || sudo modprobe loop
	sudo losetup --find --show $(fs) | tee loop.dev
	grep "/dev/loop" loop.dev && sudo chmod a+rw `cat loop.dev`
	$(LFS) --block_count=128 `cat loop.dev` $(mount)
	printf "loop_device=`cat loop.dev`\nmount=$(mount)" > $(state)
	tree -C -h $(mount)

umount:
	-umount $(mount)
	sudo losetup -d `cat loop.dev`
	rm ./$(state)


