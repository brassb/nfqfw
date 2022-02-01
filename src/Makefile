COMPILER = gcc
APP_NAME = nfqfw
SRC_FILES = $(APP_NAME).c

build: $(SRC_FILES)
	$(COMPILER) -o $(APP_NAME) $(SRC_FILES) -lnetfilter_queue -lcrypto

clean:
	rm $(APP_NAME)
