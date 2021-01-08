DIR := $(PWD)
GIT_ORIGIN=origin
BUILD := $(shell git rev-parse --short HEAD)
PROJECTNAME := $(shell basename "$(PWD)")

DRUTINY_BIN=$(shell ./vendor/bin/drutiny)
DRUSH_BIN=$(shell drush --version 2> /dev/null)

VERSION=$(shell git describe --tags --abbrev=0)
DATE=$(shell date +%FT%T%z)
VERSION_FORMATTED=$(shell git describe --tags --abbrev=0 | sed 's/\./-/g')

all: clean composer-install check-drush 

.PHONY: clean
clean:
	rm -rf vendor/
	rm -rf builds/

install: clean composer-install

composer-install:
	composer install -o

check-drush:
ifndef DRUSH_BIN
	$(error "drush is not available, please install")
endif
	@echo $(DRUSH_BIN)

# Release phar (WIP)
release-test:
	mkdir -p builds
	./vendor/drutiny/drutiny/bin/build_phar
	mv drutiny*.phar builds/

current-tag:
	CURRENT=$(shell git describe --abbrev=0 --tags)