LDLIBS = -lcrypto
CFLAGS = -g

all: build_requestinfo key2spki cm_ipa_csrgen

build_requestinfo: build_requestinfo_main.o build_requestinfo.o

cm_ipa_csrgen: cm_ipa_csrgen.o build_requestinfo.o
