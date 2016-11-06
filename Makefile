LDLIBS = -lcrypto
CFLAGS = -g

all: build_requestinfo key2spki cm_ipa_csrgen req2reqinfo

build_requestinfo: build_requestinfo_main.o build_requestinfo.o

cm_ipa_csrgen: cm_ipa_csrgen.o build_requestinfo.o

key2spki: key2spki.o build_requestinfo.o

req2reqinfo: req2reqinfo.o build_requestinfo.o
