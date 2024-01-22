# example of extracting multiple functions at once, for instance, 32,1024 and 32,2048
# $ ./../test/scripts/jpp -I Sphincs:../ -in shake256.jtmpl -out shake256_lib.jazz
# $ ../test/scripts/preprocessor --input_file shake256_lib.jazz --output_file shake256_lib.jazz --task "fn:__shake256 p:OUTLEN:32 p:INLEN:1024" "fn:__shake256 p:OUTLEN:32 p:INLEN:2048"

JPP           ?= ../test/scripts/jpp
PREPROCESSOR  ?= ../test/scripts/preprocessor

GET_OUTLEN = $(word 1, $(subst _, ,$*))
GET_INLEN  = $(word 2, $(subst _, ,$*))

.PRECIOUS: shake256_%.jpp
shake256_%.jpp:
	$(JPP) -I Sphincs:../ -in shake256.jtmpl -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ --task "fn:__shake256 p:OUTLEN:$(GET_OUTLEN) p:INLEN:$(GET_INLEN)" 

clean:
	rm -f *.jpp
