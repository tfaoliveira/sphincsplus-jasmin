Intrinsics accepting no size suffix:
 - AESDEC
 - AESDECLAST
 - AESENC
 - AESENCLAST
 - AESIMC
 - AESKEYGENASSIST
 - CLC
 - CLFLUSH
 - LFENCE
 - MFENCE
 - PCLMULQDQ
 - SETcc
 - SFENCE
 - STC
 - VAESDEC
 - VAESDECLAST
 - VAESENC
 - VAESENCLAST
 - VAESIMC
 - VAESKEYGENASSIST
 - VEXTRACTI128
 - VINSERTI128
 - VMOVHPD
 - VMOVLPD
 - VPBROADCAST_2u128
 - VPERM2I128
 - VPERMD
 - VPERMQ
 - concat_2u128
 - init_msf
 - mov_msf
 - protect_ptr
 - swap
 - update_msf

Intrinsics accepting one optional size suffix, e.g., “_64”:
 - ADC
 - ADCX
 - ADD
 - ADOX
 - AND
 - ANDN
 - BSWAP
 - BT
 - CMOVcc
 - CMP
 - CQO
 - DEC
 - DIV
 - IDIV
 - IMUL
 - IMULr
 - IMULri
 - INC
 - LEA
 - LZCNT
 - MOV
 - MOVD
 - MOVV
 - MOVX
 - MUL
 - MULX
 - MULX_hi
 - MULX_lo_hi
 - NEG
 - NOT
 - OR
 - PDEP
 - PEXT
 - POPCNT
 - RCL
 - RCR
 - RDTSC
 - RDTSCP
 - ROL
 - ROR
 - SAL
 - SAR
 - SBB
 - SHL
 - SHLD
 - SHR
 - SHRD
 - SUB
 - TEST
 - VMOV
 - VMOVDQA
 - VMOVDQU
 - VMOVSHDUP
 - VMOVSLDUP
 - VPALIGNR
 - VPAND
 - VPANDN
 - VPBLENDVB
 - VPCLMULQDQ
 - VPEXTR
 - VPMADDUBSW
 - VPMADDWD
 - VPMUL
 - VPMULU
 - VPOR
 - VPSHUFB
 - VPSHUFD
 - VPSHUFHW
 - VPSHUFLW
 - VPSLLDQ
 - VPSRLDQ
 - VPTEST
 - VPXOR
 - VSHUFPS
 - XCHG
 - XOR
 - adc
 - copy
 - mulu
 - protect
 - sbb
 - set0

Intrinsics accepting a zero/sign extend suffix, e.g., “_u32u16”:
 - MOVSX
 - MOVZX
 - VPMOVMSKB

Intrinsics accepting one vector description suffix, e.g., “_4u64”:
 - VPACKSS
 - VPACKUS
 - VPADD
 - VPAVG
 - VPBLEND
 - VPBROADCAST
 - VPCMPEQ
 - VPCMPGT
 - VPINSR
 - VPMAX
 - VPMAXS
 - VPMAXU
 - VPMIN
 - VPMINS
 - VPMINU
 - VPMULH
 - VPMULHRS
 - VPMULHU
 - VPMULL
 - VPSLL
 - VPSLLV
 - VPSRA
 - VPSRL
 - VPSRLV
 - VPSUB
 - VPUNPCKH
 - VPUNPCKL

Intrinsics accepting two vector description suffixes, e.g., “_2u16_2u64”:
 - VPMOVSX
 - VPMOVZX

Intrinsics accepting a flag setting suffix (i.e. “S”) and a condition suffix (i.e. “cc”):

