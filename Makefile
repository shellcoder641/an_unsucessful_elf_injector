all: elf_injector hellox64

elf_injector:elfinjector.c
	${CC} -o $@ $<

hellox64:hellox64.s
	nasm -f elf64 -o hellox64.o hellox64.s
	ld -o hellox64 hellox64.o

clean:
	rm hellox64.o elf_injector hellox64
