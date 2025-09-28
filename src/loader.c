#include <alloca.h>
#include <elf.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

__attribute__((visibility ("hidden"))) void z_trampo(void (*entry)(void), unsigned long *sp, void (*fini)(void));

#if UINTPTR_MAX == 0xffffffffffffffff            
#  define ELFCLASS ELFCLASS64                                
#  define Elf_Ehdr Elf64_Ehdr                   
#  define Elf_Phdr Elf64_Phdr
#  define Elf_auxv_t Elf64_auxv_t                                   
#elif UINTPTR_MAX == 0xffffffff                                       
#  define ELFCLASS ELFCLASS32                                 
#  define Elf_Ehdr Elf32_Ehdr                                        
#  define Elf_Phdr Elf32_Phdr                                                  
#  define Elf_auxv_t Elf32_auxv_t
#else
#  error "Failed to determine 32 or 64 bit arch"
#endif

#define PAGE_SIZE	4096
#define ALIGN		(PAGE_SIZE - 1)
#define ROUND_PG(x)	(((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x)	((x) & ~(ALIGN))
#define PFLAGS(x)	((((x) & PF_R) ? PROT_READ : 0) | \
			 (((x) & PF_W) ? PROT_WRITE : 0) | \
			 (((x) & PF_X) ? PROT_EXEC : 0))
#define LOAD_ERR	((unsigned long)-1)

void z_errx(int eval, const char *fmt, ...)
{
va_list ap;
dprintf(2, "error: ");
va_start(ap, fmt);
vdprintf(2, fmt, ap);
va_end(ap);
dprintf(2, "\n");
_exit(eval);
}

static void z_fini(void)
{
	printf("Fini at work\n");
}

static int check_ehdr(Elf_Ehdr *ehdr)
{
	unsigned char *e_ident = ehdr->e_ident;
	return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
		e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
	    	e_ident[EI_CLASS] != ELFCLASS ||
		e_ident[EI_VERSION] != EV_CURRENT ||
		(ehdr->e_type != ET_EXEC)) ? 0 : 1;
}

static unsigned long loadelf_anon(int fd, Elf_Ehdr *ehdr, Elf_Phdr *phdr)
{
	unsigned long minva, maxva;
	Elf_Phdr *iter;
	ssize_t sz;
	int flags, dyn = ehdr->e_type == ET_DYN;
	unsigned char *p, *base, *hint;

	minva = (unsigned long)-1;
	maxva = 0;
	
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		if (iter->p_type != PT_LOAD)
			continue;
		if (iter->p_vaddr < minva)
			minva = iter->p_vaddr;
		if (iter->p_vaddr + iter->p_memsz > maxva)
			maxva = iter->p_vaddr + iter->p_memsz;
	}

	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);

	/* For dynamic ELF let the kernel chose the address. */	
	hint = dyn ? NULL : (void *)minva;
	flags = dyn ? 0 : MAP_FIXED;
	flags |= (MAP_PRIVATE | MAP_ANONYMOUS);

	/* Check that we can hold the whole image. */
	base = mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);
	if (base == (void *)-1)
		return -1;
	munmap(base, maxva - minva);

	flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
	/* Now map each segment separately in precalculated address. */
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		unsigned long off, start;
		if (iter->p_type != PT_LOAD)
			continue;
		off = iter->p_vaddr & ALIGN;
		start = dyn ? (unsigned long)base : 0;
		start += TRUNC_PG(iter->p_vaddr);
		sz = ROUND_PG(iter->p_memsz + off);

		p = mmap((void *)start, sz, PROT_WRITE, flags, -1, 0);
		if (p == (void *)-1)
			goto err;
		if (lseek(fd, iter->p_offset, SEEK_SET) < 0)
			goto err;
		if (read(fd, p + off, iter->p_filesz) !=
				(ssize_t)iter->p_filesz)
			goto err;
		mprotect(p, sz, PFLAGS(iter->p_flags));
	}

	return (unsigned long)base;
err:
	munmap(base, maxva - minva);
	return LOAD_ERR;
}

//void z_entry(unsigned long *sp, void (*fini)(void))
void exec_elf(unsigned long *entry_sp, const char *file, int argc, char *argv[])
{
	Elf_Ehdr ehdr;
	Elf_Phdr *phdr;
	Elf_auxv_t *av;
	char **env, **p;
	unsigned long *sp = entry_sp;
	ssize_t sz;
	int fd;


	{
		unsigned long *p = sp;
		/* argc */
		p++;
		/* argv */
		while (*p++ != 0);

		unsigned long *from = p;
		/* env */
		while (*p++ != 0);
		/* aux vector */
		while (*p++ != 0) {
			p++;
		}
		p++;

		unsigned long argv_sz = argc * sizeof(*p);
		unsigned sz = (char *)p - (char *)from;
		p = alloca(sizeof(*p) + argv_sz + sz);
		*p = argc;
		memcpy(p + 1, argv, argv_sz);
		memcpy((char *)(p + 1) + argv_sz, from, sz);
		sp = p;
		argv = (char **)sp + 1;
	}

	env = p = (char **)&argv[argc + 1];
	while (*p++ != NULL)
		;
	av = (void *)p;

	(void)env;

		/* Open file, read and than check ELF header.*/
		if ((fd = open(file, O_RDONLY)) < 0)
			z_errx(1, "can't open %s", file);
		if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
			z_errx(1, "can't read ELF header %s", file);
		if (!check_ehdr(&ehdr))
			z_errx(1, "bogus ELF header %s", file);

		/* Read the program header. */
		sz = ehdr.e_phnum * sizeof(Elf_Phdr);
		phdr = alloca(sz);
		if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0)
			z_errx(1, "can't lseek to program header %s", file);
		if (read(fd, phdr, sz) != sz)
			z_errx(1, "can't read program header %s", file);
		/* Time to load ELF. */
	unsigned long base =  loadelf_anon(fd, &ehdr, phdr);
  if (base == LOAD_ERR) {
			z_errx(1, "can't load ELF %s", file);
	}

		close(fd);

	/* Reassign some vectors that are important for
	 * the dynamic linker and for lib C. */
#define AVSET(t, v, expr) case (t): (v)->a_un.a_val = (expr); break
	while (av->a_type != AT_NULL) {
		switch (av->a_type) {
		AVSET(AT_PHDR, av, base + ehdr.e_phoff);
		AVSET(AT_PHNUM, av, ehdr.e_phnum);
		AVSET(AT_PHENT, av, ehdr.e_phentsize);
		AVSET(AT_ENTRY, av, ehdr.e_entry);
		AVSET(AT_EXECFN, av, (unsigned long)argv[1]);
		AVSET(AT_BASE, av, av->a_un.a_val);
		}
		++av;
	}
#undef AVSET
	++av;

	z_trampo((void (*)(void))(ehdr.e_entry), sp, z_fini);
	/* Should not reach. */
	_exit(0);
}

int main(int argc, char *argv[])
{
  /* We assume that argv comes from the original executable params. */
  unsigned long* entry_sp = (unsigned long*)argv - 1; 

	if (argc < 2)
		z_errx(1, "no input file");

	exec_elf(entry_sp, argv[1], argc - 1, argv + 1);
}
