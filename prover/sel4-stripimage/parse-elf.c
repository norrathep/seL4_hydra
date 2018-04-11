#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

struct cpio_header {
    char c_magic[6];      /* Magic header '070701'. */
    char c_ino[8];        /* "i-node" number. */
    char c_mode[8];       /* Permisions. */
    char c_uid[8];        /* User ID. */
    char c_gid[8];        /* Group ID. */
    char c_nlink[8];      /* Number of hard links. */
    char c_mtime[8];      /* Modification time. */
    char c_filesize[8];   /* File size. */
    char c_devmajor[8];   /* Major dev number. */
    char c_devminor[8];   /* Minor dev number. */
    char c_rdevmajor[8];
    char c_rdevminor[8];
    char c_namesize[8];   /* Length of filename in bytes. */
    char c_check[8];      /* Checksum. */
};

static unsigned long parse_hex_str(char *s, unsigned int max_len)
{
    unsigned long r = 0;
    unsigned long i;

    for (i = 0; i < max_len; i++) {
        r *= 16;
        if (s[i] >= '0' && s[i] <= '9') {
            r += s[i] - '0';
        }  else if (s[i] >= 'a' && s[i] <= 'f') {
            r += s[i] - 'a' + 10;
        }  else if (s[i] >= 'A' && s[i] <= 'F') {
            r += s[i] - 'A' + 10;
        } else {
            return r;
        }
        continue;
    }
    return r;
}

unsigned long get_cpio_size(char *fbase) {
	struct cpio_header *header = (void*) fbase;
	//printf("name size %lu\n", parse_hex_str(header->c_namesize, sizeof(header->c_namesize)));
	return parse_hex_str(header->c_filesize, sizeof(header->c_filesize));

}

unsigned long parse_cpio(char *fbase) {
	
	for(int i=1; ; i++) {
		if(fbase[i] == 0x30 && fbase[i+1] == 0x37 && fbase[i+2] == 0x30 && fbase[i+3] == 0x37 && fbase[i+4] == 0x30 && fbase[i+5] == 0x31) return i;
		if(fbase[i] == 0x54 && fbase[i+1] == 0x52 && fbase[i+2] == 0x41 && fbase[i+3] == 0x49) return i;

	}
	
	/*struct cpio_header *header = (void*) fbase;
	printf("name size %lu\n", parse_hex_str(header->c_namesize, sizeof(header->c_namesize)));
	return parse_hex_str(header->c_filesize, sizeof(header->c_filesize))+sizeof(struct cpio_header)+11;*/
}

int parse(char *fbase) {
	
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)fbase;
	Elf32_Shdr *sects = (Elf32_Shdr *)(fbase + ehdr->e_shoff);
	int shsize = ehdr->e_shentsize;
	int shnum = ehdr->e_shnum;
	int shstrndx = ehdr->e_shstrndx;

	return ehdr->e_ehsize + (ehdr->e_phnum * ehdr->e_phentsize) + (ehdr->e_shnum * ehdr->e_shentsize);

	/*Elf32_Shdr *shstrsect = &sects[shstrndx];
	char *shstrtab = fbase + shstrsect->sh_offset;

	int i;
	for(i=0; i<shnum; i++) {
	    if(!strcmp(shstrtab+sects[i].sh_name, ".rodata")) {
		printf("found text\n");
	    }
	}*/

}

int find_trailer(char *start, int len) {

	int i=0;
	for(i=0; i<len; i++) {
		if(start[i] == 0x54 && start[i+1] == 0x52 && start[i+2] == 0x41 && start[i+3] == 0x49) {
			return i+9;
		}
	}
	return -1;
}

int find_header(char *fbase, int len) {

	int i=0;
	for(i=0; i<len; i++) {
		if(fbase[i] == 0x30 && fbase[i+1] == 0x37 && fbase[i+2] == 0x30 && fbase[i+3] == 0x37 && fbase[i+4] == 0x30 && fbase[i+5] == 0x31) {
			return i;
		}
	}
	return -1;

}

int main() {

	char* file = "../images/dhs-demo-image-arm-imx6";
	int fd = open(file, O_RDONLY);

	/* map ELF file into memory for easier manipulation */
	struct stat statbuf;
	fstat(fd, &statbuf);
	char *fbase = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);

	int i=0;
	int start_addr, write_len = 0;
	int cs;

	/*for(i=0x807c; i<0x807c+8*4096; i++) {
		uint8_t count, value = fbase[i];
            	for(count=0; value!=0; count++, value&=value-1);
            	cs += count;
	}
	printf("cs: %d\n", cs);
	return 1;*/
	
	/*while(1) {
		int start_addr = i+find_header(fbase+i, statbuf.st_size-i);
		int end_addr = i+find_trailer(fbase+i, statbuf.st_size-i);
		if(start_addr == -1 || end_addr == -1) break;
		int len = end_addr - start_addr;
		i = end_addr;
		if(len < 2000) continue;
		printf("header at: %d, trailer at: %d\n", start_addr, end_addr);
		char buf[20];
		sprintf(buf, "%s_%d", file, start_addr);
		printf("buf: %s\n", buf);
		int fd2 = open(buf, O_CREAT | O_WRONLY);// | O_APPEND);
		if(fd2 < 0) {
			printf("sth wrong\n");
			break;
		}
		if(write(fd2, fbase+start_addr, len) != len) {
			printf("also sth wrong\n");
			break;
		}
		if(i > statbuf.st_size) break;

	}*/

	for(i=0; i<statbuf.st_size-6; i++) {
		if(fbase[i] == 0x30 && fbase[i+1] == 0x37 && fbase[i+2] == 0x30 && fbase[i+3] == 0x37 && fbase[i+4] == 0x30 && fbase[i+5] == 0x31) {
			unsigned long size = parse_cpio(fbase+i);
			char *image_name = fbase+i+sizeof(struct cpio_header);
			
			// skip trailer
			if(size < 100 || strcmp(image_name, "TRAILER!!!") == 0) continue;
			
			printf("Found elf image: size = %lu at %d, name %s\n", size, i, image_name);
			int fd2 = open(image_name, O_CREAT | O_WRONLY | O_APPEND);
			if(fd2 < 0) {

				printf("sth wrong\n");
				break;
			}
			if(write(fd2, fbase+i, size) != size) {
				printf("also sth wrong\n");
				break;
			}

		}
	}	
	/*for(i=0; i<statbuf.st_size-6; i++) {
		//if(fbase[i] == 0x7f && fbase[i+1] == 0x45 && fbase[i+2] == 0x4c && fbase[i+3] == 0x46) {
		if(fbase[i] == 0x30 && fbase[i+1] == 0x37 && fbase[i+2] == 0x30 && fbase[i+3] == 0x37 && fbase[i+4] == 0x30 && fbase[i+5] == 0x31) {
			int max_chars = 20;
			if(i > max_chars) {
				int j=0;
				printf("img name: ");
				for(j=max_chars; j>0; j--) {
					printf("%c", fbase[i-j]);
				}
				printf(" at offset %x\n", i);
			}
			char buf[20];
			sprintf(buf, "%s_%d", file, i);
			printf("buf: %s\n", buf);
			int fd2 = open(buf, O_CREAT | O_WRONLY | O_APPEND);
			if(fd2 < 0) {

				printf("sth wrong\n");
				break;
			}
			if(write(fd2, fbase+i, statbuf.st_size-i) != statbuf.st_size-i) {
				printf("also sth wrong\n");
				break;
			}
			//parse(fbase+i);
		} else if(fbase[i] == 0x54 && fbase[i+1] == 0x52 && fbase[i+2] == 0x41 && fbase[i+3] && 0x49) {
			printf("TRAILER at offset %x\n", i);
		}
		
	}*/
}
