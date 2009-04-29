#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "tools.h"
#include "my_getopt.h"

#define ZESTIG_VERSION_STRING "Zestig v1.0m by CaitSith2, original version by segher\n"
  
int verbosity_level;
int out_of_band = 0;
int verify_ecc = 0;
int verify_hmac = 0;
  
static const u8 *rom;
static const u8 *super;
static u8 superblock[0x40000];
static const u8 *fat;
static const u8 *fst;

static u8 key[16];


static const u8 *map_rom(const char *name)
{
	int fd = open(name, O_RDONLY);
  printf("Opening nand dump\n");
  if(fd<0)
    fatal("Could not open nand dump %s",name);
	void *map = mmap(0, 0x21000400, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
  if(map==NULL)
    fatal("Could not allocate memory for nand dump %s",name);
	return map;
}

static const u8 *find_super(void)
{
	u32 newest = 0;
	const u8 *super = 0, *p;
  int start = 0x1fc00000;
  int end = 0x20000000;
  int add = 0x40000;
  
  if(out_of_band)
  {
    start=0x20BE0000;
    end = 0x21000000;
    add = 0x42000;
  }

	for (p = rom + start; p < rom + end; p += add)
		if (be32(p) == 0x53464653) {
			u32 version = be32(p + 4);
			if (super == 0 || version > newest) {
				super = p;
				newest = version;
			}
		}

	return super;
}

static void print_mode(u8 mode)
{
	int i;
	const char dir[4] = "?-d?";
	const char perm[3] = "-rw";

	fprintf(stderr, "%c", dir[mode & 3]);
	for (i = 0; i < 3; i++) {
		fprintf(stderr, "%c", perm[(mode >> 6) & 1]);
		fprintf(stderr, "%c", perm[(mode >> 6) & 2]);
		mode <<= 2;
	}
}

static void print_entry(const u8 *entry)
{
	char name[13];
	u8 mode, attr;
	u16 sub, sib;
	u32 size;
	u16 x1, uid, gid;
	u32 x3;

	memcpy(name, entry, 12);
	name[12] = 0;
	mode = entry[0x0c];
	attr = entry[0x0d];
	sub = be16(entry + 0x0e);
	sib = be16(entry + 0x10);
	size = be32(entry + 0x12);
	x1 = be16(entry + 0x16);
	uid = be16(entry + 0x18);
	gid = be16(entry + 0x1a);
	x3 = be32(entry + 0x1c);

	print_mode(mode);
	fprintf(stderr, " %02x %04x %04x %08x (%04x %08x) %s\n",
	        attr, uid, gid, size, x1, x3, name);
}

static u8 block[0x4000];

static void do_file(const u8 *entry, const char *parent_path)
{
	char name[13];
	char path[256];
	u8 iv[16];
	u16 sub;
	u32 size, this_size;
	FILE *fp;

	memcpy(name, entry, 12);
	name[12] = 0;
	sub = be16(entry + 0x0e);
	size = be32(entry + 0x12);

	if (parent_path[strlen(parent_path) - 1] == '/' || name[0] == '/')
		sprintf(path, "%s%s", parent_path, name);
	else
		sprintf(path, "%s/%s", parent_path, name);

	fp = fopen(path + 1, "wb");

	while (size) {
		this_size = size > 0x4000 ? 0x4000 : size;

		memset(iv, 0, sizeof iv);
		aes_cbc_dec(key, iv, (u8 *)rom + 0x4000*sub, 0x4000, block);

		fwrite(block, 1, this_size, fp);

		size -= this_size;
		sub = be16(fat + 2*sub);
	}

	fclose(fp);
}

static void do_entry(const u8 *entry, const char *parent_path);

static void print_dir_entries(const u8 *entry)
{
	u16 sib;

	sib = be16(entry + 0x10);

	if (sib != 0xffff)
		print_dir_entries(fst + 0x20*sib);

	print_entry(entry);
}

static void do_dir(const u8 *entry, const char *parent_path)
{
	char name[13];
	char path[256];
	u16 sub, sib;

	memcpy(name, entry, 12);
	name[12] = 0;
	sub = be16(entry + 0x0e);
	sib = be16(entry + 0x10);

	if (parent_path[strlen(parent_path) - 1] == '/' || name[0] == '/')
		sprintf(path, "%s%s", parent_path, name);
	else
		sprintf(path, "%s/%s", parent_path, name);
	fprintf(stderr, "%s:\n", path);
	if (sub != 0xffff)
		print_dir_entries(fst + 0x20*sub);
	fprintf(stderr, "\n");

	if (path[1])
		mkdir(path + 1, 0777);

	if (sub != 0xffff)
		do_entry(fst + 0x20*sub, path);
}

static void do_entry(const u8 *entry, const char *parent_path)
{
	u8 mode;
	u16 sib;

	mode = entry[0x0c];
	sib = be16(entry + 0x10);

	if (sib != 0xffff)
		do_entry(fst + 0x20*sib, parent_path);

	mode &= 3;

	switch(mode) {
	case 1:
		do_file(entry, parent_path);
		break;
	case 2:
		do_dir(entry, parent_path);
		break;
	default:
		fprintf(stderr, "unknown mode! (%d)\n", mode);
	}
}

void print_help()
{
  printf("usage: zestig [options] nandfilename\n");
	printf("Valid options:\n");
	printf("  --name=NAME    Load wii-specific keys from ~/.wii/NAME\n");
	printf("  --otp=NAME     Load keys from the given OTP dump instead of using ~/.wii/\n");
  printf("  --nandotp      Load keys from nand dump instead of using ~/.wii/\n");
  printf("  --oob          Use out of band (extra data) if it exists\n");
	printf("  --verbose      Increase verbosity, can be specified multiple times\n");
	printf("\n");
	printf("  --help         Display this help and exit\n");
	printf("  --version      Print version and exit\n");
}

int main(int argc, char **argv)
{
  char otp[256] = {0};
  char nandotp = 0;
  int i;
	printf("zestig\n\n");

	char wiiname[256] = {0};
  
  static const struct option wiifsck_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'V' },
		{ "name", required_argument, 0, 'n' },
    { "oob", no_argument, 0, 'o' },
		{ "otp", required_argument, 0, 'O' },
    { "nandotp", no_argument, 0, 'N' },
		{ "verbose", no_argument, 0, 'v' },
		{ 0, 0, 0, 0 }
	};
  if(argc==1)
  {
    printf("usage: zestig [options] nandfilename\n");
    printf("Try -h for more information on [options]\n");
    exit(0);
  }
  int c = 0;
	int optionindex;
  
	while(c >= 0) {
		c = my_getopt_long_only(argc, argv, "-:", wiifsck_options, &optionindex);
		switch (c) {
			case 'n':
				strncpy(wiiname, my_optarg, 255);
				break;
      case 'N':
        nandotp = 1;
        break;
			case 'v':
				verbosity_level++;
				break;
			case 'h':
				print_help();
				exit(0);
			case 'V':
				printf(ZESTIG_VERSION_STRING);
				printf("\n");
				exit(0);
			case 'O':
        strncpy(otp, my_optarg, 255);
				break;
      case 'o':
        out_of_band = 1;
        break;
			case '?':
				printf("Invalid option -%c. Try -h\n", my_optopt);
				exit(-1);
			case 1:
        rom = map_rom(my_optarg);
				break;
		}
	}
  if(rom==NULL)
  {
    printf("error: You must specify a nand file to extract\n");
    exit(0);
  }
	get_key("default/nand-key", key, 16);
  
  
	super = find_super();
  if(out_of_band)
  {
    for(i=0;i<128;i++)
    {
      memcpy(superblock+(i*2048),super+(i*2112),2048);
    }
    fat = superblock + 0x0c;
  }
  else
  {
  	fat = super + 0x0c;
  }
  	fst = fat + 0x10000;
  
	mkdir(argv[2], 0777);
	chdir(argv[2]);
	do_entry(fst, "");
	chdir("..");

	return 0;
}
