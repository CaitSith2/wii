#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "tools.h"
#include "my_getopt.h"
#include "ecc.h"
#include "fs_hmac.h"
#include "sha1.h"

#define ZESTIG_VERSION_STRING "Zestig v1.1m by CaitSith2, original version by segher\n"
  
int verbosity_level = 0;
int out_of_band = 0;
int verify_ecc = 0;
int verify_hmac = 0;
int verify_boot1 = 0;
int otp_used = 0;
  
static const u8 *rom;
static const u8 *super;
static u8 superblock[0x40000];
static const u8 *fat;
static const u8 *fst;

static u8 hash[20];
static u32 console_id;
static u8 key[16];
static u8 hmac[20];

static const u8 boot1hash_table[3][20] = {
  { 0xB3, 0x0C, 0x32, 0xB9, 0x62, 0xC7, 0xCD, 0x08, 0xAB, 0xE3, 0x3D, 0x01, 0x5B, 0x9B, 0x8B, 0x1D, 0xB1, 0x09, 0x75, 0x44 }, //4A7C...
  { 0xEF, 0x3E, 0xF7, 0x81, 0x09, 0x60, 0x8D, 0x56, 0xDF, 0x56, 0x79, 0xA6, 0xF9, 0x2E, 0x13, 0xF7, 0x8B, 0xBD, 0xDF, 0xDF }, //2CCD...
  { 0xD2, 0x20, 0xC8, 0xA4, 0x86, 0xC6, 0x31, 0xD0, 0xDF, 0x5A, 0xDB, 0x31, 0x96, 0xEC, 0xBC, 0x66, 0x87, 0x80, 0xCC, 0x8D }  //F01E...
};

static u8 boot1key[16] = {0x92, 0x58, 0xA7, 0x52, 0x64, 0x96, 0x0D, 0x82, 0x67, 0x6F, 0x90, 0x44, 0x56, 0x88, 0x2A, 0x73};
static u8 boot1iv[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };

static const u32 console_ids[2] = { 0x021DFFFF, 0x06000000 };

static int verify_boot1_hash(u32 id)
{
  int i;
  static SHA1Context boothash;
  u8 boot1contents[0x800];
  u8 boot1hash[20];

  SHA1Reset(&boothash);
  for(i=0;i<47;i++)
  {
    aes_cbc_dec(boot1key, boot1iv, (u8 *)rom + 0x840*i, 0x800, boot1contents);
    SHA1Input(&boothash,boot1contents,0x800);
  }
  for(i=0;i<5;i++)
    wbe32(boot1hash + (i*4),boothash.Message_Digest[i]);
  if(otp_used)
  {
    if(memcmp(hash,boot1hash,20))
    {
      for(i=0;i<20;i++)
      {
        if(hash[i])
          return 0;
      }   //A hash of ALL 00 in the otp memory means the wii will boot no matter what boot1 is present.
      return 1;
    }
    else
      return 1;
  }
  else
  {
    if(id == 0xFFFFFFFF)
    {
      for(i=0;i<3;i++)
      {
        if(!memcmp(boot1hash,boot1hash_table[i],20))
          break;
      }
      if(i<3)
        return 1;
      else
        return 0;
    }
    else if(id <= console_ids[0])
    {
      if(memcmp(boot1hash,boot1hash_table[0],20))
        return 0;
      else
        return 1;
    }
    else if((id > console_ids[0]) && (id < console_ids[1]))
    {
      if(memcmp(boot1hash,boot1hash_table[1],20))
        return 0;
      else
        return 1;
    }
    else
    {
      if(memcmp(boot1hash,boot1hash_table[2],20))
        return 0;
      else
        return 1;
    }
  }
  return 0;
}

static const u8 *map_rom(const char *name)
{
  int i;
  fprintf(stderr,"Opening nand dump\n");
  FILE *fd = fopen(name,"rb");
  if(fd==NULL)
    fatal("Could not open nand dump %s",name);
	void *map = malloc(0x21000400);
  if(map==NULL)
    fatal("Could not allocate memory for nand dump %s",name);
  fprintf(stderr,"reading nand dump\n");
  for(i=0;i<64;i++)
  {
    if(fread(map+i*0x840010,0x840010,1,fd)!=1)
      break;
    fprintf(stderr,".");
  }
	fclose(fd);
  fprintf(stderr,"\n");
	return map;
}

static const u8 *find_super(void)
{
	u32 newest = 0;
	const u8 *super = 0, *p;
  int start = 0x1fc00000;
  int end = 0x20000000;
  int add = 0x40000;
  int i,j;
  u8 block_hmac[40];
  u8 hmac_super[20];
  
  if(out_of_band)
  {
    start=0x20BE0000;
    end = 0x21000000;
    add = 0x42000;
  }

	for (p = rom + start,j=0; p < rom + end; p += add,j++)
		if (be32(p) == 0x53464653) {
			u32 version = be32(p + 4);
			if (super == 0 || version > newest) {
        if(out_of_band)
        {
          for(i=0;i<128;i++)
          {
            memcpy(superblock+(i*2048),p+(i*2112),2048);
          }
        }
        if(verify_hmac)
        {
          memcpy(block_hmac,p+add-0x87F,32);
          memcpy(block_hmac+32,p+add-0x3F,8);
          fs_hmac_meta(superblock,0x7F00+(0x10*j),hmac_super);
          if(memcmp(hmac_super,block_hmac,20) && memcmp(hmac_super,block_hmac+20,20))
          {
            fprintf(stdout,"Warning: HMAC for superblock %d is invalid. Not using this block\n",j);
            continue;
          }
          else
            fprintf(stdout,"Super block %d OK\n",j);
        }
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

	fprintf(stdout, "%c", dir[mode & 3]);
	for (i = 0; i < 3; i++) {
		fprintf(stdout, "%c", perm[(mode >> 6) & 1]);
		fprintf(stdout, "%c", perm[(mode >> 6) & 2]);
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

  if(verbosity_level >= 3)
  {
  	print_mode(mode);
  	fprintf(stdout, " %02x %04x %04x %08x (%04x %08x) ",
  	        attr, uid, gid, size, x1, x3);
  }
  else
    fprintf(stdout, "    ");
  fprintf(stdout, "%s\n",name);
}

static u8 block[0x4000];

static void do_file(const u8 *entry, const char *parent_path, int entry_num)
{
	char name[13];
	char path[256];
	u8 iv[16];
	u16 sub;
	u32 size, this_size;
	FILE *fp;
  int i,j=0;
  u8 hmac_block[40];
  u8 hmac_data[20];

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
    if(out_of_band)
    {
      for(i=0;i<8;i++)
      {
        aes_cbc_dec(key, iv, (u8 *)rom + 0x4200*sub + 0x840*i, 0x800, block + 0x800*i);
      }
      if(verify_hmac)
      {
        memcpy(hmac_block,rom+(0x4200*(sub+1))-0x87F,32);
        memcpy(hmac_block+32,rom+(0x4200*(sub+1))-0x3F,8);
        fs_hmac_data(block,be16(entry+0x18),entry,entry_num,be32(entry+0x1C),j++,hmac_data);
        if(memcmp(hmac_data,hmac_block,20) && memcmp(hmac_data,hmac_block+20,20))
        {
          fprintf(stdout,"Warning: Invalid hmac for file %s in cluster %d\n",path,j);
        }
      }
    }
    else
    {
		  aes_cbc_dec(key, iv, (u8 *)rom + 0x4000*sub, 0x4000, block);
    }

		fwrite(block, 1, this_size, fp);

		size -= this_size;
		sub = be16(fat + 2*sub);
	}

	fclose(fp);
}

static void do_entry(const u8 *entry, const char *parent_path, int entry_num);

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
  if(verbosity_level>1)
  {
  	fprintf(stdout, "%s:\n", path);
  	if (sub != 0xffff)
  		print_dir_entries(fst + 0x20*sub);
  	fprintf(stdout, "\n");
  }
  else if (verbosity_level==1)
  {
    fprintf(stdout, "%s\n", path);
  }

	if (path[1])
		mkdir(path + 1, 0777);

	if (sub != 0xffff)
		do_entry(fst + 0x20*sub, path, sub);
}

static void do_entry(const u8 *entry, const char *parent_path, int entry_num)
{
	u8 mode;
	u16 sib;

	mode = entry[0x0c];
	sib = be16(entry + 0x10);

	if (sib != 0xffff)
		do_entry(fst + 0x20*sib, parent_path, sib);

	mode &= 3;

	switch(mode) {
	case 1:
		do_file(entry, parent_path, entry_num);
		break;
	case 2:
		do_dir(entry, parent_path);
		break;
	default:
		fprintf(stdout, "unknown mode! (%d)\n", mode);
	}
}

void print_help()
{
  printf("usage: zestig [options] nandfilename\n");
	printf("Valid options:\n");
	printf("  --name=NAME    Load wii-specific keys from ~/.wii/NAME\n");
	printf("  --otp=OTP      Load keys from the given OTP dump instead of using ~/.wii/\n");
  printf("  --nandotp      Load keys from nand dump instead of using ~/.wii/\n");
  printf("  --oob          Use out of band (extra data) if it exists\n");
  printf("  --ecc          Verifies ecc data. (Requires --oob)\n");
  printf("  --hmac         Verifies superblock/file hmac (Requires --oob)\n");
  printf("  --boot1        Verifies boot1 hash\n");
  printf("  --out=PATH     Where to store dumped files. Defaults to ./wiiflash/");
	printf("  --verbose      Shows file listing, repeat for more details.\n");
	printf("\n");
	printf("  --help         Display this help and exit\n");
	printf("  --version      Print version and exit\n");
}

int main(int argc, char **argv)
{
  char path[256];
  char wiiname[256] = {0};
  char otp[256] = {0};
  char nanddump[256] = {0};
  char nandotp = 0;
  int i, result;
	printf("zestig\n\n");
	
  static const struct option wiifsck_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'V' },
    { "ecc", no_argument, 0, 'E' },
    { "hmac", no_argument, 0, 'H' },
    { "boot1", no_argument, 0, 'b' },
		{ "name", required_argument, 0, 'n' },
    { "oob", no_argument, 0, 'o' },
		{ "otp", required_argument, 0, 'O' },
    { "out", required_argument, 0, 'p' },
    { "nandotp", no_argument, 0, 'N' },
		{ "verbose", no_argument, 0, 'v' },
		{ 0, 0, 0, 0 }
	};
  if(argc==1)
  {
    printf("usage: zestig [options] nandfilename\n");
    printf("Try --help for more information on [options]\n");
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
      case 'p':
        strncpy(nanddump,my_optarg,255);
        break;
			case '?':
				printf("Invalid option -%c. Try --help\n", my_optopt);
				exit(-1);
      case 'E':
        verify_ecc = 1;
        break;
      case 'H':
        verify_hmac = 1;
        break;
      case 'b':
        verify_boot1 = 1;
        break;
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
  if(nandotp)
  {
    memcpy(hash,rom+0x21000100,20);
    memcpy(&console_id,rom+0x21000124,4);
    memcpy(key,rom+0x21000158,16);
    memcpy(hmac,rom+0x21000144,20);  //Why not, its already here.
    otp_used = 1;
  }
  else if(otp[0] != 0)
  {
    int fd = open(otp, O_RDONLY);
    if(fd<0)
      fatal("Could not open otp file %s",otp);
    void *otpdata = mmap(0, 0x100, PROT_READ, MAP_SHARED, fd, 0);
    if(otpdata==NULL)
      fatal("Could not allocate memory for otp file %s",otp);
    close(fd);
    memcpy(hash,otpdata+0x24,20);
    memcpy(&console_id,otpdata,4);
    memcpy(key,otpdata+0x58,16);
    memcpy(hmac,otpdata+0x44,20);  //Why not, its already here.
    otp_used = 1;
  }
  else if(wiiname[0]!=0)
  {
    sprintf(path,"%s/nand-key",wiiname);
    get_key(path, key, 16);
    if(verify_hmac)
    {
      sprintf(path,"%s/nand-hmac",wiiname);
      get_key(path, hmac, 20);
    }
    if(verify_boot1)
    {
      sprintf(path,"%s/NG-id",wiiname);
      if(get_key_optional(path, (u8*)&console_id, 4))
        console_id = 0xFFFFFFFF;
    }
  }
  else
  {
    get_key("default/nand-key", key, 16);
    if(verify_hmac)
      get_key("default/nand-hmac", hmac, 20);
    if(verify_boot1)
    {
      if(get_key_optional("default/NG-id", (u8*)&console_id, 4))
        console_id = 0xFFFFFFFF;
    }
  }
	
  if(verify_ecc)
  {
    if(!out_of_band)
    {
      fprintf(stderr,"Warning: --oob required to verify ecc.\n");
      verify_ecc = 0;
    }
    else
    {
      fprintf(stderr,"Verifying ECC data\n");
      for(i=0;i<262144;i++)
      {
        if((i%4096)==4095)
          fprintf(stderr,".");
        result=check_ecc((u8*)rom+(i*2112));
        if(result==-1)
          fprintf(stderr,"ECC error at page %d\n",i);
      }
      fprintf(stderr,"\n");
    }
  }
  if(verify_hmac)
  {
    if(!out_of_band)
    {
      fprintf(stderr,"Warning: --oob required to verify hmac.\n");
      verify_hmac=0;
    }
    else
    {
      fprintf(stderr,"Verifying superblock/file hmac\n");
      fs_hmac_set_key(hmac,20);
    }
  }
  if(verify_boot1)
  {
    fprintf(stderr,"Verifying boot1");
    if(console_id < 0xFFFFFFFF)
      fprintf(stderr," for console ID 0x%X: ",be32((u8*)&console_id));
    else
      fprintf(stderr,", console ID unknown: ");
    if(!verify_boot1_hash(be32((u8*)&console_id)))
      fprintf(stderr,"Invalid\n");
    else
      fprintf(stderr,"OK\n");
  }
  
	super = find_super();
  if(super==NULL)
  {
    printf("No valid superblocks found\n");
    if(out_of_band)
    {
      if(verify_hmac)
      {
        printf("  Your hmac key is most likely invalid.\n  Try removing --hmac from options\n");
      }
      else
      {
        printf("  Try removing --oob from options\n");
      }
    }
    else
      printf("  Try adding --oob to options\n");
    exit(1);
  }
  if(out_of_band)
  {
    fat = superblock + 0x0c;
  }
  else
  {
  	fat = super + 0x0c;
  }
  	fst = fat + 0x10000;
  if(nanddump[0]==0)
  {
    mkdir("wiiflash",0777);
    chdir("wiiflash");
  }
  else
  {
  	mkdir(nanddump, 0777);
  	chdir(nanddump);
  }
	do_entry(fst, "", 0);
	chdir("..");

	return 0;
}
