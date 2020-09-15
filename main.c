//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2016, fmad engineering llc 
//
// fast pcap time order merger 
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <linux/sched.h>

#include "fTypes.h"

//-------------------------------------------------------------------------------------------------

typedef struct
{
	bool		Valid;
	char*		FileName;
	u64			FileLength;

	int			fd;
	u8*			Map;
	u64			MapLength;
	u64			MapPos;

	u64			BufferPos;

	u8*			Buffer;
	bool		BufferValid;
	u64			BufferTS;

	u64			TSScale;

} InputFile_t;

// pcap headers

#define PCAPHEADER_MAGIC_NANO		0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC		0xa1b2c3d4
#define PCAPHEADER_MAJOR			2
#define PCAPHEADER_MINOR			4
#define PCAPHEADER_LINK_ETHERNET	1
#define PCAPHEADER_LINK_ERF			197	

typedef struct
{
	u32				Sec;				// time stamp sec since epoch 
	u32				NSec;				// nsec fraction since epoch

	u32				LengthCapture;		// captured length, inc trailing / aligned data
	u32				Length;				// length on the wire

} __attribute__((packed)) PCAPPacket_t;

// per file header

typedef struct
{

	u32				Magic;
	u16				Major;
	u16				Minor;
	u32				TimeZone;
	u32				SigFlag;
	u32				SnapLen;
	u32				Link;

} __attribute__((packed)) PCAPHeader_t;

double TSC2Nano = 0;

//-------------------------------------------------------------------------------------------------

static void Help(void)
{
	printf("capmerge -o <output file> <input file A> <inputfile B> .. \n");
	printf("\n");
	printf("-v                 : verbose output\n");
	printf("\n");
}

//-------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	int rlen;
	int wlen;
	char* OutFileName = NULL;

	int InFileCnt = 0;
	InputFile_t InFileList[2048];

	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "--help") == 0)
		{
			Help();
			return 0;
		}
		else if (strcmp(argv[i], "-o") == 0)
		{
			OutFileName = argv[i+1];
			i++;
		}
		else if (strcmp(argv[i], "--input") == 0)
		{
			FILE* F = fopen(argv[i + 1], "r");
			assert(F != NULL);

			u8 FileName[1024];
			u32 FileNamePos = 0;
			while (!feof(F))
			{
				int c = fgetc(F);	
				if (c == '\n')
				{
					FileName[FileNamePos] = 0;
					printf("[%s]\n", FileName);

					InFileList[InFileCnt++].FileName = strdup(FileName);

					FileNamePos = 0;
				}
				else
				{
					FileName[FileNamePos++] = c;
				}
			}
			i++;
		}
		else if (argv[i][0] != '-')
		{
			InFileList[InFileCnt++].FileName = strdup(argv[i]);
			if (InFileCnt > 2048)
			{
				printf("too many input files\n");
				exit(0);
			}
		}
	}

	// allocate input buffer & map each file 
	u64 TotalInputBytes = 0;
	for (int i=0; i < InFileCnt; i++)
	{
		InputFile_t* InFile  = &InFileList[i];


		InFile->Valid 		= false; 

		struct stat Stat;	
		stat(InFile->FileName, &Stat);
		InFile->FileLength = Stat.st_size;

		InFile->fd = open64(InFile->FileName, O_RDONLY);
		if (InFile->fd < 0)
		{
			printf("failed to open file [%s]\n", InFile->FileName);
			continue;
		}

		printf("Input [%s] %10.3fGB\n", InFile->FileName, InFile->FileLength / 1e9);

		// map the entire thing
		InFile->MapLength = (Stat.st_size + 1024*1024) & (~(1024*1024-1));	// 1MB round
		InFile->Map = mmap64(0, InFile->MapLength, PROT_READ, MAP_SHARED, InFile->fd, 0); 
		if (InFile->Map == (u8*)-1)
		{
			printf("failed to map File [%s]\n", InFile->FileName);
			return 0;
		}

		// read pcap header in first
		PCAPHeader_t*	Header = (PCAPHeader_t*)InFile->Map;
		switch (Header->Magic)
		{
		case PCAPHEADER_MAGIC_NANO: 
			InFile->TSScale = 1;
			break;
		case PCAPHEADER_MAGIC_USEC:
			InFile->TSScale = 1000;
			break;
		default:
			printf("[%s] invalid magic: %08x\n", InFile->FileName, Header->Magic);	
			assert(false);
		}

		InFile->BufferPos 	= sizeof(PCAPHeader_t);
		InFile->Valid 		= true;
		InFile->BufferValid = false;
		InFile->MapPos = sizeof(PCAPHeader_t);
		TotalInputBytes += InFile->FileLength;
	}

	// output 
	FILE* OutFile = fopen(OutFileName, "w");
	if (!OutFile)
	{
		printf("OutputFilename is invalid [%s]\n", OutFileName);
		return 0;
	}	
	PCAPHeader_t	Header;
	Header.Magic		= PCAPHEADER_MAGIC_NANO;
	Header.Major		= PCAPHEADER_MAJOR;
	Header.Minor		= PCAPHEADER_MINOR;
	Header.TimeZone		= 0; 
	Header.SigFlag		= 0; 
	Header.SnapLen		= 16*1024; 
	Header.Link			= PCAPHEADER_LINK_ETHERNET; 
	fwrite(&Header, 1, sizeof(Header), OutFile);	

	CycleCalibration();
	u64 TotalBytes 		= 0;
	u64 NextPrintTSC 	= 0;
	u64 T0 				= rdtsc();
	while (TotalBytes < TotalInputBytes)
	{
		// load next packet
		for (int i=0; i < InFileCnt; i++)
		{
			InputFile_t* InFile  = &InFileList[i];

			if (!InFile->Valid) continue;
			if (InFile->BufferValid) continue;

			if (InFile->MapPos >= InFile->FileLength)
			{
				printf("end of file reached\n");
				InFile->Valid = false;
				continue;
			}

			PCAPPacket_t* Packet = (PCAPPacket_t*)(InFile->Map + InFile->MapPos);

			// generate TS
			InFile->BufferTS = Packet->Sec * 1e9 + Packet->NSec * InFile->TSScale;

			InFile->MapPos 		+= sizeof(PCAPPacket_t);
			InFile->MapPos 		+= Packet->LengthCapture; 
			InFile->BufferValid = true;
		}

		// find oldest
		u64 TS 		= (u64)-1;
		u32 Index 	= -1;
		for (int i=0; i < InFileCnt; i++)
		{
			if (!InFileList[i].Valid) continue;
			if (!InFileList[i].BufferValid) continue;

			if (InFileList[i].BufferTS < TS)
			{
				TS 		= InFileList[i].BufferTS;
				Index 	= i;
			}
		}
		// all streams finished
		if (Index == -1) break;

		// output
		InputFile_t* InFile = &InFileList[Index];

		PCAPPacket_t* Packet = (PCAPPacket_t*)(InFile->Map + InFile->BufferPos);
		wlen = fwrite(Packet, sizeof(PCAPPacket_t) + Packet->LengthCapture, 1, OutFile); 
		if (wlen != 1)
		{
			printf("write failed\n");
			break;
		}

		InFile->BufferPos += sizeof(PCAPPacket_t);
		InFile->BufferPos += Packet->LengthCapture; 

		assert(Packet->LengthCapture > 0);
		assert(Packet->LengthCapture < 16*1024);

		InFile->BufferValid = false;
		TotalBytes += Packet->LengthCapture + sizeof(PCAPPacket_t);

		u64 T1 = rdtsc();
		if (T1 > NextPrintTSC)
		{
			NextPrintTSC = T1 + ns2tsc(1e9);

			double dT = tsc2ns(T1 - T0) / 1e9;
			double Bps = (TotalBytes * 8.0) / dT;

			double ETA = ((TotalInputBytes * 8.0) / Bps) - dT;

			printf("[%.4f %%] %.3fGB %.6fGbps Elapsed:%f Min ETA:%2.f Min | ", TotalBytes / (double)TotalInputBytes, TotalBytes / 1e9, Bps / 1e9, dT/60, ETA / 60);
			for (int i=0; i < InFileCnt; i++)
			{
				printf("%.3fGB ", InFileList[i].MapPos / 1e9);
			}
			printf("\n");
		}
	}

	// cleanup
	printf("Closing\n");
	for (int i=0; i < InFileCnt; i++)
	{
		InputFile_t* InFile  = &InFileList[i];

		munmap(InFile->Map, InFile->MapLength);
		close(InFile->fd);
	}
	fclose(OutFile);

	return 0;
}
