#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32")
#include "protocol.h"
#include "pkt_handler.h"

#ifdef _WIN32
#include <tchar.h>

BOOL LoadNpcapDlls() // Npcap을 설치했는지 확인하는 함수
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

int main()
{
#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls()) // Npcap이 설치되지 않았으면 종료
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	int mode_num;
	char errbuf[PCAP_ERRBUF_SIZE];
	char save_name[100];
	pcap_t* fp;
	FILE* save_file;

	printf("======================== Packet Analysis Tool ========================\n");
	printf("1. Offline\n2. Live\n");
	printf("Enter the mode: ");
	scanf_s("%d", &mode_num, 1);
	printf("======================================================================\n");

	switch (mode_num)
	{
		case 1:
		{
			char file_path[100];

			printf("Enter pcap file path(max length : 100): ");
			scanf("%s", file_path, 100);

			/* Open the capture file */
			if ((fp = pcap_open_offline(file_path,			// name of the device
									errbuf					// error buffer
								)) == NULL)
			{
				fprintf(stderr, "\nUnable to open the file %s.\n", file_path);
				return -1;
			}
			break;
		}
		case 2:
		{
			pcap_if_t* alldevs;
			pcap_if_t* d;
			int inum;
			int i = 0;

			/* Retrieve the device list */
			if (pcap_findalldevs(&alldevs, errbuf) == -1) // Device 확인
			{
				fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
				exit(1);
			}

			/* Print the list */
			for (d = alldevs; d; d = d->next) // Device list 나열
			{
				printf("%d. %s", ++i, d->name);
				if (d->description)
					printf(" (%s)\n", d->description);
				else
					printf(" (No description available)\n");
			}

			if (i == 0)
			{
				printf("\nNo interfaces found! Make sure Npcap is installed.\n");
				return -1;
			}

			printf("Enter the interface number (1-%d):", i);
			scanf_s("%d", &inum, 1);

			if (inum < 1 || inum > i)
			{
				printf("\nInterface number out of range.\n");
				/* Free the device list */
				pcap_freealldevs(alldevs);
				return -1;
			}

			/* Jump to the selected adapter */
			for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

			/* Open the device */
			/* Open the adapter */
			if ((fp = pcap_open_live(d->name,	// name of the device
									65536,			// portion of the packet to capture. 
													// 65536 grants that the whole packet will be captured on all the MACs.
									1,				// promiscuous mode (nonzero means promiscuous)
									1000,			// read timeout
									errbuf			// error buffer
								)) == NULL)
			{
				fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
				/* Free the device list */
				pcap_freealldevs(alldevs);
				return -1;
			}

			printf("\nlistening on %s...\n", d->description);

			/* At this point, we don't need any more the device list. Free it */
			pcap_freealldevs(alldevs);

			break;
		}
	}
	printf("Enter the file name to save(max length :  100): ");
	scanf_s("%s", save_name, 100);
	save_file = fopen(strcat(save_name, ".txt"), "w");

	/* start the capture */
	pcap_loop(fp, 0, packet_handler, (u_char*)save_file);

	pcap_close(fp);
	fclose(save_file);

	system("pause");
	return 0;
}
