#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h> 
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include <math.h>
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void udp_packet_data(const u_char * , int);
void hex_to_binary (const u_char * , int );
double logbase (double , int );
int count(int[], int );
int oddOrEven(int [] , int  , int );
struct sockaddr_in source,dest;
int udp=0 ,i,j ;
int checksum , source_port , length;	
char ip[20] ,md_ip [20];
char devname2 [30] ;
int main()
{
	pcap_t *handle; 
	char errbuf[100] ;
	printf("Enter the name of the device you want to sniff : ");
	scanf("%s",devname2);
	printf("Opening device %s for sniffing ... " , devname2);
	handle = pcap_open_live(devname2 , 65536 , 1 , 0 , errbuf);
	if (handle == NULL) 
		exit(1);
	printf("Done\n");
	pcap_loop(handle , -1 , process_packet , NULL);
	return 0;	
}
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	udp_packet_data(buffer , size);
	printf("ip : %s\n" ,ip);
	printf("checksum : %d\n" ,checksum);
	printf("source port : %d\n" ,source_port);
	printf("length : %d\n" ,length);
}
void ip_header(const u_char * Buffer, int Size)
{
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	strcpy(ip ,inet_ntoa(source.sin_addr));
}
void udp_packet_data(const u_char *Buffer , int Size)
{	
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	ip_header(Buffer,Size);			
	checksum = ntohs(udph->check);
	source_port = ntohs(udph->source);
	length = ntohs(udph->len);
	const u_char * data = Buffer + header_size ;
	hex_to_binary(Buffer + header_size  , (Size - header_size) );
}
int count(int arr[], int n)
{
    if (arr[n - 1] == 0) {
        return 0;
    }
 
    if (arr[0]) {
        return n;
    }
 
    return count(arr, n/2) + count(arr + n/2, n - n/2);
}
double logbase (double y, int b)
    {
      double lg;
      lg = log10(y)/log10(b);
      return(lg);
    }
int oddOrEven(int a[] , int size , int ite)
{	//1 return means even , 0 return means odd
	int temp_size = size/ite , cn=0 , k=0;
	int temp[temp_size];
	for(int i=ite-1 ; i<size-ite;i=i+2*ite)
	{
		for(int j=i ; j<i+ite ; j++)
		{
			temp[k]=a[j];
			k++;
		}
	}
	for(int z=0 ; z<temp_size-1;z++)
	{
		temp[z]=temp[z+1];
	}
	cn = count(temp , temp_size);
	if (cn%2 == 0)
		return 1;
	else
		return 0;
}
void hex_to_binary(const u_char * data , int Size)
{	int a[8*Size],temp[8], k =0;
	int hamming_numbers = logbase(8*Size, 2) ;//number of hamming bit 
		printf("number of hammings : %d\n", hamming_numbers); 
		printf("first index data: %d\n" ,data[0]);
	//hex to binary
	for(i=0 ; i < Size ; i++)  
   	{  	int n = data[i];
		
		for(j=0;j<8;j++)    
		{    	
			if (n>0)
			{
				temp[j]=n%2; 
				n=n/2;
			}
			
			else	
			{
				temp[j]=0;
			}  
		}

		for(j=j-1;j>=0;j--)
			{
				a[k]=temp[j];
				k++;
			}	
	} 
	
	//printf("haming 1 is %d\n" , oddOrEven(a ,k,1));
	for (int z =0 ;z<2 ;z++)
	{
		int po =pow(2,z);
		printf("haming %d is :" ,po); 
		printf("%d \n",oddOrEven(a , k , po));
		
	}
	//ptint bit stream
	for(int r = 0 ;r<k;r++)
	{	
		printf("%d",a[r]); 
	}
	printf("\n#############################################\n");
	
	
}



