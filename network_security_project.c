#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>


//이더넷 헤더를 정의한다. 출/목적지 주소, 프로토콜 종류를 구조체로 정의의
struct ethheader 
{
  unsigned char  ether_shost[6]; // source host address
  unsigned char  ether_dhost[6]; // destination host address
  unsigned short ether_type;     // protocol type (IP, ARP, RARP, etc)
};

//IP헤더를 정의한다. iph_ver ipv4인지 6인지, ttl(패킷의 수명), iph_protocol(상위 프로토콜을 나타냄 TCP = 6, UDP = 17, 송/수신 IP 주소)
struct ipheader 
{
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};


//TCP 헤더를 정의 TCP에서 송수신port번호 , SEQ(시퀀스번호), ACK(Acknowledgment Numver), TCP_flags(TCP제어 플러그 ACK,SYN,FIN)
struct tcpheader 
{
  unsigned short tcp_sport;      // source port 
  unsigned short tcp_dport;      // destination port
  unsigned int   tcp_seq;        // SEQ 
  unsigned int   tcp_ack;        // ACK 
  unsigned char  tcp_offx2;      // data offset, reserved 
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)

unsigned char  tcp_flags;
#define TH_FIN  0X01
#define TH_SYN  0X02
#define TH_RST  0X04
#define TH_PSH  0X08
#define TH_ACK  0x10
#define TH_URG  0X20
#define TH_ECE  0X40
#define TH_CWR  0X80

  unsigned short tcp_win;        // window size
  unsigned short tcp_sum;        // checksum
  unsigned short tcp_urp;        // urgent pointer 
};

//패킷 캡쳐함수 패킷을 수신했을때 호출, 패킷을 분석 후 출력한다다
/* Ethernet header, S mac, D mac print */
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;        //패킷을 이더넷 헤더 구조체로 변환환

  printf("\nEthernet Header:\n");
  printf("   Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
         eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], 
         eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  printf("   Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
         eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], 
         eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
//송수신 mac 출력

  //IP패킷인지 확인 0x0800은 IPv4 패킷이다
  if (ntohs(eth->ether_type) == 0x0800) 
  {          
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));    //=> 이를 구조체로 변환
    printf("\nIP Header:\n");
    printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));

//송수신 IP출력
    //TCP 패킷인지 확인한다. iph_protocol = 6이면 TCP 
    if (ip->iph_protocol == IPPROTO_TCP) 
    {          
      struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));     //이제 TCP 헤더 구조체로 변환환
      printf("\nTCP Header:\n");
      printf("   Source Port: %u\n", ntohs(tcp->tcp_sport));
      printf("   Destination Port: %u\n", ntohs(tcp->tcp_dport));
      printf("   Sequence Number: %u\n", ntohl(tcp->tcp_seq));
      printf("   Acknowledgement Number: %u\n", ntohl(tcp->tcp_ack));
      //송 수신 포트 출력

      // 플래그 출력
      printf("   TCP Flags: ");
      if (tcp->tcp_flags & TH_SYN) printf("SYN ");
      else if (tcp->tcp_flags & TH_ACK) printf("ACK ");
      else if (tcp->tcp_flags & TH_FIN) printf("FIN ");
      else if (tcp->tcp_flags & TH_RST) printf("RST ");
      else if (tcp->tcp_flags & TH_PSH) printf("PSH ");
      else if (tcp->tcp_flags & TH_URG) printf("URG ");
      else if (tcp->tcp_flags & TH_ECE) printf("ECE ");
      else if (tcp->tcp_flags & TH_CWR) printf("CWR ");
      else printf("UNKNOWN FLAG");
      }
      printf("\n");

      // 메시지 출력(오직 50byte만 + payload)
      struct tcpheader *tcp = NULL;
      unsigned char *data = (unsigned char *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader) + TH_OFF(tcp) * 4);
      printf("   Message (first 50 bytes of payload): ");
      for (int i = 0; i < 50; i++) 
      {
        if (data[i] == '\0') break;
        printf("%c", data[i]);
      }
      printf("\n");
    }
  }

//main 함수 패킷캡처시작작
int main() 
{
  pcap_t *handle;    //패킷 캡쳐를 위한 핸들러러
  char errbuf[PCAP_ERRBUF_SIZE];          //에러메시지 저장하기위한 버퍼
  struct bpf_program fp;                  //필터를 저장할 구조체체
  char filter_exp[] = "tcp";  // 오직 TCP 헤더만 출력함
  bpf_u_int32 net;

  // Step 1:enp0s3 인터페이스에서 패킷을 캡쳐한다. BUFSIZ 크기의 버퍼 사용, 1 = PROMISCUOUS MDDE 활성화한다.   , 1000MS = 캡처 타임아웃
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);          

  if (handle == NULL) 
  {
    printf("Error opening pcap session: %s\n", errbuf);
    return 1;
  }                 //헨들러 값이 없으면 오류 출력력

  //Step 2: tcp 피터를 BPF (VerKeley Packet)코드로 컴파일한다.
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
  {
    printf("Error compiling filter: %s\n", pcap_geterr(handle));
    return 1;
  }

  // Step 3:오직 TCP 패킷만 캡쳐할 수 있도록 하고, TCP 패킷이 아니라면 -1반환하여 종료료
  if (pcap_setfilter(handle, &fp) == -1) 
  {
    printf("Error setting filter: %s\n", pcap_geterr(handle));
    return 1;
  }

  //패킷을 계속 호출하여 got_packet 함수를 호출한다다
  pcap_loop(handle, 0, got_packet, NULL);    

  // 헨들러 종료
  pcap_close(handle);
  return 0;
}