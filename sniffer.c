/*
 Copyright (c) 2013 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3

 Compile: gcc -o sniffer sniffer.c
 Run:
 $ ./sniffer -A ttyS19 -B tty20 -b 115200 | wireshark -k -i -
 $ ./sniffer -A ttyS19 -B tty20 -w filename
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <poll.h>

#include <termios.h>

#include <sys/ioctl.h>
#include <sys/time.h>

#include <errno.h>

#include <sched.h>

//MSG debug option
int debug = 0;

uint8_t port1[256]= "/dev/ttyS0";
uint8_t port2[256]= "/dev/ttyS1";

#define RX_LINES 2
#define BUFFER_SIZE 8192


struct pollfd pfd[RX_LINES] =
{
  {.fd = -1, .events = POLLIN},
  {.fd = -1, .events = POLLIN},
};

/*
 * The baud rate in bps.
 */
//#define TTY_BAUDRATE B3000000 //3Mbps
uint32_t TTY_BAUDRATE = 115200; //default baud rate:115200

/*
 * Connect to a serial port.
 */
int serial_connect(char* portname,uint32_t baud)
{
  struct termios options;
  int fd;
  uint32_t posix_baud;

  if ((fd = open(portname, O_RDONLY | O_NOCTTY)) < 0)
  {
    fprintf(stderr, "can't connect to %s\n", portname);
  }
  else
  {
    tcgetattr(fd, &options);
    if(check_baudrate_is_ext_baud(baud,&posix_baud))
    {
     printf("posix ext\r\n");
     options.c_cflag |= CBAUDEX;
     cfsetispeed(&options, posix_baud-4096);
     cfsetospeed(&options, posix_baud-4096);
    }
    else
    {
     printf("posix std\r\n");
     cfsetispeed(&options, posix_baud);
     cfsetospeed(&options, posix_baud);
    }

    cfmakeraw(&options);
    if(tcsetattr(fd, TCSANOW, &options) < 0)
    {
      fprintf(stderr, "can't set serial port options to %s \n",portname);
      close(fd);
      fd = -1;
    }
    tcflush(fd, TCIFLUSH);
  }

  return fd;
}

void serial_reopen(uint32_t baud)
{
  int fd1 = serial_connect(port1,baud);
  if(fd1 < 0)
  {
    exit(-1);
  }
  pfd[0].fd=fd1;

  int fd2 = serial_connect(port2,baud);
  if(fd1 < 0)
  {
    exit(-1);
  }
  pfd[1].fd=fd2;
}

void serial_close(int fd)
{
  close(fd);
}

#define guint32 unsigned int
#define guint16 unsigned short
#define gint32 signed int

typedef struct pcap_hdr_s {
  guint32 magic_number; /* magic number */
  guint16 version_major; /* major version number */
  guint16 version_minor; /* minor version number */
  gint32 thiszone; /* GMT to local correction */
  guint32 sigfigs; /* accuracy of timestamps */
  guint32 snaplen; /* max length of captured packets, in octets */
  guint32 network; /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  guint32 ts_sec; /* timestamp seconds */
  guint32 ts_usec; /* timestamp microseconds */
  guint32 incl_len; /* number of octets of packet saved in file */
  guint32 orig_len; /* actual length of packet */
} pcaprec_hdr_t;

static pcap_hdr_t capture_header =
{
  .magic_number = 0xa1b2c3d4,
  .version_major = 0x0002,
  .version_minor = 0x0004,
  .thiszone = 0x00000000,
  .sigfigs = 0x00000000,
  .snaplen = 0x0000FFFF,
  .network = 0x000000C9, //DLT_BLUETOOTH_HCI_H4_WITH_PHDR
};

typedef struct _pcap_bluetooth_h4_header {
  guint32 direction; /* if first bit is set direction is incoming */
} pcap_bluetooth_h4_header;

static pcaprec_hdr_t packet_header = {};

static FILE* file = NULL;
static char* filename = NULL;

void pcapwriter_init()
{
  if(filename)
  {
    file = fopen(filename, "w");

    if(!file)
    {
      fprintf(stderr, "pcapwriter_init");
    }
    else
    {
      fwrite((char*)&capture_header, 1, sizeof(capture_header), file);
    }
  }
  else
  {
    write(fileno(stdout), &capture_header, sizeof(capture_header));
  }
}

void pcapwriter_close()
{
  if(file)
  {
    fclose(file);
  }
}

static unsigned char buffer[1000000];
static unsigned int total = 0;

void store_data(void* from, unsigned int length)
{
  if(total + length >= sizeof(buffer))
  {
    fwrite((char*)buffer, 1, total, file);
    total = 0;
  }

  memcpy(buffer+total, from, length);
  total += length;
}

void pcapwriter_write(struct timeval* tv, unsigned int direction, unsigned short data_length, unsigned char data[data_length])
{
  pcap_bluetooth_h4_header bt_h4_hdr =
  {
    .direction = direction
  };

  packet_header.ts_sec = tv->tv_sec;
  packet_header.ts_usec = tv->tv_usec;

  packet_header.incl_len = sizeof(bt_h4_hdr)+data_length;
  packet_header.orig_len = sizeof(bt_h4_hdr)+data_length;

  if(file)
  {
    store_data(&packet_header, sizeof(packet_header));
    store_data(&bt_h4_hdr, sizeof(bt_h4_hdr));
    store_data(data, data_length);
  }
  else
  {
    write(fileno(stdout), &packet_header, sizeof(packet_header));
    write(fileno(stdout), &bt_h4_hdr, sizeof(bt_h4_hdr));
    write(fileno(stdout), data, data_length);
  }
}

static void usage()
{
  fprintf(stderr, "Usage: sniffer [-w filename] [-D] [-A] [-B] [-b]\n");
  exit(EXIT_FAILURE);
}



/*
 * Reads command-line arguments.
 */
static void read_args(int argc, char* argv[])
{
  int opt;

  while ((opt = getopt(argc, argv, "w:A:B:b:D")) != EOF)
  {
    switch (opt)
    {
      case 'w':
        filename = optarg;
        break;
      case 'D':
        printf("MSG Debug enable\r\n");
        debug = 1;
        break;
      case 'A':
	    snprintf(port1,sizeof(port1),"%s%s","/dev/",optarg);
        fprintf(stdout, "PortA:%s\r\n", port1);
        //printf("%s\r\n",port1);
        break;
      case 'B':
	    snprintf(port2,sizeof(port2),"%s%s","/dev/",optarg);
        fprintf(stdout, "PortB:%s\r\n", port2);
        //printf("%s\r\n",port2);
     case 'b':
        TTY_BAUDRATE = atoi(optarg);
        printf("%d\r\n",TTY_BAUDRATE);
        break;
      default: /* '?' */
        usage();
        break;
    }
  }
}

static volatile int done = 0;

void terminate(int sig)
{
  done = 1;
}

#define HCI_COMMAND_PKT         0x01
#define HCI_ACLDATA_PKT         0x02
#define HCI_SCODATA_PKT         0x03
#define HCI_EVENT_PKT           0x04
#define HCI_VENDOR_PKT          0xff

unsigned char buf[RX_LINES][BUFFER_SIZE] = {};
unsigned int direction[RX_LINES] = {};
int last[RX_LINES] = {};
struct timeval tv[RX_LINES] = {};

const uint32_t posix_std_baud[] ={0,50,75,110,134,150,200,300,600,1200,1800,2400,4800,9600,19200,38400,}; /*the POSIX std*/


int check_baudrate_is_ext_baud(uint32_t baudrate, uint32_t * new_baudrate)
{
  switch(baudrate)
  {
    case 9600:
    *new_baudrate= B9600 ;
    return 0;
    case 115200:
    *new_baudrate= B115200 ;
    return 0;
    case 3000000:
    *new_baudrate= B3000000 ;
    return 0;
    default:
    return 1;
    break;
  }
}

/*
 * warning: enabling debug can lead to performance issues,
 * that will mostly result in decoding failure.
 */

int read_packet(int index)
{
  int offset = 0;
  static uint32_t hci_cmd_new_baudrate=0;

  while(offset < last[index] && !buf[index][offset])
  {
    offset++;
  }

  if(filename && offset)
  {
    printf("(%d) skip: %d byte(s)\n", index, offset);
  }

  if(offset == last[index])
  {
    last[index] = 0;
    return 0;
  }

  unsigned char type = buf[index][offset];

  switch(type)
  {
    case HCI_COMMAND_PKT:
      direction[index] = 0x00000000;
      break;
    case HCI_EVENT_PKT:
      direction[index] = 0x01000000;
      break;
  }

  unsigned int length = 0;

  switch(type)
  {
    case HCI_COMMAND_PKT:
      if(last[index] > 3)
      {
        length = buf[index][offset+3]+4;
      }
      break;
    case HCI_ACLDATA_PKT:
      if(last[index] > 3)
      {
        length = buf[index][offset+3]+(buf[index][offset+4] << 8)+5;
        if(length > BUFFER_SIZE)
        {
          fprintf(stderr, "length is higher than %d: %d\n", BUFFER_SIZE, length);
          done = 1;
        }
      }
      break;
    case HCI_SCODATA_PKT:
      if(last[index] > 3)
      {
        length = buf[index][offset+3]+4;
      }
      break;
    case HCI_EVENT_PKT:
      if(last[index] > 2)
      {
        length = buf[index][offset+2]+3;
      }
      break;
    case HCI_VENDOR_PKT:
      if(last[index] > 2)
      {
        length = buf[index][offset+2]+3;
      }
      break;
    default:
      fprintf(stderr, "unknown packet type: 0x%02x\n", type);
      done = 1;
      break;
  }

  if(!length)
  {
    return 0;
  }

  if(last[index]-offset < length)
  {
    return 0;
  }

  if(filename)
  {
    printf("(%d) packet: type=0x%02x length=%d\n", index, type, length);
  }

  if(debug)
  {
    int j;
    for(j=0; j<length; ++j)
    {
      if(!(j%16))
      {
        printf("\n");
      }
      printf("0x%02x ", buf[index][offset+j]);
    }
    printf("\n");
  }

  if(buf[index][0]==HCI_COMMAND_PKT && buf[index][1]==0x18 && buf[index][2]==0xfc && buf[index][3]==0x06 )
  {
     //buf[index][4];
     //buf[index][5];
     hci_cmd_new_baudrate=buf[index][6];
     hci_cmd_new_baudrate+=buf[index][7]<<8;
     hci_cmd_new_baudrate+=buf[index][8]<<16;
     printf("host cmd baud update:%x %d\r\n",hci_cmd_new_baudrate,hci_cmd_new_baudrate);
  }

  else if( buf[index][0]==HCI_EVENT_PKT && buf[index][2]==0x04 && buf[index][3]==01 && buf[index][4]==0x18 && buf[index][5]==0xFC )
  {
    if(buf[index][1]==0x0e && buf[index][6]==0x00 )
    {
     printf("controller baud update success!\r\n");
     if(hci_cmd_new_baudrate)
     {
       serial_close(pfd[0].fd);
       serial_close(pfd[1].fd);
       serial_reopen(hci_cmd_new_baudrate);
     }
    }else
     printf("controller baud update fail eventcode:%d ret:%d!\r\n",buf[index][1]==0x0e,buf[index][6]==0x00);
  }

  else if( buf[index][0]==HCI_EVENT_PKT && buf[index][1]==0x0e && buf[index][2]==04 && buf[index][3]==0x01 && 
           buf[index][4]==0x4e          && buf[index][5]==0xFC && buf[index][6]==0x00 )
  {
       printf("download fw finish,reboot \r\n");
       serial_close(pfd[0].fd);
       serial_close(pfd[1].fd);
       serial_reopen(115200); //default baudrate
  }

  pcapwriter_write(tv+index, direction[index], length, buf[index]);

  memmove(buf[index], buf[index]+length, last[index]-length);

  last[index] -= length;

  return 1;
}

int main(int argc, char* argv[])
{
  (void) signal(SIGINT, terminate);

    printf("HELLO world\r\n");

  struct sched_param p =
  {
      .sched_priority = sched_get_priority_max(SCHED_FIFO)
  };

  sched_setscheduler(0, SCHED_FIFO, &p);

  read_args(argc, argv);

  int fd1 = serial_connect(port1,TTY_BAUDRATE);
  if(fd1 < 0)
  {
    exit(-1);
  }
  pfd[0].fd=fd1;

  int fd2 = serial_connect(port2,TTY_BAUDRATE);
  if(fd1 < 0)
  {
    exit(-1);
  }
  pfd[1].fd=fd2;
  
  pcapwriter_init(argv[1]);


  int res;
  int i;

  while(!done)
  {
    if(poll(pfd, 2, -1) > 0)
    {
      for(i=0; i<RX_LINES; ++i)
      {
        if(pfd[i].revents & POLLIN)
        {
          res = read(pfd[i].fd, buf[i]+last[i], sizeof(*buf)-last[i]);
          if(res < 0)
          {
            if(errno == EINTR)
            {
              continue;
            }
            else
            {
              fprintf(stderr, "error reading from fd=%d\n", pfd[i].fd);
              done = 1;
            }
          }
          else if(res > 0)
          {
            if(filename)
            {
              printf("(%d) read: %d bytes\n", i, res);
            }

            last[i] += res;

            gettimeofday(tv+i, NULL);

            while(read_packet(i)) {}
          }
        }
        if(pfd[i].revents & POLLERR)
        {
          fprintf(stderr, "error reading from fd=%d\n", pfd[i].fd);
          done = 1;
        }
      }
    }
  }

  if(total > 0)
  {
    fwrite((char*)buffer, 1, total, file);
  }

  pcapwriter_close();

  serial_close(pfd[0].fd);
  serial_close(pfd[1].fd);

  return 0;
}